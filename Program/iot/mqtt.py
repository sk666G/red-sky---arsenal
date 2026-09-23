# language: Python, file: Program/iot/mqtt.py, target: Red Sky iot — MQTT recon
# Talks raw MQTT 3.1.1 over TCP/TLS. No paho dependency.
#   - connect     : CONNECT/CONNACK, auth-required detection, broker banner
#   - subscribe   : subscribe to a wildcard topic (default "#") and dump messages
#   - topics      : enumeration via $SYS/#, common IoT topic names, retained-message probe
#   - publish     : craft PUBLISH (retained or not) to a topic — for testing your
#                   own broker; also useful for simulating a device's command topic
#   - acl         : probe which topics the anonymous user is allowed to write

import json
import socket
import ssl
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
MQTT_DIR.mkdir(parents=True, exist_ok=True)


# ── wire helpers ──
def _encode_len(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out += bytes([b])
        if not n:
            break
    return out


def _encode_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _packet(pkt_type: int, flags: int, body: bytes) -> bytes:
    return bytes([(pkt_type << 4) | flags]) + _encode_len(len(body)) + body


def connect_packet(client_id: str, user: str = "", password: str = "",
                   keepalive: int = 60, clean: bool = True) -> bytes:
    vh = b"\x00\x04MQTT\x04"
    flags = 0
    if clean:
        flags |= 0x02
    payload = _encode_str(client_id)
    if user:
        flags |= 0x80
        payload += _encode_str(user)
    if password:
        flags |= 0x40
        payload += _encode_str(password)
    vh += bytes([flags]) + struct.pack(">H", keepalive)
    return _packet(1, 0, vh + payload)


def subscribe_packet(topic: str, qos: int = 0, pkt_id: int = 1) -> bytes:
    body = struct.pack(">H", pkt_id) + _encode_str(topic) + bytes([qos])
    return _packet(8, 2, body)  # flags 0x02 required for SUBSCRIBE


def publish_packet(topic: str, payload: bytes, qos: int = 0, retain: bool = False,
                   pkt_id: int = 1) -> bytes:
    flags = (qos << 1) | (1 if retain else 0)
    body = _encode_str(topic)
    if qos > 0:
        body += struct.pack(">H", pkt_id)
    body += payload
    return _packet(3, flags, body)


def disconnect_packet() -> bytes:
    return _packet(14, 0, b"")


def _read_remaining_len(sock: socket.socket) -> int:
    mult = 1
    value = 0
    for _ in range(4):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("closed")
        v = b[0]
        value += (v & 0x7F) * mult
        if not (v & 0x80):
            break
        mult *= 128
    return value


def _read_packet(sock: socket.socket) -> Tuple[int, bytes]:
    header = sock.recv(1)
    if not header:
        raise ConnectionError("closed")
    pkt_type = header[0] >> 4
    flags = header[0] & 0x0F
    length = _read_remaining_len(sock)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise ConnectionError("short")
        body += chunk
    return (pkt_type << 4) | flags, body


def _open(host: str, port: int, tls: bool, timeout: float = 5.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


# ── commands ──
def cmd_connect(host: str, port: int, tls: bool, user: str, password: str) -> int:
    print_info("MQTT connect probe")
    print_kv("host", host)
    print_kv("port", str(port))
    print_kv("tls", "yes" if tls else "no")
    print_kv("user", user or "(anonymous)")
    print()

    try:
        s = _open(host, port, tls)
    except Exception as e:
        print_err("cannot open: " + str(e))
        return 1

    cid = "rs-" + str(int(time.time()) & 0xFFFF)
    try:
        s.sendall(connect_packet(cid, user, password))
        pkt, body = _read_packet(s)
        if pkt >> 4 != 2:
            print_err("unexpected response: 0x{:02x}".format(pkt))
            return 1
        rc = body[1] if len(body) >= 2 else 0xFF
        session_present = bool(body[0] & 1) if body else False
        codes = {
            0: "accepted",
            1: "rejected: unacceptable protocol version",
            2: "rejected: identifier rejected",
            3: "rejected: server unavailable",
            4: "rejected: bad user/password",
            5: "rejected: not authorized",
        }
        print_kv("session present", str(session_present))
        print_kv("return code", str(rc) + " (" + codes.get(rc, "unknown") + ")")
        if rc == 0:
            print()
            print_ok("connection accepted")
            if not user and not password:
                print_warn("broker allows anonymous connections")
        else:
            print()
            print_warn("connection rejected")
    finally:
        try:
            s.sendall(disconnect_packet())
        except Exception:
            pass
        s.close()
    return 0


def cmd_subscribe(host: str, port: int, tls: bool, topic: str, duration: int,
                  user: str, password: str, out_file: str) -> int:
    print_info("MQTT subscribe")
    print_kv("topic", topic)
    print_kv("duration", str(duration) + "s")
    print()
    try:
        s = _open(host, port, tls)
    except Exception as e:
        print_err("cannot open: " + str(e))
        return 1

    cid = "rs-sub-" + str(int(time.time()) & 0xFFFF)
    s.sendall(connect_packet(cid, user, password))
    pkt, body = _read_packet(s)
    if pkt >> 4 != 2 or (len(body) >= 2 and body[1] != 0):
        print_err("connect failed")
        return 1

    print_ok("connected, subscribing to " + topic)
    s.sendall(subscribe_packet(topic, 0, 1))
    pkt, _ = _read_packet(s)
    if pkt >> 4 != 9:
        print_err("subscribe failed")
        return 1
    print_ok("subscribed")

    messages = []
    t0 = time.time()
    s.settimeout(1.0)
    try:
        while time.time() - t0 < duration:
            try:
                pkt, body = _read_packet(s)
                if pkt >> 4 != 3:  # PUBLISH
                    continue
                topic_len = struct.unpack(">H", body[:2])[0]
                topic_name = body[2:2+topic_len].decode("utf-8", errors="replace")
                payload = body[2+topic_len:]
                msg = {"ts": time.time(), "topic": topic_name, "payload": payload.decode("utf-8", errors="replace")}
                messages.append(msg)
                print(SCARLET + "[msg]" + RESET + " " + BONE + topic_name + RESET
                      + "  " + CLOT + msg["payload"][:200] + RESET)
            except socket.timeout:
                continue
            except ConnectionError:
                break
    finally:
        try:
            s.sendall(disconnect_packet())
        except Exception:
            pass
        s.close()

    out = Path(out_file) if out_file else MQTT_DIR / ("subscribe_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(messages, indent=2))
    print()
    print_kv("messages", str(len(messages)))
    print_kv("saved", out)
    return 0


def cmd_topics(host: str, port: int, tls: bool, user: str, password: str,
               duration: int, out_file: str) -> int:
    print_info("MQTT topic enumeration — subscribe to # and $SYS/#")
    print()
    try:
        s = _open(host, port, tls)
    except Exception as e:
        print_err("cannot open: " + str(e))
        return 1

    cid = "rs-topics-" + str(int(time.time()) & 0xFFFF)
    s.sendall(connect_packet(cid, user, password))
    pkt, body = _read_packet(s)
    if pkt >> 4 != 2 or (len(body) >= 2 and body[1] != 0):
        print_err("connect failed")
        return 1

    s.sendall(subscribe_packet("#", 0, 1))
    _read_packet(s)
    s.sendall(subscribe_packet("$SYS/#", 0, 2))
    _read_packet(s)
    print_ok("subscribed to # and $SYS/#")

    # kick $SYS by publishing a no-op to a wildcard-less topic? not helpful.
    # $SYS topics publish on their own schedule once subscribed.

    seen_topics = {}
    t0 = time.time()
    s.settimeout(1.0)
    try:
        while time.time() - t0 < duration:
            try:
                pkt, body = _read_packet(s)
                if pkt >> 4 != 3:
                    continue
                tl = struct.unpack(">H", body[:2])[0]
                t = body[2:2+tl].decode("utf-8", errors="replace")
                seen_topics[t] = seen_topics.get(t, 0) + 1
            except socket.timeout:
                continue
            except ConnectionError:
                break
    finally:
        try:
            s.sendall(disconnect_packet())
        except Exception:
            pass
        s.close()

    print()
    print_info(str(len(seen_topics)) + " unique topic(s) observed")
    print()
    for t, n in sorted(seen_topics.items()):
        print("  " + ARTERY + "*" + RESET + " " + BONE + t + RESET + "  "
              + ASH + str(n) + " msg" + RESET)

    out = Path(out_file) if out_file else MQTT_DIR / ("topics_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(seen_topics, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_publish(host: str, port: int, tls: bool, topic: str, payload: str,
                retain: bool, user: str, password: str) -> int:
    print_info("MQTT publish")
    print_kv("topic", topic)
    print_kv("payload", payload[:100])
    print_kv("retain", "yes" if retain else "no")
    print()
    try:
        s = _open(host, port, tls)
    except Exception as e:
        print_err("cannot open: " + str(e))
        return 1

    cid = "rs-pub-" + str(int(time.time()) & 0xFFFF)
    s.sendall(connect_packet(cid, user, password))
    pkt, body = _read_packet(s)
    if pkt >> 4 != 2 or (len(body) >= 2 and body[1] != 0):
        print_err("connect failed")
        return 1
    print_ok("connected")

    s.sendall(publish_packet(topic, payload.encode(), qos=0, retain=retain))
    time.sleep(0.3)
    s.sendall(disconnect_packet())
    s.close()
    print_ok("published")
    return 0


def cmd_acl(host: str, port: int, tls: bool, user: str, password: str) -> int:
    """Probe whether the anonymous user can publish to common device topics.
    Publishes a harmless __rs_probe__ payload to likely command topics and sees
    if the broker disconnects us (indicating ACL denial)."""
    print_info("MQTT ACL probe — which topics accept our writes")
    print()

    probes = [
        "cmd", "command", "control", "shell",
        "home/+/set", "devices/+/set", "zigbee2mqtt/+/set",
        "esphome/+/command", "tasmota/+/cmd",
        "device/+/command", "iot/+/cmd",
        "shellies/+/command",
    ]

    allowed = []
    denied = []

    for topic in probes:
        try:
            s = _open(host, port, tls, timeout=4.0)
        except Exception as e:
            print_err("cannot connect: " + str(e))
            return 1

        try:
            cid = "rs-acl-" + str(int(time.time() * 1000) & 0xFFFF)
            s.sendall(connect_packet(cid, user, password))
            pkt, body = _read_packet(s)
            if pkt >> 4 != 2 or (len(body) >= 2 and body[1] != 0):
                denied.append((topic, "connect rejected"))
                continue

            s.sendall(publish_packet(topic, b"__rs_probe__", qos=0, retain=False))
            time.sleep(0.3)
            # if broker accepted, we're still connected -> send a PINGREQ (12)
            s.sendall(_packet(12, 0, b""))
            try:
                s.settimeout(1.5)
                pkt, _ = _read_packet(s)
                if pkt >> 4 == 13:  # PINGRESP
                    allowed.append(topic)
                    print("  " + SCARLET + "OK " + RESET + BONE + topic + RESET)
            except Exception:
                denied.append((topic, "no PINGRESP"))
        finally:
            try:
                s.sendall(disconnect_packet())
            except Exception:
                pass
            s.close()

    print()
    print_kv("allowed", str(len(allowed)))
    print_kv("denied/closed", str(len(denied)))
    if allowed:
        print()
        print_warn("broker accepts anonymous writes to: " + ", ".join(allowed[:5]))
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky iot mqtt", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="connect",
                   choices=["connect", "subscribe", "topics", "publish", "acl"])
    p.add_argument("host", nargs="?", default="")
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--user", default="")
    p.add_argument("--password", default="")
    p.add_argument("--topic", default="#")
    p.add_argument("--payload", default="hello")
    p.add_argument("--retain", action="store_true")
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky iot mqtt <connect|subscribe|topics|publish|acl> <host> [opts]")
        return 2

    if ns.help:
        print_info("connect   <host>                    -- CONNECT/CONNACK check")
        print_info("subscribe <host> --topic '#' --duration 60")
        print_info("topics    <host> --duration 60       -- enumerate observed topics")
        print_info("publish   <host> --topic X --payload Y [--retain]")
        print_info("acl       <host>                    -- which write topics are open")
        print_info("add --tls for 8883, --user / --password for auth")
        return 0

    if not ns.host:
        print_err("give a host")
        return 2

    if ns.action == "connect":
        return cmd_connect(ns.host, ns.port, ns.tls, ns.user, ns.password)
    if ns.action == "subscribe":
        return cmd_subscribe(ns.host, ns.port, ns.tls, ns.topic, ns.duration, ns.user, ns.password, ns.out)
    if ns.action == "topics":
        return cmd_topics(ns.host, ns.port, ns.tls, ns.user, ns.password, ns.duration, ns.out)
    if ns.action == "publish":
        return cmd_publish(ns.host, ns.port, ns.tls, ns.topic, ns.payload, ns.retain, ns.user, ns.password)
    if ns.action == "acl":
        return cmd_acl(ns.host, ns.port, ns.tls, ns.user, ns.password)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
