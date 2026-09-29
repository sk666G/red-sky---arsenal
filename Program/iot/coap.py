# language: Python, file: Program/iot/coap.py, target: Red Sky IoT — CoAP attack
# CoAP (RFC 7252) is UDP-based, so unlike MQTT there is no connection setup
# and no auth handshake at the transport layer. CoAP has optional DTLS or
# OSCOAP for security, but the vast majority of shipped IoT uses plain CoAP
# on port 5683 and DTLS-CoAP on 5684. This module drives the plain port.
#
# Two things:
#   1. GET / well-known/core — the standard resource-discovery endpoint.
#      Every spec-compliant CoAP server lists its resources there. That is
#      the entry map: sensors, actuators, config, /debug, sometimes /admin.
#   2. Per-resource GET / PUT / POST — reads values, writes commands.
#      CoAP has no login on plain UDP; once the resource URI is known the
#      only access control is what the server chose to implement (rarely).

import json
import os
import random
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
COAP_DIR = IOT_DIR / "coap"


# ── wire format ─────────────────────────────────────────────────────────────
# CoAP header (4 bytes minimum):
#   byte 0: ver(2) | type(2) | token length(4)
#   byte 1: code (class.detail packed: 0x45 for 4.05, 0x01 for GET)
#   bytes 2-3: message ID
# Then token (tkl bytes), then options (delta-encoded), then 0xFF + payload.

COAP_VER = 1
TYPE_CON = 0
TYPE_NON = 1
TYPE_ACK = 2
TYPE_RST = 3

METHOD_GET    = 0x01
METHOD_POST   = 0x02
METHOD_PUT    = 0x03
METHOD_DELETE = 0x04

COAP_PORT = 5683


def _pack_option_delta(delta: int, length: int) -> bytes:
    """Option header: 4-bit delta + 4-bit length, with extended bytes."""
    out = bytearray()
    # delta nibble
    if delta < 13:
        d_nibble = delta
        d_ext = b""
    elif delta < 269:
        d_nibble = 13
        d_ext = bytes([delta - 13])
    else:
        d_nibble = 14
        d_ext = struct.pack("!H", delta - 269)
    # length nibble
    if length < 13:
        l_nibble = length
        l_ext = b""
    elif length < 269:
        l_nibble = 13
        l_ext = bytes([length - 13])
    else:
        l_nibble = 14
        l_ext = struct.pack("!H", length - 269)
    out.append((d_nibble << 4) | l_nibble)
    out += d_ext + l_ext
    return bytes(out)


def encode_options(options: List[Tuple[int, bytes]]) -> bytes:
    """Options must be sorted ascending by number. Encodes delta-relative."""
    out = bytearray()
    last = 0
    for num, val in sorted(options, key=lambda x: x[0]):
        out += _pack_option_delta(num - last, len(val))
        out += val
        last = num
    return bytes(out)


def build_request(method: int, path: str, msg_id: int,
                  token: bytes = b"", payload: bytes = b"",
                  type_: int = TYPE_CON) -> bytes:
    """Path is /a/b/c — split on / and emit Uri-Path options (11) per segment."""
    tkl = len(token) & 0x0F
    hdr = bytes([
        (COAP_VER << 6) | (type_ << 4) | tkl,
        method,
    ]) + struct.pack("!H", msg_id & 0xFFFF)

    opts: List[Tuple[int, bytes]] = []
    if path and path != "/":
        for seg in path.strip("/").split("/"):
            opts.append((11, seg.encode()))  # Uri-Path

    body = bytearray()
    body += hdr
    body += token
    body += encode_options(opts)
    if payload:
        body.append(0xFF)
        body += payload
    return bytes(body)


def parse_response(data: bytes) -> Dict:
    """Best-effort parse of a CoAP response."""
    if len(data) < 4:
        return {"error": "short"}
    b0 = data[0]
    ver = (b0 >> 6) & 0x03
    t = (b0 >> 4) & 0x03
    tkl = b0 & 0x0F
    code = data[1]
    code_class = (code >> 5) & 0x07
    code_detail = code & 0x1F
    msgid = struct.unpack("!H", data[2:4])[0]
    token = data[4:4+tkl]
    off = 4 + tkl

    opts: List[Tuple[int, bytes]] = []
    num = 0
    while off < len(data):
        if data[off] == 0xFF:
            off += 1
            break
        byte = data[off]
        off += 1
        delta = (byte >> 4) & 0x0F
        length = byte & 0x0F
        if delta == 13:
            delta = 13 + data[off]; off += 1
        elif delta == 14:
            delta = 269 + struct.unpack("!H", data[off:off+2])[0]; off += 2
        if length == 13:
            length = 13 + data[off]; off += 1
        elif length == 14:
            length = 269 + struct.unpack("!H", data[off:off+2])[0]; off += 2
        num += delta
        opts.append((num, data[off:off+length]))
        off += length

    payload = data[off:] if off < len(data) else b""

    return {
        "ver": ver, "type": t, "code": code,
        "code_str": str(code_class) + "." + format(code_detail, "02d"),
        "msgid": msgid, "token": token.hex(),
        "options": [(n, v.hex()) for n, v in opts],
        "payload": payload,
    }


# ── transaction ─────────────────────────────────────────────────────────────

def coap_request(host: str, port: int, method: int, path: str,
                 payload: bytes = b"", timeout: int = 5) -> Optional[Dict]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    msg_id = random.randint(0, 0xFFFF)
    token = os.urandom(4)
    pkt = build_request(method, path, msg_id, token=token, payload=payload)
    try:
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_response(data)
    except socket.timeout:
        sock.close()
        return None
    except Exception as e:
        sock.close()
        return {"error": str(e)}


# ── commands ────────────────────────────────────────────────────────────────

def cmd_discover(host: str, port: int) -> int:
    COAP_DIR.mkdir(parents=True, exist_ok=True)
    print_info("coap discover")
    print_kv("target", host + ":" + str(port))
    print()
    r = coap_request(host, port, METHOD_GET, "/.well-known/core")
    if not r:
        print_err("no response (timeout)")
        return 1
    if "error" in r and r["error"]:
        print_err("error: " + r["error"])
        return 1
    print_kv("code", r["code_str"])
    print_kv("payload bytes", len(r["payload"]))
    print()
    text = r["payload"].decode("utf-8", errors="replace")
    print(BONE + text + RESET)
    out = COAP_DIR / ("discover_" + host.replace(".", "_") + "_" + str(int(time.time())) + ".txt")
    out.write_text(text)
    print()
    print_kv("saved", out)
    return 0


def cmd_get(host: str, port: int, path: str) -> int:
    r = coap_request(host, port, METHOD_GET, path)
    if not r:
        print_err("no response")
        return 1
    if "error" in r and r["error"]:
        print_err("error: " + r["error"])
        return 1
    print_kv("path", path)
    print_kv("code", r["code_str"])
    print_kv("content_format", next((v for n, v in r["options"] if n == 12), "(none)"))
    print()
    print(BONE + r["payload"].decode("utf-8", errors="replace") + RESET)
    return 0


def cmd_put(host: str, port: int, path: str, value: str) -> int:
    payload = value.encode()
    r = coap_request(host, port, METHOD_PUT, path, payload=payload)
    if not r:
        print_err("no response")
        return 1
    if "error" in r and r["error"]:
        print_err("error: " + r["error"])
        return 1
    print_kv("path", path)
    print_kv("code", r["code_str"])
    if r["payload"]:
        print_kv("response", r["payload"].decode("utf-8", errors="replace"))
    return 0


def cmd_post(host: str, port: int, path: str, value: str) -> int:
    payload = value.encode()
    r = coap_request(host, port, METHOD_POST, path, payload=payload)
    if not r:
        print_err("no response")
        return 1
    if "error" in r and r["error"]:
        print_err("error: " + r["error"])
        return 1
    print_kv("path", path)
    print_kv("code", r["code_str"])
    if r["payload"]:
        print_kv("response", r["payload"].decode("utf-8", errors="replace"))
    return 0


def cmd_fuzz(host: str, port: int, wordlist: str, method: str) -> int:
    """Walk a wordlist of common IoT CoAP paths, log response codes."""
    words = [
        "sensors", "actuators", "config", "debug", "admin", "device",
        "status", "time", "info", "control", "reset", "cmd", "shell",
        "update", "firmware", "log", "net", "wifi", "ip", "led",
        "temperature", "humidity", "motion", "door", "lock", "light",
    ]
    if wordlist:
        p = Path(wordlist)
        if p.exists():
            words = [w.strip() for w in p.read_text().splitlines() if w.strip() and not w.startswith("#")]

    m = METHOD_GET
    if method.lower() == "put":
        m = METHOD_PUT
    elif method.lower() == "post":
        m = METHOD_POST
    elif method.lower() == "delete":
        m = METHOD_DELETE

    print_info("coap fuzz")
    print_kv("target", host + ":" + str(port))
    print_kv("wordlist", len(words))
    print_kv("method", method.upper())
    print()

    hits = []
    for w in words:
        path = "/" + w.lstrip("/")
        r = coap_request(host, port, m, path, timeout=3)
        if not r:
            print("  " + ASH + path + RESET + " (timeout)")
            continue
        code = r.get("code_str", "?")
        if code.startswith("2"):
            marker = SCARLET + "HIT" + RESET
            hits.append({"path": path, "code": code, "payload_len": len(r.get("payload", b""))})
        elif code.startswith("4") and code == "4.04":
            marker = ASH + "404 " + RESET
        else:
            marker = ARTERY + code + " " + RESET
        print("  " + marker + " " + path + " " + ASH + str(len(r.get("payload", b""))) + "B" + RESET)

    print()
    print_kv("hits", len(hits))
    if hits:
        out = COAP_DIR / ("fuzz_" + host.replace(".", "_") + "_" + str(int(time.time())) + ".json")
        COAP_DIR.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(hits, indent=2))
        print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky iot coap <sub-command>")
        print_info("")
        print_info("  discover --host H [--port 5683]")
        print_info("      GET /.well-known/core — the resource map")
        print_info("  get      --host H --path /a/b")
        print_info("  put      --host H --path /a/b --value 1")
        print_info("  post     --host H --path /a/b --value 'text'")
        print_info("  fuzz     --host H [--wordlist FILE] [--method get|put|post|delete]")
        print_info("      walk common paths, report 2.xx responses")
        return 0

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--host", required=False, default="")
    base.add_argument("--port", type=int, default=COAP_PORT)

    if sub == "discover":
        p = argparse.ArgumentParser(prog="redsky iot coap discover", parents=[base], add_help=False)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot coap discover --host H [--port 5683]")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_discover(ns.host, ns.port)

    if sub in ("get", "read"):
        p = argparse.ArgumentParser(prog="redsky iot coap get", parents=[base], add_help=False)
        p.add_argument("--path", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot coap get --host H --path /a/b")
            return 2
        if not ns.host or not ns.path:
            print_err("--host and --path required")
            return 2
        return cmd_get(ns.host, ns.port, ns.path)

    if sub in ("put", "set"):
        p = argparse.ArgumentParser(prog="redsky iot coap put", parents=[base], add_help=False)
        p.add_argument("--path", required=False, default="")
        p.add_argument("--value", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot coap put --host H --path /a/b --value 1")
            return 2
        if not ns.host or not ns.path or not ns.value:
            print_err("--host, --path, --value required")
            return 2
        return cmd_put(ns.host, ns.port, ns.path, ns.value)

    if sub == "post":
        p = argparse.ArgumentParser(prog="redsky iot coap post", parents=[base], add_help=False)
        p.add_argument("--path", required=False, default="")
        p.add_argument("--value", required=False, default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot coap post --host H --path /a/b --value 'text'")
            return 2
        if not ns.host or not ns.path or not ns.value:
            print_err("--host, --path, --value required")
            return 2
        return cmd_post(ns.host, ns.port, ns.path, ns.value)

    if sub == "fuzz":
        p = argparse.ArgumentParser(prog="redsky iot coap fuzz", parents=[base], add_help=False)
        p.add_argument("--wordlist", default="")
        p.add_argument("--method", default="get")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot coap fuzz --host H [--wordlist FILE] [--method get]")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_fuzz(ns.host, ns.port, ns.wordlist, ns.method)

    print_err("unknown coap sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
