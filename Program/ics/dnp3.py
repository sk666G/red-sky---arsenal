# language: Python, file: Program/ics/dnp3.py, target: Red Sky ics — DNP3
# DNP3 client. Layered protocol:
#
#   Link layer:  0x0564 (start), length, control, dest(2), src(2), header CRC
#                then payload in 16-byte chunks, each with a CRC
#   Transport:   1 byte (FIR | FIN | sequence)
#   Application: function code + IIN (2) for responses, or app header +
#                object headers + data for requests
#
# Common application function codes:
#   0x01  Read
#   0x02  Write
#   0x03  Select
#   0x04  Operate
#   0x05  Direct Operate
#   0x06  Direct Operate No Ack
#   0x81  Response
#   0x82  Unsolicited Response
#
# Class polls:
#   Class 0  = static data (all points)
#   Class 1  = highest priority events
#   Class 2  = medium priority events
#   Class 3  = lowest priority events
#
# DNP3 has no default authentication on legacy deployments (Secure
# Authentication v5 exists but is not commonly enabled on older RTUs).

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


ICS_DIR = OUTPUT_DIR / "ics"
DNP3_DIR = ICS_DIR / "dnp3"


DNP3_CRC_TABLE = [
    0, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xCE45, 0xF81B, 0xA2F9, 0x94A7, 0x173D, 0x2163, 0x7B81, 0x4DDF,
    0x8A1A, 0xBC44, 0xE6A6, 0xD0F8, 0x5362, 0x653C, 0x3FDE, 0x0980,
    0x445F, 0x7201, 0x28E3, 0x1EBD, 0x9D27, 0xAB79, 0xF19B, 0xC7C5,
    0x1006, 0x2658, 0x7CBA, 0x4AE4, 0xC97E, 0xFF20, 0xA5C2, 0x939C,
    0xDE43, 0xE81D, 0xB2FF, 0x84A1, 0x073B, 0x3165, 0x6B87, 0x5DD9,
    0x9A1C, 0xAC42, 0xF6A0, 0xC0FE, 0x4364, 0x753A, 0x2FD8, 0x1986,
    0x5459, 0x6207, 0x38E5, 0x0EBB, 0x8D21, 0xBB7F, 0xE19D, 0xD7C3,
    0x200C, 0x1652, 0x4CB0, 0x7AEE, 0xF974, 0xCF2A, 0x95C8, 0xA396,
    0xEE49, 0xD817, 0x82F5, 0xB4AB, 0x3731, 0x016F, 0x5B8D, 0x6DD3,
    0xAA16, 0x9C48, 0xC6AA, 0xF0F4, 0x736E, 0x4530, 0x1FD2, 0x298C,
    0x6453, 0x520D, 0x08EF, 0x3EB1, 0xBD2B, 0x8B75, 0xD197, 0xE7C9,
    0x400B, 0x7655, 0x2CB7, 0x1AE9, 0x9973, 0xAF2D, 0xF5CF, 0xC391,
    0x8E4E, 0xB810, 0xE2F2, 0xD4AC, 0x5736, 0x6168, 0x3B8A, 0x0DD4,
    0xCA11, 0xFC4F, 0xA6AD, 0x90F3, 0x1369, 0x2537, 0x7FD5, 0x498B,
    0x0454, 0x320A, 0x68E8, 0x5EB6, 0xDD2C, 0xEB72, 0xB190, 0x87CE,
    0x8017, 0xB649, 0xECAB, 0xDAF5, 0x596F, 0x6F31, 0x35D3, 0x038D,
    0x4E52, 0x780C, 0x22EE, 0x14B0, 0x972A, 0xA174, 0xFBF6, 0xCBA8,
    0x0C2D, 0x3A73, 0x6091, 0x56CF, 0xD555, 0xE30B, 0xB9E9, 0x8FB7,
    0xC268, 0xF436, 0xAED4, 0x988A, 0x1B10, 0x2D4E, 0x77AC, 0x41F2,
    0xA03E, 0x9660, 0xCC82, 0xFADC, 0x7946, 0x4F18, 0x15FA, 0x23A4,
    0x6E7B, 0x5825, 0x02C7, 0x3499, 0xB703, 0x815D, 0xDBBF, 0xEDE1,
    0x2A24, 0x1C7A, 0x4698, 0x70C6, 0xF35C, 0xC502, 0x9FE0, 0xA9BE,
    0xE461, 0xD23F, 0x88DD, 0xBEA3, 0x3D39, 0x0B67, 0x5185, 0x67DB,
    0xC02E, 0xF670, 0xAC92, 0x9ACC, 0x1956, 0x2F08, 0x75EA, 0x43B4,
    0x0E6B, 0x3835, 0x62D7, 0x5489, 0xD713, 0xE14D, 0xBBAF, 0x8DF1,
    0x4A34, 0x7C6A, 0x2688, 0x10D6, 0x934C, 0xA512, 0xFFF0, 0xC9AE,
    0x8471, 0xB22F, 0xE8CD, 0xDE93, 0x5D09, 0x6B57, 0x31B5, 0x07EB,
    0xE02C, 0xD672, 0x8C90, 0xBACE, 0x3954, 0x0F0A, 0x55E8, 0x63B6,
    0x2E69, 0x1837, 0x42D5, 0x748B, 0xF711, 0xC14F, 0x9BAD, 0xADF3,
    0x6A36, 0x5C68, 0x068A, 0x30D4, 0xB34E, 0x8510, 0xDFF2, 0xE9AC,
    0xA473, 0x922D, 0xC8CF, 0xFE91, 0x7D0B, 0x4B55, 0x11B7, 0x27E9,
]


def _crc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = ((crc >> 8) & 0xFF) ^ DNP3_CRC_TABLE[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFF


def _crc_pad(data: bytes) -> bytes:
    """Chunk data into 16-byte groups, each followed by its CRC (LE)."""
    out = bytearray()
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        out += chunk
        out += struct.pack("<H", _crc(chunk))
    return bytes(out)


# ── link layer ────────────────────────────────────────────────────────────

def build_link_frame(dest: int, src: int, payload: bytes, func: int = 0x44) -> bytes:
    """func = DIR(7) | PRM(6) | FCB(5) | FCV(4) | function(0..3)
    Common values: 0x44 = user data unconfirmed (PRM=1, FC=4)
                   0x40 = reset link states (PRM=1, FC=0)"""
    # header before CRC: 05 64 LEN CTRL DEST SRC
    length = 5 + len(payload)  # control + dest(2) + src(2) + payload
    length_field = length + (length // 16) + ((1 if length % 16 else 0))  # rough guess — real logic below
    # correct length calculation: header is 5 bytes (len, ctrl, dest, src, plus the length byte itself)
    # DNP3: LEN = count of bytes between LEN and the first CRC, minus 3 (start+len)
    # Actually: LEN = number of bytes from CTRL to end of user data, plus the CRC counts.
    # The proper formula: LEN = 5 (ctrl + dest(2) + src(2)) + len(payload) + CRCs in payload
    crc_bytes = (len(payload) + 15) // 16 * 2 if payload else 0
    LEN = 5 + len(payload) + crc_bytes
    header = bytes([0x05, 0x64, LEN, func]) + struct.pack("<HH", dest, src)
    frame = header + struct.pack("<H", _crc(header))
    if payload:
        frame += _crc_pad(payload)
    return frame


def parse_link_frame(data: bytes) -> Optional[bytes]:
    """Return the payload after link-layer header + CRCs, or None."""
    if len(data) < 10:
        return None
    if data[0] != 0x05 or data[1] != 0x64:
        return None
    LEN = data[2]
    if len(data) < LEN + 2:
        return None
    # verify header CRC
    header = data[:8]
    hdr_crc = struct.unpack("<H", data[8:10])[0]
    if _crc(header) != hdr_crc:
        return None
    user = data[10:10 + (LEN - 5)]
    # strip user-data CRCs
    out = bytearray()
    for i in range(0, len(user), 18):
        chunk = user[i:i+16]
        out += chunk
    return bytes(out)


# ── transport + application ───────────────────────────────────────────────

def build_app_request(dest: int, src: int, app_func: int, seq: int = 0,
                      obj_bytes: bytes = b"") -> bytes:
    """app_func is the DNP3 application function code (0x01 read, 0x05 direct operate, etc.)
    obj_bytes is the application object headers (headers + qualifier)."""
    # transport control: FIR=1, FIN=1, SEQ=seq
    transport = bytes([0xC0 | (seq & 0x3F)])
    # app control: FIR=1, FIN=1, CON=0, UNS=0, SEQ=seq
    app_ctrl = bytes([0xC0 | (seq & 0x0F)])
    app = app_ctrl + bytes([app_func]) + obj_bytes
    return build_link_frame(dest, src, transport + app)


def parse_app_response(payload: bytes) -> Dict:
    if len(payload) < 3:
        return {"error": "short"}
    transport = payload[0]
    app = payload[1:]
    if len(app) < 3:
        return {"error": "short app"}
    app_ctrl = app[0]
    app_func = app[1]
    iin = struct.unpack("<H", app[2:4])[0]
    return {
        "transport": transport,
        "app_ctrl": app_ctrl,
        "app_func": app_func,
        "iin": iin,
        "iin_bits": {
            "all_stations":    bool(iin & 0x0001),
            "class_1_events":  bool(iin & 0x0002),
            "class_2_events":  bool(iin & 0x0004),
            "class_3_events":  bool(iin & 0x0008),
            "need_time":       bool(iin & 0x0010),
            "local_control":   bool(iin & 0x0020),
            "device_trouble":  bool(iin & 0x0040),
            "device_restart":  bool(iin & 0x0080),
            "no_func_code":    bool(iin & 0x0100),
            "object_unknown":  bool(iin & 0x0200),
            "parameter_error": bool(iin & 0x0400),
            "event_buffer_ovf": bool(iin & 0x0800),
            "already_executing": bool(iin & 0x1000),
            "config_corrupt":  bool(iin & 0x2000),
        },
        "raw": app.hex(),
    }


# ── commands ──────────────────────────────────────────────────────────────

def cmd_integrity(host: str, port: int, dest: int, src: int) -> int:
    """Integrity poll — request Class 1+2+3+0. Standard health check."""
    print_info("dnp3 integrity poll")
    print_kv("host", host + ":" + str(port))
    print_kv("dest", dest)
    print_kv("src", src)
    print()
    try:
        s = socket.create_connection((host, port), timeout=5)
    except Exception as e:
        print_err("connect: " + str(e))
        return 1
    s.settimeout(5)

    # first: reset link
    s.sendall(build_link_frame(dest, src, b"", func=0x40))
    try:
        s.recv(1024)
    except Exception:
        pass

    # class 1+2+3+0 poll: object header group 60 var 1 (class), qualifier 0x06 (all objects)
    # 0x3C 0x01 0x06 is group 60 var 1 all — 0x3C=60, 0x01=var, 0x06=all objects
    obj = bytes([0x3C, 0x01, 0x06, 0x3C, 0x02, 0x06, 0x3C, 0x03, 0x06, 0x3C, 0x04, 0x06])
    req = build_app_request(dest, src, 0x01, seq=1, obj_bytes=obj)
    s.sendall(req)
    data = b""
    try:
        while len(data) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    s.close()

    if not data:
        print_err("no response")
        return 1
    payload = parse_link_frame(data)
    if payload is None:
        print_err("bad link frame — got " + data[:16].hex())
        return 1
    r = parse_app_response(payload)
    print_ok("response")
    print_kv("app_func", "0x" + format(r.get("app_func", 0), "02x"))
    print_kv("iin", "0x" + format(r.get("iin", 0), "04x"))
    for k, v in r.get("iin_bits", {}).items():
        if v:
            print("  " + SCARLET + "IIN set: " + RESET + k)
    print_kv("payload_bytes", len(data))

    out = DNP3_DIR / ("integrity_" + host.replace(".", "_") + "_" + str(int(time.time())) + ".bin")
    DNP3_DIR.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print_kv("saved", out)
    return 0


def cmd_class_poll(host: str, port: int, dest: int, src: int, cls: int) -> int:
    print_info("dnp3 class " + str(cls) + " poll")
    print_kv("host", host + ":" + str(port))
    print()
    try:
        s = socket.create_connection((host, port), timeout=5)
    except Exception as e:
        print_err("connect: " + str(e))
        return 1
    s.settimeout(5)
    # group 60, var = cls+1 (var 1=class 0, var 2=class 1, var 3=class 2, var 4=class 3)
    obj = bytes([0x3C, cls + 1, 0x06])
    req = build_app_request(dest, src, 0x01, seq=1, obj_bytes=obj)
    s.sendall(req)
    data = b""
    try:
        data = s.recv(4096)
    except socket.timeout:
        pass
    s.close()
    if not data:
        print_err("no response")
        return 1
    payload = parse_link_frame(data)
    if payload is None:
        print_err("bad link frame")
        return 1
    r = parse_app_response(payload)
    print_ok("class " + str(cls) + " response")
    print_kv("app_func", "0x" + format(r.get("app_func", 0), "02x"))
    print_kv("iin", "0x" + format(r.get("iin", 0), "04x"))
    for k, v in r.get("iin_bits", {}).items():
        if v:
            print("  " + SCARLET + "IIN set: " + RESET + k)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky ics dnp3 <sub-command>")
        print_info("")
        print_info("  integrity --host H [--port 20000] [--dest 1] [--src 100]")
        print_info("      integrity poll: class 1+2+3+0, decode IIN bits")
        print_info("  poll --host H --class N [--dest 1]")
        print_info("      single class poll (0..3)")
        return 0

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--host", required=False, default="")
    base.add_argument("--port", type=int, default=20000)
    base.add_argument("--dest", type=int, default=1)
    base.add_argument("--src", type=int, default=100)

    if sub in ("integrity", "int"):
        p = argparse.ArgumentParser(prog="redsky ics dnp3 integrity", parents=[base], add_help=False)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics dnp3 integrity --host H [--dest 1]")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_integrity(ns.host, ns.port, ns.dest, ns.src)

    if sub in ("poll", "class"):
        p = argparse.ArgumentParser(prog="redsky ics dnp3 poll", parents=[base], add_help=False)
        p.add_argument("--class", dest="cls", type=int, default=0)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics dnp3 poll --host H --class 0")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_class_poll(ns.host, ns.port, ns.dest, ns.src, ns.cls)

    print_err("unknown dnp3 sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
