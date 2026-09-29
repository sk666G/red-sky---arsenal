# language: Python, file: Program/ics/s7.py, target: Red Sky ics — Siemens S7comm
# Siemens S7comm client. Three nested layers on TCP/102:
#
#   TPKT        (RFC 1006) — ISO-on-TCP transport
#   COTP        (RFC 905)  — connection-oriented transport
#   S7comm                 — Siemens protocol payload
#
# S7comm operations:
#   0xF0  Setup Communication
#   0x04  Read Variable
#   0x05  Write Variable
#   0x1D  Request SZL (System Status List)
#   0x28  PLC Control (start/stop)
#
# S7comm-plus (0x72) is a separate newer protocol used by S7-1200/1500 with
# TLS-like security features. Not implemented here.
#
# Read/write addresses use a 7-byte pointer:
#   area (1)  DB number (2)  access (1)  address (3)
# Areas: 0x81 = Inputs, 0x82 = Outputs, 0x83 = Merkers, 0x84 = DB,
#        0x1C = counters, 0x1D = timers
# Access: 0x02 = byte, 0x04 = word, 0x06 = dword

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
S7_DIR = ICS_DIR / "s7"


# ── TPKT + COTP ────────────────────────────────────────────────────────────

def _tpkt(payload: bytes) -> bytes:
    # version=3 reserved=0 length(2 BE) — includes the 4-byte header
    return struct.pack("!BBH", 3, 0, len(payload) + 4) + payload


def _cotp_connect() -> bytes:
    # COTP Connection Request: 0xE0, dst-ref(2), src-ref(2), class=0
    # parameters: TPDU size (0xC0), src TSAP (0xC1), dst TSAP (0xC2)
    # TSAP for S7-300/400: source = 0x0100, dest = 0x0102 (rack 0, slot 2)
    payload = struct.pack("!BBHHB", 0x11, 0xE0, 0x0000, 0x0001, 0x00)
    # TPDU size parameter: 0xC0 0x01 0x0A (1024 bytes)
    payload += bytes([0xC0, 0x01, 0x0A])
    # src TSAP
    payload += bytes([0xC1, 0x02, 0x01, 0x00])
    # dst TSAP — rack 0, slot 2 → 0x0102
    payload += bytes([0xC2, 0x02, 0x01, 0x02])
    return _tpkt(payload)


def _cotp_data(payload: bytes) -> bytes:
    # COTP Data: 0x0F, EOT=1, TPDU number = 0
    return _tpkt(bytes([0x02, 0xF0, 0x80]) + payload)


# ── S7comm PDU ─────────────────────────────────────────────────────────────

def _s7_header(pdu: bytes, rosctr: int = 0x01) -> bytes:
    # protocol id = 0x32, ROSCTR, redundancy id = 0x0000, PDURef (2), ParamLen (2), DataLen (2)
    return bytes([0x32, rosctr, 0x00, 0x00]) + struct.pack("!HHH", 1, 0, len(pdu)) + pdu


def _setup_comm() -> bytes:
    # F0 00 00 01 00 01 03 C0  —  max AmQ = 1, max PDU = 960
    params = bytes([0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xC0])
    return _s7_header(params, rosctr=0x01)


def _read_szl(szl_id: int) -> bytes:
    # SZL read: 0x1D + 0x00 0x00 (SZL id) + 0x00 0x00 (index)
    # Actual format: 0x1D, 0x00, <szl_id(2)>, <index(2)>
    params = bytes([0x1D, 0x00]) + struct.pack("!HH", szl_id, 0x0000)
    return _s7_header(params, rosctr=0x01)


def _read_var(area: int, db: int, start: int, length_bytes: int) -> bytes:
    # Item: 0x12, var_spec(0x0A), length(2 BE), syntax(0x10),
    #       transport_size (0x02 = byte, 0x04 = word, 0x06 = dword),
    #       length(2), DB(2), area(1), addr(3 bytes)
    # For a byte read: transport_size = 0x02, length = byte count
    # Address is expressed in bits — so byte 0 = bit address 0
    addr_bits = start * 8
    item = bytes([0x12, 0x0A, 0x10])
    item += bytes([0x02])  # transport size: byte
    item += struct.pack("!H", length_bytes)
    item += struct.pack("!H", db)
    item += bytes([area])
    item += (addr_bits & 0xFFFFFF).to_bytes(3, "big")
    params = bytes([0x04, 0x01]) + item  # 0x04 = read var, item count 1
    return _s7_header(params, rosctr=0x01)


def _write_var(area: int, db: int, start: int, data: bytes) -> bytes:
    addr_bits = start * 8
    item = bytes([0x12, 0x0A, 0x10, 0x02])  # spec, len, syntax, transport=byte
    item += struct.pack("!H", len(data))
    item += struct.pack("!H", db)
    item += bytes([area])
    item += (addr_bits & 0xFFFFFF).to_bytes(3, "big")
    params = bytes([0x05, 0x01]) + item
    # data payload: 0x00, 0x04 (transport: byte), length*8, data (+ pad to even)
    data_header = bytes([0x00, 0x04]) + struct.pack("!H", len(data) * 8)
    payload = data_header + data
    if len(data) % 2:
        payload += b"\x00"
    return _s7_header(params, rosctr=0x01) + payload


# ── connection ────────────────────────────────────────────────────────────

def s7_connect(host: str, port: int = 102, timeout: int = 5) -> Optional[socket.socket]:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(_cotp_connect())
        resp = s.recv(1024)
        if not resp or len(resp) < 6:
            s.close()
            return None
        # COTP connect confirm: byte 5 should be 0xD0
        if resp[5] != 0xD0:
            s.close()
            return None
        # send S7 Setup Communication
        s.sendall(_cotp_data(_setup_comm()))
        resp = s.recv(1024)
        if not resp or len(resp) < 8:
            s.close()
            return None
        return s
    except Exception:
        return None


def s7_transact(s: socket.socket, pdu: bytes, timeout: int = 5) -> Optional[bytes]:
    try:
        s.sendall(_cotp_data(pdu))
        s.settimeout(timeout)
        resp = s.recv(4096)
        if not resp:
            return None
        return resp
    except Exception:
        return None


# ── commands ──────────────────────────────────────────────────────────────

def cmd_info(host: str, port: int) -> int:
    print_info("s7 info")
    print_kv("host", host + ":" + str(port))
    print()
    s = s7_connect(host, port)
    if s is None:
        print_err("connect failed (not s7, or port blocked)")
        return 1
    print_ok("COTP + Setup Communication OK")

    # SZL 0x001C = component identification (order number, firmware)
    for szl_id, label in [
        (0x001C, "component identification"),
        (0x0011, "communication status"),
        (0x0013, "memory"),
        (0x0000, "order number"),
    ]:
        resp = s7_transact(s, _read_szl(szl_id))
        if resp and len(resp) > 20:
            # SZL response payload starts after COTP(3) + S7 header(10) + param(4)
            payload = resp[17:]
            print()
            print_kv(label + " (SZL 0x" + format(szl_id, "04x") + ")",
                     str(len(payload)) + " bytes")
            # dump printable strings
            txt = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
            print("  " + BONE + txt[:200] + RESET)
    s.close()
    return 0


def cmd_read(host: str, port: int, area_name: str, db: int, start: int, length: int) -> int:
    areas = {"input": 0x81, "output": 0x82, "merker": 0x83, "db": 0x84, "counter": 0x1C, "timer": 0x1D}
    if area_name not in areas:
        print_err("area must be one of: " + ", ".join(areas.keys()))
        return 1
    area = areas[area_name]

    print_info("s7 read")
    print_kv("host", host + ":" + str(port))
    print_kv("area", area_name + " (0x" + format(area, "02x") + ")")
    if area_name == "db":
        print_kv("db", db)
    print_kv("start", start)
    print_kv("length", length)
    print()

    s = s7_connect(host, port)
    if s is None:
        print_err("connect failed")
        return 1
    resp = s7_transact(s, _read_var(area, db, start, length))
    s.close()
    if resp is None:
        print_err("no response")
        return 1

    # Look for data payload: 0xFF marker at end of PDU
    idx = resp.rfind(b"\xff\x04")
    data = b""
    if idx >= 0 and idx + 4 <= len(resp):
        # 0xFF, transport(1), length(2), then data
        dlen = struct.unpack("!H", resp[idx+2:idx+4])[0]
        data = resp[idx+4:idx+4+dlen]
    print_ok("read " + str(len(data)) + " bytes")
    print()
    for i in range(0, len(data), 16):
        row = data[i:i+16]
        hexs = " ".join(format(b, "02x") for b in row)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print("  " + ASH + str(start + i).zfill(5) + RESET + "  "
              + BONE + hexs.ljust(48) + RESET + "  " + ARTERY + txt + RESET)

    out = S7_DIR / ("read_" + host.replace(".", "_") + "_" + str(int(time.time())) + ".bin")
    S7_DIR.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print()
    print_kv("saved", out)
    return 0


def cmd_write(host: str, port: int, area_name: str, db: int, start: int,
              hex_value: str, dry_run: bool) -> int:
    areas = {"input": 0x81, "output": 0x82, "merker": 0x83, "db": 0x84}
    if area_name not in areas:
        print_err("area must be: input, output, merker, db")
        return 1
    if not hex_value:
        print_err("--hex required (hex bytes, e.g. 01020304)")
        return 1
    try:
        data = bytes.fromhex(hex_value.replace(" ", ""))
    except ValueError:
        print_err("invalid hex")
        return 1

    area = areas[area_name]
    print_info("s7 write" + (" (DRY RUN)" if dry_run else ""))
    print_kv("host", host + ":" + str(port))
    print_kv("area", area_name)
    print_kv("db", db)
    print_kv("start", start)
    print_kv("bytes", len(data))
    print_kv("hex", data.hex())

    if dry_run:
        print()
        print_warn("dry-run: no packet sent")
        return 0

    s = s7_connect(host, port)
    if s is None:
        print_err("connect failed")
        return 1
    resp = s7_transact(s, _write_var(area, db, start, data))
    s.close()
    if resp is None:
        print_err("no response")
        return 1
    # check response for ACK data with error code
    if len(resp) > 21 and resp[20] == 0x00:
        print_ok("write acknowledged")
        return 0
    print_ok("write sent (check response: " + resp[-8:].hex() + ")")
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky ics s7 <sub-command>")
        print_info("")
        print_info("  info --host H [--port 102]")
        print_info("      read SZL 0x1C (component identification) + order number")
        print_info("  read --host H [--area merker|db|input|output] [--db N] --start B --length L")
        print_info("      read a byte range from the PLC")
        print_info("  write --host H --area merker|db [--db N] --start B --hex AABBCCDD [--dry-run]")
        print_info("      write bytes to the PLC")
        return 0

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--host", required=False, default="")
    base.add_argument("--port", type=int, default=102)

    if sub == "info":
        p = argparse.ArgumentParser(prog="redsky ics s7 info", parents=[base], add_help=False)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics s7 info --host H")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_info(ns.host, ns.port)

    if sub == "read":
        p = argparse.ArgumentParser(prog="redsky ics s7 read", parents=[base], add_help=False)
        p.add_argument("--area", default="merker")
        p.add_argument("--db", type=int, default=1)
        p.add_argument("--start", type=int, default=0)
        p.add_argument("--length", type=int, default=16)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics s7 read --host H --area merker --start 0 --length 16")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_read(ns.host, ns.port, ns.area, ns.db, ns.start, ns.length)

    if sub == "write":
        p = argparse.ArgumentParser(prog="redsky ics s7 write", parents=[base], add_help=False)
        p.add_argument("--area", default="merker")
        p.add_argument("--db", type=int, default=1)
        p.add_argument("--start", type=int, default=0)
        p.add_argument("--hex", dest="hex_value", required=False, default="")
        p.add_argument("--dry-run", action="store_true")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics s7 write --host H --area merker --start 0 --hex AABBCC [--dry-run]")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_write(ns.host, ns.port, ns.area, ns.db, ns.start, ns.hex_value, ns.dry_run)

    print_err("unknown s7 sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
