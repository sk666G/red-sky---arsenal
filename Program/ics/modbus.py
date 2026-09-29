# language: Python, file: Program/ics/modbus.py, target: Red Sky ics — Modbus TCP
# Modbus TCP client. Raw socket, no pymodbus dependency — the wire format
# is simple enough that building it directly is shorter.
#
# Frame layout (MBAP + PDU):
#   MBAP header (7 bytes):
#     transaction id (2)  protocol id = 0 (2)  length (2)  unit id (1)
#   PDU:
#     function code (1)   data (N)
#
# Function codes we care about:
#   0x01  Read Coils                (bit outputs — relays, valves)
#   0x02  Read Discrete Inputs      (bit inputs — switches, sensors)
#   0x03  Read Holding Registers    (16-bit — setpoints, config)
#   0x04  Read Input Registers      (16-bit — sensor readings)
#   0x05  Write Single Coil         (turn an output on/off)
#   0x06  Write Single Register     (set a 16-bit value)
#   0x0F  Write Multiple Coils
#   0x10  Write Multiple Registers
#
# Modbus has no authentication. Any device that answers on TCP/502 accepts
# any write that names a valid unit id.

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
MODBUS_DIR = ICS_DIR / "modbus"


# ── wire format ────────────────────────────────────────────────────────────

def _mbap(txid: int, unit: int, pdu: bytes) -> bytes:
    length = len(pdu) + 1  # + unit id
    return struct.pack("!HHHB", txid, 0, length, unit) + pdu


def _read_coils(unit: int, addr: int, count: int) -> bytes:
    return struct.pack("!BHH", 0x01, addr, count)


def _read_discrete(unit: int, addr: int, count: int) -> bytes:
    return struct.pack("!BHH", 0x02, addr, count)


def _read_holding(unit: int, addr: int, count: int) -> bytes:
    return struct.pack("!BHH", 0x03, addr, count)


def _read_input(unit: int, addr: int, count: int) -> bytes:
    return struct.pack("!BHH", 0x04, addr, count)


def _write_coil(unit: int, addr: int, value: int) -> bytes:
    # 0xFF00 = ON, 0x0000 = OFF
    val = 0xFF00 if value else 0x0000
    return struct.pack("!BHH", 0x05, addr, val)


def _write_reg(unit: int, addr: int, value: int) -> bytes:
    return struct.pack("!BHH", 0x06, addr, value & 0xFFFF)


def _write_multi_regs(unit: int, addr: int, values: List[int]) -> bytes:
    body = struct.pack("!BHHB", 0x10, addr, len(values), len(values) * 2)
    for v in values:
        body += struct.pack("!H", v & 0xFFFF)
    return body


def _transact(host: str, port: int, unit: int, pdu: bytes, timeout: int = 5) -> Optional[bytes]:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return None
    txid = int(time.time() * 1000) & 0xFFFF
    pkt = _mbap(txid, unit, pdu)
    try:
        s.sendall(pkt)
        s.settimeout(timeout)
        # read MBAP header
        head = s.recv(7)
        if len(head) < 7:
            s.close()
            return None
        rtxid, rproto, rlen, runit = struct.unpack("!HHHB", head)
        body = b""
        while len(body) < rlen - 1:
            chunk = s.recv(rlen - 1 - len(body))
            if not chunk:
                break
            body += chunk
        s.close()
        return body
    except Exception:
        s.close()
        return None


def _parse_read_bits(body: bytes) -> Optional[Tuple[int, List[int]]]:
    """Returns (byte_count, [bit values])."""
    if len(body) < 2:
        return None
    fc = body[0]
    if fc & 0x80:
        return None  # error
    bc = body[1]
    bits = []
    for i in range(2, 2 + bc):
        if i >= len(body):
            break
        for b in range(8):
            bits.append((body[i] >> b) & 1)
    return bc, bits


def _parse_read_regs(body: bytes) -> Optional[List[int]]:
    if len(body) < 2:
        return None
    fc = body[0]
    if fc & 0x80:
        return None
    bc = body[1]
    regs = []
    for i in range(0, bc, 2):
        if 2 + i + 1 >= len(body):
            break
        regs.append(struct.unpack("!H", body[2+i:2+i+2])[0])
    return regs


def _error_code(body: bytes) -> Optional[int]:
    if len(body) >= 2 and (body[0] & 0x80):
        return body[1]
    return None


# ── commands ───────────────────────────────────────────────────────────────

def cmd_scan(host: str, port: int, unit_start: int, unit_end: int) -> int:
    """Probe unit IDs 1-247 by trying a single read on each."""
    print_info("modbus unit id scan")
    print_kv("host", host + ":" + str(port))
    print_kv("unit_range", str(unit_start) + ".." + str(unit_end))
    print()

    alive = []
    for uid in range(unit_start, unit_end + 1):
        body = _transact(host, port, uid, _read_holding(uid, 0, 1))
        if body and len(body) >= 2 and not (body[0] & 0x80):
            print("  " + SCARLET + "UNIT " + str(uid) + RESET + " — answered read holding reg 0")
            alive.append(uid)
        elif body and _error_code(body) is not None:
            # error response = device is there, just refused this read
            print("  " + ARTERY + "unit " + str(uid) + RESET + " — err code " + str(_error_code(body)))
            alive.append(uid)
    print()
    print_kv("units_responding", len(alive))
    out = MODBUS_DIR / ("scan_" + host.replace(".", "_") + "_" + str(int(time.time())) + ".json")
    MODBUS_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"host": host, "port": port, "units": alive}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_read(host: str, port: int, unit: int, kind: str, addr: int, count: int) -> int:
    if kind == "coils":
        pdu = _read_coils(unit, addr, count)
    elif kind == "discrete":
        pdu = _read_discrete(unit, addr, count)
    elif kind == "holding":
        pdu = _read_holding(unit, addr, count)
    elif kind == "input":
        pdu = _read_input(unit, addr, count)
    else:
        print_err("kind must be coils|discrete|holding|input")
        return 1

    body = _transact(host, port, unit, pdu)
    if body is None:
        print_err("no response")
        return 1
    err = _error_code(body)
    if err is not None:
        print_err("modbus exception code " + str(err))
        return 1

    print_info("modbus read")
    print_kv("host", host + ":" + str(port))
    print_kv("unit", unit)
    print_kv("kind", kind)
    print_kv("start", addr)
    print_kv("count", count)
    print()

    if kind in ("coils", "discrete"):
        r = _parse_read_bits(body)
        if not r:
            print_err("parse failed")
            return 1
        _, bits = r
        for i, b in enumerate(bits[:count]):
            print("  " + BONE + str(addr + i).ljust(6) + RESET + " " + (SCARLET + "1" + RESET if b else ASH + "0" + RESET))
    else:
        regs = _parse_read_regs(body)
        if regs is None:
            print_err("parse failed")
            return 1
        for i, v in enumerate(regs):
            signed = v - 0x10000 if v >= 0x8000 else v
            print("  " + BONE + str(addr + i).ljust(6) + RESET + " " + SCARLET + str(v) + RESET + " " + ASH + "(0x" + format(v, "04x") + " " + str(signed) + ")" + RESET)
    return 0


def cmd_write(host: str, port: int, unit: int, kind: str, addr: int,
              value: str, dry_run: bool) -> int:
    if kind == "coil":
        try:
            v = int(value, 0)
        except ValueError:
            v = 1 if value.lower() in ("on", "true", "1") else 0
        pdu = _write_coil(unit, addr, v)
        desc = "coil " + str(addr) + " = " + ("ON" if v else "OFF")
    elif kind == "register":
        try:
            v = int(value, 0)
        except ValueError:
            print_err("value must be integer (0x.. or decimal)")
            return 1
        pdu = _write_reg(unit, addr, v)
        desc = "register " + str(addr) + " = " + str(v)
    elif kind == "registers":
        try:
            values = [int(x, 0) for x in value.split(",")]
        except ValueError:
            print_err("registers value must be comma-separated ints")
            return 1
        pdu = _write_multi_regs(unit, addr, values)
        desc = "registers " + str(addr) + ".." + str(addr + len(values) - 1) + " = " + str(values)
    else:
        print_err("kind must be coil|register|registers")
        return 1

    print_info("modbus write" + (" (DRY RUN)" if dry_run else ""))
    print_kv("host", host + ":" + str(port))
    print_kv("unit", unit)
    print_kv("op", desc)
    if dry_run:
        print()
        print_warn("dry-run: no packet sent")
        return 0

    body = _transact(host, port, unit, pdu)
    if body is None:
        print_err("no response")
        return 1
    err = _error_code(body)
    if err is not None:
        print_err("modbus exception code " + str(err))
        return 1
    print_ok("write acknowledged")
    return 0


def cmd_dump(host: str, port: int, unit: int, addr: int, count: int) -> int:
    """Read a span of holding registers, print as a grid."""
    regs = []
    remaining = count
    start = addr
    while remaining > 0:
        chunk = min(125, remaining)  # modbus max per request
        body = _transact(host, port, unit, _read_holding(unit, start, chunk))
        if body is None:
            break
        r = _parse_read_regs(body)
        if not r:
            break
        regs.extend(r)
        start += len(r)
        remaining -= len(r)
        if len(r) == 0:
            break

    print_info("holding register dump")
    print_kv("host", host + ":" + str(port))
    print_kv("unit", unit)
    print_kv("start", addr)
    print_kv("count", len(regs))
    print()
    for i in range(0, len(regs), 8):
        line = "  " + ASH + str(addr + i).zfill(5) + RESET + "  "
        for j in range(i, min(i + 8, len(regs))):
            line += BONE + format(regs[j], "04x") + " " + RESET
        print(line)

    out = MODBUS_DIR / ("dump_" + host.replace(".", "_") + "_" + str(unit) + "_" + str(int(time.time())) + ".json")
    MODBUS_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"host": host, "port": port, "unit": unit,
                                "start": addr, "regs": regs}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky ics modbus <sub-command>")
        print_info("")
        print_info("  scan --host H [--port 502] [--from 1] [--to 247]")
        print_info("      probe unit IDs by firing a read on each")
        print_info("  read --host H --unit N --kind coils|discrete|holding|input --addr A --count C")
        print_info("  write --host H --unit N --kind coil|register|registers --addr A --value V [--dry-run]")
        print_info("  dump --host H --unit N --addr A --count C")
        print_info("      read a span of holding registers, print hex grid")
        return 0

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("--host", required=False, default="")
    base.add_argument("--port", type=int, default=502)
    base.add_argument("--unit", type=int, default=1)

    if sub == "scan":
        p = argparse.ArgumentParser(prog="redsky ics modbus scan", parents=[base], add_help=False)
        p.add_argument("--from", dest="ufrom", type=int, default=1)
        p.add_argument("--to", dest="uto", type=int, default=247)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics modbus scan --host H [--from 1 --to 247]")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_scan(ns.host, ns.port, ns.ufrom, ns.uto)

    if sub == "read":
        p = argparse.ArgumentParser(prog="redsky ics modbus read", parents=[base], add_help=False)
        p.add_argument("--kind", default="holding", choices=["coils", "discrete", "holding", "input"])
        p.add_argument("--addr", type=int, default=0)
        p.add_argument("--count", type=int, default=16)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics modbus read --host H --unit N --kind holding --addr A --count C")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_read(ns.host, ns.port, ns.unit, ns.kind, ns.addr, ns.count)

    if sub == "write":
        p = argparse.ArgumentParser(prog="redsky ics modbus write", parents=[base], add_help=False)
        p.add_argument("--kind", default="register", choices=["coil", "register", "registers"])
        p.add_argument("--addr", type=int, default=0)
        p.add_argument("--value", required=False, default="")
        p.add_argument("--dry-run", action="store_true")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics modbus write --host H --unit N --kind register --addr A --value V")
            return 2
        if not ns.host or ns.value == "":
            print_err("--host and --value required")
            return 2
        return cmd_write(ns.host, ns.port, ns.unit, ns.kind, ns.addr, ns.value, ns.dry_run)

    if sub == "dump":
        p = argparse.ArgumentParser(prog="redsky ics modbus dump", parents=[base], add_help=False)
        p.add_argument("--addr", type=int, default=0)
        p.add_argument("--count", type=int, default=100)
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ics modbus dump --host H --unit N --addr A --count C")
            return 2
        if not ns.host:
            print_err("--host required")
            return 2
        return cmd_dump(ns.host, ns.port, ns.unit, ns.addr, ns.count)

    print_err("unknown modbus sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
