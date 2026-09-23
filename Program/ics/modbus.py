# language: Python, file: Program/ics/modbus.py, target: Red Sky ics — Modbus/TCP
# Modbus/TCP scanner + read/write toolkit.
#   scan       -- find Modbus servers on a CIDR (port 502 + alt 5020)
#   units      -- enumerate valid unit IDs on one server
#   read       -- read coils / discrete inputs / holding / input registers
#   write      -- write coil / register (single or bulk)
#   enumerate  -- walk the address space and surface populated ranges
#   probe      -- full function-code probe (which FCs does this PLC accept)
# Everything builds raw Modbus/TCP frames — no pymodbus dependency.

import json
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


ICS_DIR = OUTPUT_DIR / "ics"
MODBUS_DIR = ICS_DIR / "modbus"
MODBUS_DIR.mkdir(parents=True, exist_ok=True)


# ── Modbus function codes ──
FC_READ_COILS = 0x01
FC_READ_DISCRETE_INPUTS = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_COILS = 0x0F
FC_WRITE_MULTIPLE_REGISTERS = 0x10
FC_REPORT_SERVER_ID = 0x11
FC_READ_FILE_RECORD = 0x14
FC_WRITE_FILE_RECORD = 0x15
FC_MASK_WRITE_REGISTER = 0x16
FC_READ_WRITE_MULTIPLE_REGISTERS = 0x17
FC_READ_FIFO_QUEUE = 0x18
FC_READ_DEVICE_IDENTIFICATION = 0x2B


# ── Modbus/TCP framing ──
def build_request(txid: int, unit_id: int, pdu: bytes) -> bytes:
    """MBAP header = txid(2) + proto(2) + length(2) + unit(1)."""
    length = len(pdu) + 1
    return struct.pack(">HHHB", txid, 0, length, unit_id) + pdu


def read_request(fc: int, start: int, count: int) -> bytes:
    return struct.pack(">BHH", fc, start, count)


def write_single_coil_request(addr: int, value: bool) -> bytes:
    val = 0xFF00 if value else 0x0000
    return struct.pack(">BHH", FC_WRITE_SINGLE_COIL, addr, val)


def write_single_register_request(addr: int, value: int) -> bytes:
    return struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, addr, value)


def write_multiple_registers_request(start: int, values: List[int]) -> bytes:
    body = struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGISTERS, start, len(values), len(values) * 2)
    body += b"".join(struct.pack(">H", v) for v in values)
    return body


def parse_response(data: bytes) -> Optional[Dict]:
    """Parse a Modbus/TCP response. Return {'fc': ..., 'data': ..., 'error': ...}."""
    if len(data) < 9:
        return None
    txid, proto, length, unit = struct.unpack(">HHHB", data[:7])
    pdu = data[7:]
    if not pdu:
        return None
    fc = pdu[0]
    # exception response has the high bit set
    if fc & 0x80:
        code = pdu[1] if len(pdu) > 1 else 0
        return {"fc": fc & 0x7F, "unit": unit, "exception": code,
                "exception_name": {
                    1: "illegal function", 2: "illegal data address",
                    3: "illegal data value", 4: "server device failure",
                    5: "acknowledge", 6: "server device busy",
                    8: "memory parity error", 10: "gateway path unavailable",
                    11: "gateway target device failed",
                }.get(code, "unknown")}
    if fc in (FC_READ_COILS, FC_READ_DISCRETE_INPUTS):
        if len(pdu) < 2:
            return None
        byte_count = pdu[1]
        bits = []
        for b in pdu[2:2+byte_count]:
            for i in range(8):
                bits.append(bool(b & (1 << i)))
        return {"fc": fc, "unit": unit, "bits": bits}
    if fc in (FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS):
        if len(pdu) < 2:
            return None
        byte_count = pdu[1]
        regs = []
        for i in range(2, 2 + byte_count, 2):
            regs.append(struct.unpack(">H", pdu[i:i+2])[0])
        return {"fc": fc, "unit": unit, "registers": regs}
    if fc in (FC_WRITE_SINGLE_COIL, FC_WRITE_SINGLE_REGISTER,
              FC_WRITE_MULTIPLE_COILS, FC_WRITE_MULTIPLE_REGISTERS):
        if len(pdu) >= 5:
            addr, val = struct.unpack(">HH", pdu[1:5])
            return {"fc": fc, "unit": unit, "addr": addr, "value": val, "ok": True}
    if fc == FC_REPORT_SERVER_ID:
        if len(pdu) >= 2:
            bc = pdu[1]
            return {"fc": fc, "unit": unit, "server_id": pdu[2:2+bc].decode("utf-8", errors="replace")}
    if fc == 0x2B:  # read device identification
        return {"fc": fc, "unit": unit, "raw": pdu.hex()}
    return {"fc": fc, "unit": unit, "raw": pdu.hex()}


# ── socket helpers ──
def tcp_probe(ip: str, port: int = 502, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((ip, port))
        s.close()
        return rc == 0
    except Exception:
        return False


def modbus_send(ip: str, port: int, unit_id: int, pdu: bytes,
                timeout: float = 3.0) -> Optional[Dict]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return None
        txid = int(time.time() * 1000) & 0xFFFF
        s.sendall(build_request(txid, unit_id, pdu))
        data = b""
        # read at least the MBAP header + response
        while len(data) < 9:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return parse_response(data)
    except Exception:
        return None


# ── commands ──
def cmd_scan(cidr: str, ports: str, workers: int, out_file: str) -> int:
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print_err("bad cidr: " + cidr)
        return 2

    port_list = [int(p) for p in ports.split(",")] if ports else [502, 5020, 44818, 102]
    hosts = [str(h) for h in net.hosts()][:1024]

    print_info("Modbus / ICS port scan")
    print_kv("cidr", cidr)
    print_kv("hosts", str(len(hosts)))
    print_kv("ports", ",".join(str(p) for p in port_list))
    print()

    hits: List[Dict] = []
    t0 = time.time()

    def probe(ip: str):
        out = []
        for port in port_list:
            if tcp_probe(ip, port, timeout=1.5):
                out.append((ip, port))
        return out

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, ip) for ip in hosts]
        done = 0
        for f in as_completed(futures):
            done += 1
            for ip, port in f.result():
                hits.append({"ip": ip, "port": port})
                svc = {502: "modbus", 5020: "modbus-alt", 44818: "ethernet/ip", 102: "s7comm"}.get(port, "?")
                print("  " + SCARLET + "▓ " + RESET + BONE + ip.ljust(16) + RESET
                      + " " + ARTERY + str(port).ljust(6) + RESET + " " + ASH + svc + RESET)
            if done % 64 == 0:
                print("  " + ASH + "[" + str(done) + "/" + str(len(hosts)) + "]" + RESET + "        ", end="\r")

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("found", len(hits))

    out = Path(out_file) if out_file else MODBUS_DIR / ("scan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


def cmd_units(ip: str, port: int, unit_range: str, out_file: str) -> int:
    if unit_range:
        lo, _, hi = unit_range.partition("-")
        start, end = int(lo), int(hi or lo)
    else:
        start, end = 0, 255

    print_info("Modbus unit ID enumeration")
    print_kv("target", ip + ":" + str(port))
    print_kv("units", str(start) + "-" + str(end))
    print()

    valid = []
    for uid in range(start, end + 1):
        # read 1 holding register — if we get a response at all, the unit is alive
        resp = modbus_send(ip, port, uid, read_request(FC_READ_HOLDING_REGISTERS, 0, 1))
        if resp and "exception" not in resp:
            valid.append(uid)
            print("  " + SCARLET + "▓ " + RESET + "unit " + BONE + str(uid) + RESET
                  + "  " + ASH + "regs[0]=" + str(resp.get("registers", [None])[0]) + RESET)
        elif resp and resp.get("exception") in (1, 2):
            # illegal function or illegal address — the unit answered, so it exists
            valid.append(uid)
            print("  " + ARTERY + "░ " + RESET + "unit " + BONE + str(uid) + RESET
                  + "  " + ASH + "answered exception " + str(resp["exception"]) + RESET)
        time.sleep(0.02)

    print()
    print_kv("live units", len(valid))

    out = Path(out_file) if out_file else MODBUS_DIR / ("units_" + ip.replace(".", "_") + ".json")
    out.write_text(json.dumps({"target": ip, "port": port, "units": valid}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_read(ip: str, port: int, unit: int, fc: int, start: int, count: int,
             out_file: str) -> int:
    print_info("Modbus read")
    print_kv("target", ip + ":" + str(port))
    print_kv("unit", str(unit))
    print_kv("fc", "0x{:02X}".format(fc))
    print_kv("start", str(start))
    print_kv("count", str(count))
    print()

    resp = modbus_send(ip, port, unit, read_request(fc, start, count), timeout=5.0)
    if not resp:
        print_err("no response")
        return 1
    if "exception" in resp:
        print_err("exception " + str(resp["exception"]) + ": " + resp["exception_name"])
        return 1

    if "registers" in resp:
        for i, r in enumerate(resp["registers"]):
            addr = start + i
            print("  " + BONE + str(addr).ljust(6) + RESET + "  "
                  + SCARLET + str(r).ljust(8) + RESET + "  "
                  + ASH + "0x{:04X}".format(r) + RESET + "  "
                  + CLOT + repr(chr(r) if 32 <= r < 127 else ".") + RESET)
    elif "bits" in resp:
        for i, b in enumerate(resp["bits"]):
            addr = start + i
            print("  " + BONE + str(addr).ljust(6) + RESET + "  "
                  + (SCARLET + "TRUE" if b else ASH + "false") + RESET)

    out = Path(out_file) if out_file else MODBUS_DIR / ("read_" + ip.replace(".", "_") + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(resp, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_write(ip: str, port: int, unit: int, kind: str, addr: int, value: str,
              out_file: str) -> int:
    print_info("Modbus write")
    print_kv("target", ip + ":" + str(port))
    print_kv("unit", str(unit))
    print_kv("kind", kind)
    print_kv("addr", str(addr))
    print_kv("value", value)
    print()
    print_warn("this writes to a live device. interruptions can trip safety systems.")

    pdu = None
    if kind == "coil":
        v = value.strip().lower() in ("1", "true", "on", "yes")
        pdu = write_single_coil_request(addr, v)
    elif kind == "register":
        pdu = write_single_register_request(addr, int(value))
    elif kind == "registers":
        vals = [int(x.strip()) for x in value.split(",")]
        pdu = write_multiple_registers_request(addr, vals)
    else:
        print_err("kind must be coil / register / registers")
        return 2

    resp = modbus_send(ip, port, unit, pdu, timeout=5.0)
    if not resp:
        print_err("no response")
        return 1
    if "exception" in resp:
        print_err("exception " + str(resp["exception"]) + ": " + resp["exception_name"])
        return 1

    print_ok("write accepted")
    out = Path(out_file) if out_file else MODBUS_DIR / ("write_" + ip.replace(".", "_") + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"target": ip, "port": port, "unit": unit,
                               "kind": kind, "addr": addr, "value": value,
                               "resp": resp}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_enumerate(ip: str, port: int, unit: int, kind: str, block: int,
                  max_addr: int, out_file: str) -> int:
    """Walk the address space block-by-block and report populated ranges."""
    fc = {"coils": 0x01, "discrete": 0x02, "holding": 0x03, "input": 0x04}.get(kind)
    if fc is None:
        print_err("kind must be coils / discrete / holding / input")
        return 2

    print_info("Modbus address space enumeration")
    print_kv("target", ip + ":" + str(port))
    print_kv("unit", str(unit))
    print_kv("kind", kind)
    print_kv("block size", str(block))
    print_kv("max addr", str(max_addr))
    print()

    populated = []
    for start in range(0, max_addr, block):
        resp = modbus_send(ip, port, unit, read_request(fc, start, block), timeout=3.0)
        if not resp or "exception" in resp:
            continue
        if "registers" in resp:
            regs = resp["registers"]
            non_zero = [(start + i, r) for i, r in enumerate(regs) if r != 0]
            if non_zero:
                populated.append({"start": start, "end": start + block - 1,
                                  "non_zero": len(non_zero),
                                  "sample": [{"addr": a, "value": v} for a, v in non_zero[:5]]})
                print("  " + SCARLET + "▓ " + RESET + BONE + "regs " + str(start).ljust(6)
                      + "-" + str(start + block - 1).ljust(6) + RESET
                      + "  " + ASH + str(len(non_zero)) + " non-zero" + RESET)
        elif "bits" in resp:
            bits = resp["bits"]
            true_count = sum(1 for b in bits if b)
            if true_count:
                populated.append({"start": start, "end": start + block - 1,
                                  "true_count": true_count})
                print("  " + SCARLET + "▓ " + RESET + BONE + "bits " + str(start).ljust(6)
                      + "-" + str(start + block - 1).ljust(6) + RESET
                      + "  " + ASH + str(true_count) + " true" + RESET)
        time.sleep(0.02)

    print()
    print_kv("populated blocks", len(populated))

    out = Path(out_file) if out_file else MODBUS_DIR / ("enum_" + ip.replace(".", "_") + "_" + kind + ".json")
    out.write_text(json.dumps({"target": ip, "kind": kind, "populated": populated}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_probe(ip: str, port: int, unit: int, out_file: str) -> int:
    """Send each function code and log what the device accepts."""
    print_info("Modbus function code probe")
    print_kv("target", ip + ":" + str(port))
    print_kv("unit", str(unit))
    print()

    probes = [
        ("read coils (1 reg)", FC_READ_COILS, read_request(FC_READ_COILS, 0, 1)),
        ("read discrete (1 bit)", FC_READ_DISCRETE_INPUTS, read_request(FC_READ_DISCRETE_INPUTS, 0, 1)),
        ("read holding (1 reg)", FC_READ_HOLDING_REGISTERS, read_request(FC_READ_HOLDING_REGISTERS, 0, 1)),
        ("read input (1 reg)", FC_READ_INPUT_REGISTERS, read_request(FC_READ_INPUT_REGISTERS, 0, 1)),
        ("report server id", FC_REPORT_SERVER_ID, struct.pack(">B", FC_REPORT_SERVER_ID)),
        ("read device id (0x2B/0x0E)", FC_READ_DEVICE_IDENTIFICATION,
         struct.pack(">BBBB", FC_READ_DEVICE_IDENTIFICATION, 0x0E, 0x01, 0x00)),
    ]
    results = []
    for name, fc, pdu in probes:
        resp = modbus_send(ip, port, unit, pdu, timeout=3.0)
        if resp and "exception" not in resp:
            print("  " + SCARLET + "▓ " + RESET + BONE + name.ljust(30) + RESET
                  + " " + ARTERY + "accepted" + RESET)
        elif resp and "exception" in resp:
            print("  " + ASH + "░ " + name.ljust(30) + " exception " + str(resp["exception"]) + RESET)
        else:
            print("  " + ASH + "░ " + name.ljust(30) + " no response" + RESET)
        results.append({"name": name, "fc": fc, "resp": resp})
        time.sleep(0.05)

    out = Path(out_file) if out_file else MODBUS_DIR / ("probe_" + ip.replace(".", "_") + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ics modbus", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["scan", "units", "read", "write", "enumerate", "probe", "help"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--cidr", default="")
    p.add_argument("--ports", default="")
    p.add_argument("--port", type=int, default=502)
    p.add_argument("--unit", type=int, default=1)
    p.add_argument("--units", default="")
    p.add_argument("--fc", type=lambda s: int(s, 0), default=0x03)
    p.add_argument("--start", type=int, default=0)
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--kind", default="holding")
    p.add_argument("--addr", type=int, default=0)
    p.add_argument("--value", default="")
    p.add_argument("--block", type=int, default=16)
    p.add_argument("--max-addr", type=int, default=4096)
    p.add_argument("--workers", type=int, default=128)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ics modbus <scan|units|read|write|enumerate|probe> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("scan --cidr 10.0.0.0/24 [--ports 502,5020] [--workers 128]")
        print_info("units <ip> [--units 0-255] [--port 502]")
        print_info("read <ip> --unit 1 --fc 3 --start 0 --count 10")
        print_info("write <ip> --unit 1 --kind coil --addr 0 --value 1")
        print_info("enumerate <ip> --unit 1 --kind holding --block 16 --max-addr 4096")
        print_info("probe <ip> --unit 1")
        return 0

    if ns.action == "scan":
        if not ns.cidr:
            print_err("--cidr required")
            return 2
        return cmd_scan(ns.cidr, ns.ports, ns.workers, ns.out)
    if not ns.target:
        print_err("target ip required")
        return 2
    if ns.action == "units":
        return cmd_units(ns.target, ns.port, ns.units, ns.out)
    if ns.action == "read":
        return cmd_read(ns.target, ns.port, ns.unit, ns.fc, ns.start, ns.count, ns.out)
    if ns.action == "write":
        if not ns.value:
            print_err("--value required")
            return 2
        return cmd_write(ns.target, ns.port, ns.unit, ns.kind, ns.addr, ns.value, ns.out)
    if ns.action == "enumerate":
        return cmd_enumerate(ns.target, ns.port, ns.unit, ns.kind, ns.block, ns.max_addr, ns.out)
    if ns.action == "probe":
        return cmd_probe(ns.target, ns.port, ns.unit, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
