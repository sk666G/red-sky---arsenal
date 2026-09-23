# language: Python, file: Program/ics_scada/protocols.py, target: Red Sky ics_scada — extended ICS protocols
# Beyond Modbus/S7/DNP3 (which live in Program/ics/), this covers:
#   enip    -- EtherNet/IP / CIP enumeration (list identity, list services)
#   profinet -- Profinet DCP (discover, identify, set name/ip)
#   bacnet  -- BACnet/IP Who-Is, Read-Property (device + object enumeration)
#   opcua   -- OPC-UA discovery + endpoint listing
#   scan    -- combined ICS port sweep across the common port map
# Everything is read-only or discovery-level unless otherwise noted.

import argparse
import json
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


IS_DIR = OUTPUT_DIR / "ics_scada"
IS_DIR.mkdir(parents=True, exist_ok=True)


# standard ICS port map
ICS_PORTS = {
    102:   "S7comm (ISO-TSAP)",
    502:   "Modbus/TCP",
    1089:  "Foundation Fieldbus HSE",
    1090:  "Foundation Fieldbus HSE",
    1091:  "Foundation Fieldbus HSE",
    1911:  "Niagara Fox",
    1962:  "PCWorx",
    2222:  "EtherNet/IP over TCP (alt)",
    2404:  "IEC 60870-5-104",
    2455:  "WAGO I/O",
    4000:  "Emerson ROC",
    4840:  "OPC-UA TCP",
    4843:  "OPC-UA TLS",
    5006:  "MELSEC-Q",
    5007:  "MELSEC-Q",
    5010:  "Modbus/TCP over TLS",
    5011:  "Modbus/TCP over TLS",
    5502:  "Rockwell Automation",
    5555:  "RDP (sometimes used by ICS)",
    8080:  "Web HMI",
    8443:  "Web HMI (TLS)",
    9600:  "OMRON FINS",
    10000: "DNP3 / Johnson Controls",
    10800: "OPC-UA (alt)",
    11001: "ADS (Beckhoff)",
    12000: "OPC-UA (alt)",
    18245: "GE SRTP",
    20000: "DNP3",
    20547: "ProConOS",
    34962: "Profinet RT",
    34963: "Profinet RT",
    34964: "Profinet RPC",
    44818: "EtherNet/IP",
    47808: "BACnet/IP (UDP)",
    55000: "FL-net",
}


def _tcp_probe(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((host, port))
        s.close()
        return rc == 0
    except Exception:
        return False


def cmd_scan(cidr: str, workers: int, out_file: str) -> int:
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print_err("bad cidr")
        return 2
    hosts = [str(h) for h in net.hosts()][:512]

    print_info("ICS port scan (combined)")
    print_kv("cidr", cidr)
    print_kv("hosts", str(len(hosts)))
    print_kv("ports", str(len(ICS_PORTS)))
    print()

    hits = []
    t0 = time.time()

    def probe(host: str):
        found = []
        for port in ICS_PORTS:
            if _tcp_probe(host, port, timeout=1.5):
                found.append((host, port))
        return found

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe, h) for h in hosts]
        for f in as_completed(futs):
            for h, p in f.result():
                svc = ICS_PORTS.get(p, "?")
                hits.append({"host": h, "port": p, "service": svc})
                print("  " + SCARLET + "▓ " + RESET + BONE + h.ljust(16) + RESET
                      + ":" + str(p).ljust(6) + " " + ARTERY + svc + RESET)

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("found", str(len(hits)))

    out = Path(out_file) if out_file else IS_DIR / ("scan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


# ── EtherNet/IP ──
ENIP_LIST_IDENTITY = bytes.fromhex("63000000000000000000000000000000c1 0200 0000000000000000".replace(" ", ""))


def _enip_list_identity(host: str, timeout: float = 3.0) -> Optional[Dict]:
    """Send ListIdentity (0x0063) command over TCP/44818."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, 44818)) != 0:
            s.close()
            return None
        # ENIP encapsulation header
        # command(2) length(2) session(4) status(4) context(8) options(4)
        # ListIdentity cmd 0x0063, length 0
        cmd = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)
        s.sendall(cmd)
        resp = s.recv(4096)
        s.close()
        if len(resp) < 24:
            return None
        cmd_r, len_r, session, status, ctx, opts = struct.unpack("<HHII8sI", resp[:24])
        payload = resp[24:24+len_r]
        # parse ListIdentity payload
        # header: item count(2) then item type(2) + length(2) + data
        info = {"command": cmd_r, "status": status, "raw": payload[:200].hex()}
        if len(payload) >= 4:
            # try to find common patterns
            if b"Rockwell" in payload or b"AB" in payload:
                info["vendor"] = "Rockwell"
            info["device"] = payload[30:60].decode("latin-1", errors="replace").strip("\x00").strip()
        return info
    except Exception:
        return None


def cmd_enip(host: str, out_file: str) -> int:
    if not host:
        print_err("--host required")
        return 2
    print_info("EtherNet/IP ListIdentity")
    print_kv("host", host + ":44818")

    r = _enip_list_identity(host)
    if not r:
        print_warn("no reply")
        return 1
    for k, v in r.items():
        print_kv(k, str(v))
    out = Path(out_file) if out_file else IS_DIR / ("enip_" + host.replace(".", "_") + ".json")
    out.write_text(json.dumps(r, indent=2))
    print_kv("saved", out)
    return 0


# ── Profinet DCP ──
def _profinet_identify(host: str, timeout: float = 3.0) -> Optional[Dict]:
    """Send a Profinet DCP Identify-All request over UDP/34964."""
    # PROFINET DCP packet is 4-byte header + service fields + option fields
    # Service ID 0x05 = Identify, Service Type 0x00 = Request, XID arbitrary
    dcp = struct.pack(">HBB I", 0xFEFF, 0x05, 0x00, 0x01020304)
    # Option 0xFF (All) with suboption 0xFFFF (All)
    block = struct.pack(">HH", 0xFFFF, 0xFFFF) + struct.pack(">HH", 0, 0)  # pad
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(dcp + block, (host, 34964))
        data, _ = s.recvfrom(2048)
        s.close()
        return {"host": host, "raw": data.hex()[:200], "length": len(data)}
    except Exception:
        return None


def cmd_profinet(host: str, out_file: str) -> int:
    if not host:
        print_err("--host required")
        return 2
    print_info("Profinet DCP Identify-All")
    print_kv("host", host + ":34964/udp")

    r = _profinet_identify(host)
    if not r:
        print_warn("no reply")
        return 1
    print_kv("length", str(r["length"]))
    print_kv("raw", r["raw"][:120])

    out = Path(out_file) if out_file else IS_DIR / ("profinet_" + host.replace(".", "_") + ".json")
    out.write_text(json.dumps(r, indent=2))
    print_kv("saved", out)
    return 0


# ── BACnet/IP ──
def _bacnet_who_is(host: str, timeout: float = 3.0) -> Optional[List[Dict]]:
    """Broadcast BACnet/IP Who-Is and collect I-Am replies."""
    # BVLC header: type(1) function(1) length(2)
    # BACnet NPDU: version(1) control(1)
    # APDU: type(1)=0x10 Unconfirmed, service(1)=0x08 Who-Is, data
    bvlc = struct.pack(">BBH", 0x81, 0x0B, 0)  # BVLC-Result / original broadcast
    npdu = b"\x01\x20"  # version 1, no routing
    apdu = b"\x10\x08"  # unconfirmed, who-is, no limits
    payload = bvlc + npdu + apdu
    # fix BVLC length
    payload = struct.pack(">BBH", 0x81, 0x0B, len(payload)) + payload[4:]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(timeout)
        s.sendto(payload, (host if host != "255.255.255.255" else "255.255.255.255", 47808))
        results = []
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
                results.append({"from": addr[0], "raw": data.hex()[:200]})
            except socket.timeout:
                break
        s.close()
        return results
    except Exception:
        return None


def cmd_bacnet(host: str, out_file: str) -> int:
    if not host:
        host = "255.255.255.255"
    print_info("BACnet/IP Who-Is")
    print_kv("target", host + ":47808/udp")

    r = _bacnet_who_is(host)
    if r is None or not r:
        print_warn("no I-Am replies")
        return 1
    for item in r:
        print("  " + SCARLET + "▓ " + RESET + BONE + item["from"] + RESET
              + "  " + ASH + item["raw"][:80] + RESET)

    out = Path(out_file) if out_file else IS_DIR / ("bacnet_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(r, indent=2))
    print_kv("saved", out)
    return 0


# ── OPC-UA ──
def _opcua_get_endpoints(host: str, port: int = 4840, timeout: float = 5.0) -> Optional[Dict]:
    """Send a bare Hello + GetEndpoints request over TCP."""
    # OPC-UA binary is complex — we send a Hello and read the ACK + maybe endpoints
    # Message header: type(3)='HEL' + chunk(1)='F' + size(4)
    # Hello body: protocol version(4), recv buffer(4), send buffer(4), max msg size(4), max chunk count(4),
    #             endpoint url length(4), endpoint url
    url = b"opc.tcp://" + host.encode() + b":" + str(port).encode()
    body = struct.pack("<IIIII I", 0, 65535, 65535, 0, 0, len(url)) + url
    msg = b"HELF" + struct.pack("<I", 8 + len(body)) + body
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            s.close()
            return None
        s.sendall(msg)
        resp = s.recv(4096)
        s.close()
        out = {"host": host, "port": port, "raw_len": len(resp), "hex": resp.hex()[:200]}
        if resp[:3] == b"ACK":
            out["ack"] = True
        return out
    except Exception:
        return None


def cmd_opcua(host: str, port: int, out_file: str) -> int:
    if not host:
        print_err("--host required")
        return 2
    port = port or 4840
    print_info("OPC-UA Hello")
    print_kv("host", host + ":" + str(port))

    r = _opcua_get_endpoints(host, port)
    if not r:
        print_warn("no reply")
        return 1
    for k, v in r.items():
        print_kv(k, str(v))

    out = Path(out_file) if out_file else IS_DIR / ("opcua_" + host.replace(".", "_") + ".json")
    out.write_text(json.dumps(r, indent=2))
    print_kv("saved", out)
    return 0


def cmd_list() -> int:
    print_info(str(len(ICS_PORTS)) + " ICS ports in map")
    print()
    for p, svc in sorted(ICS_PORTS.items()):
        print("  " + SCARLET + "* " + RESET + str(p).ljust(7) + " " + BONE + svc + RESET)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky ics_scada protocols", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list",
                   choices=["scan", "enip", "profinet", "bacnet", "opcua", "list"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--host", default="")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--cidr", default="")
    p.add_argument("--workers", type=int, default=64)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ics_scada protocols <scan|enip|profinet|bacnet|opcua|list> [opts]")
        return 2

    if ns.help:
        print_info("list                                  -- ICS port map")
        print_info("scan --cidr 10.0.0.0/24               -- all ICS ports across a subnet")
        print_info("enip --host 10.0.0.5                  -- EtherNet/IP ListIdentity")
        print_info("profinet --host 10.0.0.5              -- Profinet DCP Identify")
        print_info("bacnet [--host 255.255.255.255]       -- BACnet/IP Who-Is")
        print_info("opcua --host 10.0.0.5 [--port 4840]   -- OPC-UA Hello")
        return 0

    if ns.action == "list":
        return cmd_list()
    if ns.action == "scan":
        if not ns.cidr:
            print_err("--cidr required")
            return 2
        return cmd_scan(ns.cidr, ns.workers, ns.out)
    host = ns.host or ns.target
    if ns.action == "enip":
        return cmd_enip(host, ns.out)
    if ns.action == "profinet":
        return cmd_profinet(host, ns.out)
    if ns.action == "bacnet":
        return cmd_bacnet(host, ns.out)
    if ns.action == "opcua":
        return cmd_opcua(host, ns.port, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
