# language: Python, file: Program/crack/mitm_license.py, target: Red Sky crack — MITM license
# Intercept license server calls. Two modes:
#   1. hosts-file redirect — point the license domain at localhost, run a fake server
#   2. Live MITM proxy — sniff and replay the license server's real responses
# Serves a "valid" response for any activation request.

import http.server
import json
import socketserver
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


# ── generic "always valid" response shapes ──
RESPONSES = {
    "json": lambda req: json.dumps({
        "status": "ok",
        "valid": True,
        "license": "REDSKY-UNLOCKED",
        "expires": "2099-12-31",
        "features": ["pro", "enterprise", "unlimited"],
    }).encode(),
    "xml":  lambda req: (
        '<?xml version="1.0"?><response><status>ok</status>'
        '<valid>true</valid><expires>2099-12-31</expires></response>'
    ).encode(),
    "text": lambda req: b"OK",
}


class ReplayHandler(http.server.BaseHTTPRequestHandler):
    response_format = "json"
    log_path: Optional[Path] = None

    def log_message(self, fmt, *args):
        pass

    def _respond(self):
        body = RESPONSES[self.response_format](self.rfile.read(
            int(self.headers.get("Content-Length", 0) or 0)
        ))

        # log the intercepted request
        entry = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
        }
        if self.log_path:
            with self.log_path.open("a") as f:
                f.write(json.dumps(entry) + "\n")

        print(f"  {ARTERY}▓{RESET} {self.command} {self.path} -> 200 ({self.response_format})")

        self.send_response(200)
        self.send_header("Content-Type", f"application/{self.response_format}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  self._respond()
    def do_POST(self): self._respond()
    def do_PUT(self):  self._respond()


def cmd_serve(port: int, fmt: str, log_dir: str) -> int:
    log_dir_p = Path(log_dir) if log_dir else OUTPUT_DIR / "crack" / "mitm"
    log_dir_p.mkdir(parents=True, exist_ok=True)
    log_path = log_dir_p / "requests.jsonl"

    ReplayHandler.response_format = fmt
    ReplayHandler.log_path = log_path

    print_info(f"license replay server on 0.0.0.0:{port}")
    print_kv("response format", fmt)
    print_kv("log", log_path)
    print()
    print_warn("point the target's license domain at this host:")
    print(f"  {ASH}# on Windows: C:\\Windows\\System32\\drivers\\etc\\hosts{RESET}")
    print(f"  {ASH}# on Linux:   /etc/hosts{RESET}")
    print(f"  {ASH}127.0.0.1  license.example.com  activation.example.com{RESET}")
    print(f"  {ASH}# or use TLS strip — see docs{OFF}{RESET}")
    print()
    print_info("CTRL+C to stop")

    handler = ReplayHandler
    with socketserver.ThreadingTCPServer(("0.0.0.0", port), handler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print()
            print_info("stopped")
    return 0


def cmd_dump(log_dir: str) -> int:
    log_dir_p = Path(log_dir) if log_dir else OUTPUT_DIR / "crack" / "mitm"
    log_path = log_dir_p / "requests.jsonl"
    if not log_path.exists():
        print_warn("no requests logged yet")
        return 0
    for line in log_path.read_text().splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        print(f"  {ARTERY}▓{RESET} {BONE}{e['method']} {e['path']}{RESET}")
        for k, v in e.get("headers", {}).items():
            print(f"      {ASH}{k}: {v}{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky crack mitm <serve|dump> [--port N] [--format json|xml|text]")
        return 2

    sub = args[0]
    port = 443
    fmt = "json"
    log_dir = ""

    i = 1
    while i < len(args):
        a = args[i]
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2; continue
        if a == "--format" and i + 1 < len(args):
            fmt = args[i + 1]; i += 2; continue
        if a == "--log-dir" and i + 1 < len(args):
            log_dir = args[i + 1]; i += 2; continue
        i += 1

    if sub == "serve":
        return cmd_serve(port, fmt, log_dir)
    if sub == "dump":
        return cmd_dump(log_dir)
    print_err(f"unknown mitm action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
