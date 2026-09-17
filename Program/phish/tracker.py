# language: Python, file: Program/phish/tracker.py, target: Red Sky phish — tracker
# Track opens. Serve a 1x1 transparent pixel; log IP + UA + Referer per hit.

import base64
import http.server
import json
import socketserver
import sys
import time
from pathlib import Path
from typing import Dict

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


# 1x1 transparent GIF
PIXEL = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
LOG_DIR = OUTPUT_DIR / "phish" / "track"


class TrackerHandler(http.server.BaseHTTPRequestHandler):
    log_all: bool = False

    def log_message(self, fmt, *args):
        pass

    def _log(self, kind: str):
        ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() \
             or self.client_address[0]
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": kind,
            "ip": ip,
            "ua": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer", ""),
            "path": self.path,
        }
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with (LOG_DIR / "opens.jsonl").open("a") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"  {ARTERY}▓{RESET} {ASH}{entry['ts']}{RESET}  "
              f"{BONE}{ip:<16}{RESET}  {CLOT}{entry['referer'][:60]}{RESET}")

    def do_GET(self):
        self._log("open")
        # serve the pixel
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(PIXEL)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(PIXEL)

    def do_HEAD(self):
        self._log("head")
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(PIXEL)))
        self.end_headers()


def cmd_serve(port: int) -> int:
    print_info(f"tracking pixel server on 0.0.0.0:{port}")
    print_kv("log", LOG_DIR / "opens.jsonl")
    print()
    print_info(f"embed in email HTML:")
    print(f'  {ASH}<img src="https://your.tld:{port}/pixel.gif" width="1" height="1">{RESET}')
    print()
    print_info("CTRL+C to stop")

    with socketserver.ThreadingTCPServer(("0.0.0.0", port), TrackerHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print()
            print_info("stopped")
    return 0


def cmd_dump() -> int:
    log = LOG_DIR / "opens.jsonl"
    if not log.exists():
        print_warn("no opens logged yet")
        return 0
    rows = log.read_text().splitlines()
    print_info(f"{len(rows)} opens")
    for line in rows:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        print(f"  {ARTERY}▓{RESET} {ASH}{e['ts']}{RESET}  {BONE}{e['ip']:<16}{RESET}  "
              f"{CLOT}{e.get('referer','')[:60]}{RESET}")
    return 0


def cmd_gen_pixel(html_file: str = "", port: int = 8080, host: str = "your.tld") -> int:
    tag = f'<img src="https://{host}:{port}/pixel.gif" width="1" height="1" alt="">'
    if html_file:
        p = Path(html_file)
        if p.exists():
            content = p.read_text()
            if "</body>" in content.lower():
                content = content.replace("</body>", tag + "\n</body>")
            else:
                content += "\n" + tag
            p.write_text(content)
            print_ok(f"injected pixel into {html_file}")
            return 0
    print_info(f"pixel tag:")
    print(f"  {BONE}{tag}{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky phish tracker <serve|dump|pixel> [--port N] [--host H] [--html FILE]")
        return 2

    sub = args[0]
    port = 8080
    host = "your.tld"
    html = ""

    i = 1
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2; continue
        if args[i] == "--host" and i + 1 < len(args):
            host = args[i + 1]; i += 2; continue
        if args[i] == "--html" and i + 1 < len(args):
            html = args[i + 1]; i += 2; continue
        i += 1

    if sub == "serve":
        return cmd_serve(port)
    if sub == "dump":
        return cmd_dump()
    if sub == "pixel":
        return cmd_gen_pixel(html, port, host)
    print_err(f"unknown tracker action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
