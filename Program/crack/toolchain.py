# language: Python, file: Program/crack/toolchain.py, target: Red Sky crack — toolchain
# Orchestrate external reversing tools — radare2, ghidra, frida, x64dbg.

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


TOOLS = {
    "r2":          ("radare2",         "static + dynamic analysis"),
    "radare2":     ("radare2",         "static + dynamic analysis"),
    "r2pipe":      ("r2pipe",          "radare2 scripting"),
    "rabin2":      ("rabin2",          "binary inspection"),
    "objdump":     ("objdump",         "disassembly"),
    "strings":     ("strings",         "string extraction"),
    "xxd":         ("xxd",             "hex dump"),
    "file":        ("file",            "file type"),
    "frida":       ("frida",           "dynamic instrumentation"),
    "frida-trace": ("frida-trace",     "frida trace helper"),
    "gdb":         ("gdb",             "debugger"),
    "analyzeHeadless": ("analyzeHeadless", "ghidra headless"),
    "diec":        ("diec",            "Detect-It-Easy"),
    "x64dbg":      ("x64dbg",          "Windows debugger"),
    "windbg":      ("windbg",          "Windows debugger"),
    "upx":         ("upx",             "packer / unpacker"),
}


def cmd_check() -> int:
    print_info("crack toolchain check")
    print()
    available = 0
    for cmd, (name, desc) in TOOLS.items():
        path = shutil.which(cmd)
        if path:
            available += 1
            print(f"  {OK}▓{RESET} {BONE}{cmd:<20}{RESET} {ASH}{desc}{RESET}")
            print(f"      {CLOT}{path}{RESET}")
        else:
            print(f"  {SCARLET}░{RESET} {BONE}{cmd:<20}{RESET} {CLOT}missing{RESET}  {ASH}{desc}{RESET}")
    print()
    print_kv("available", f"{available}/{len(TOOLS)}")
    return 0


def cmd_strings(binary: str, min_len: int = 6, filter_kw: str = "") -> int:
    if not shutil.which("strings"):
        print_err("strings utility not installed — sudo apt install binutils")
        return 1
    cmd = ["strings", "-n", str(min_len), binary]
    r = subprocess.run(cmd, capture_output=True, text=True)
    lines = r.stdout.splitlines()

    if filter_kw:
        kws = [k.strip().lower() for k in filter_kw.split(",")]
        lines = [l for l in lines if any(k in l.lower() for k in kws)]

    for l in lines[:200]:
        print(f"  {BONE}{l}{RESET}")

    out = OUTPUT_DIR / "crack" / f"strings_{Path(binary).name}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    print()
    print_kv("total", len(lines))
    print_kv("saved", out)
    return 0


def cmd_rabin2(binary: str) -> int:
    if not shutil.which("rabin2"):
        print_err("rabin2 not found")
        return 1
    print_info("rabin2 sections")
    r = subprocess.run(["rabin2", "-S", binary], capture_output=True, text=True)
    print(r.stdout)
    print_info("rabin2 imports (interesting only)")
    r = subprocess.run(["rabin2", "-i", binary], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if any(k in line.lower() for k in ("crypt", "reg", "http", "winhttp", "time", "proc")):
            print(f"  {ASH}{line}{RESET}")
    print_info("rabin2 entry")
    r = subprocess.run(["rabin2", "-e", binary], capture_output=True, text=True)
    print(r.stdout)
    return 0


def cmd_r2_analyze(binary: str, cmd_string: str = "aaa; afl~0x") -> int:
    if not shutil.which("r2"):
        print_err("r2 not found")
        return 1
    print_info(f"r2 analysis: {cmd_string}")
    try:
        r = subprocess.run(["r2", "-q", "-c", cmd_string, binary],
                          capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print_err("r2 timed out")
        return 1
    print(r.stdout[:4000])
    if r.stderr:
        print(f"{CLOT}{r.stderr[:500]}{RESET}")
    return 0


def cmd_frida_trace(binary: str, module: str = "", function: str = "") -> int:
    if not shutil.which("frida-trace") and not shutil.which("frida"):
        print_err("frida not installed — pip install frida frida-tools")
        return 1

    cmd = ["frida-trace", "-f", binary]
    if module and function:
        cmd += ["-i", f"{module}!{function}"]
    elif module:
        cmd += ["-I", module]
    elif function:
        cmd += ["-i", function]

    print_info(f"tracing with frida: {' '.join(cmd)}")
    print_warn("CTRL+C to stop")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    return 0


def cmd_ghidra(binary: str, project_dir: str = "") -> int:
    if not shutil.which("analyzeHeadless"):
        print_err("ghidra not found (install: sudo apt install ghidra, or download from ghidra-sre.org)")
        return 1
    project = Path(project_dir) if project_dir else OUTPUT_DIR / "ghidra"
    project.mkdir(parents=True, exist_ok=True)
    cmd = [
        "analyzeHeadless", str(project), "redsky",
        "-import", binary,
        "-postScript", "ExportToJSON.java",
        "-deleteProject",
    ]
    print_info(f"ghidra headless: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, timeout=600)
    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        print_err(f"ghidra failed: {e}")
        return 1
    return 0


def run_cli(args: List[str]) -> int:
    if not args or args[0] == "check":
        return cmd_check()

    sub = args[0]
    if sub == "strings":
        if len(args) < 2:
            print_err("strings needs a binary")
            return 2
        min_len = 6
        filter_kw = ""
        i = 2
        while i < len(args):
            if args[i] == "--min" and i + 1 < len(args):
                min_len = int(args[i + 1]); i += 2; continue
            if args[i] == "--filter" and i + 1 < len(args):
                filter_kw = args[i + 1]; i += 2; continue
            i += 1
        return cmd_strings(args[1], min_len, filter_kw)

    if sub == "rabin2":
        if len(args) < 2: print_err("rabin2 needs a binary"); return 2
        return cmd_rabin2(args[1])

    if sub == "r2":
        if len(args) < 2: print_err("r2 needs a binary"); return 2
        cmd_str = args[2] if len(args) > 2 else "aaa; afl~0x"
        return cmd_r2_analyze(args[1], cmd_str)

    if sub == "frida":
        if len(args) < 2: print_err("frida needs a binary"); return 2
        module = args[2] if len(args) > 2 else ""
        function = args[3] if len(args) > 3 else ""
        return cmd_frida_trace(args[1], module, function)

    if sub == "ghidra":
        if len(args) < 2: print_err("ghidra needs a binary"); return 2
        proj = args[2] if len(args) > 2 else ""
        return cmd_ghidra(args[1], proj)

    print_err(f"unknown toolchain action: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
