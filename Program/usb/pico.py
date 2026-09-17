# language: Python, file: Program/usb/pico.py, target: Red Sky usb — Pi Pico firmware helper
# Prepares a CircuitPython firmware for RP2040 boards (Pico, Pico W, RP2040-Zero).
# Copies the compiled payload to the mounted CIRCUITPY drive.

import os
import shutil
import sys
import time
from pathlib import Path
from typing import Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


USB_DIR = OUTPUT_DIR / "usb"


def _find_circuitpy() -> Optional[Path]:
    """Look for a mounted CIRCUITPY drive."""
    candidates = [
        Path("/media") / os.environ.get("USER", "user") / "CIRCUITPY",
        Path("/mnt") / "CIRCUITPY",
        Path("/run/media") / os.environ.get("USER", "user") / "CIRCUITPY",
        Path("/Volumes") / "CIRCUITPY",  # macOS
    ]
    for c in candidates:
        if c.exists() and (c / "boot_out.txt").exists():
            return c
        if c.exists():
            return c
    return None


def cmd_tools() -> int:
    print_info("Pico toolchain")
    print()
    for name, desc in (
        ("python3", "runs the payload"),
        ("rshell",  "alternative file transfer"),
        ("picotool", "firmware flashing"),
    ):
        p = shutil.which(name)
        mark = f"{OK}▓{RESET}" if p else f"{SCARLET}░{RESET}"
        print(f"  {mark} {BONE}{name:<12}{RESET} {ASH}{p or 'missing (' + desc + ')'}{RESET}")

    cp = _find_circuitpy()
    mark = f"{OK}▓{RESET}" if cp else f"{SCARLET}░{RESET}"
    print(f"  {mark} {BONE}{'CIRCUITPY':<12}{RESET} {ASH}{cp or 'not mounted'}{RESET}")
    return 0


def cmd_install(code_py: str) -> int:
    """Copy a CircuitPython payload to the mounted CIRCUITPY drive as code.py."""
    src = Path(code_py)
    if not src.exists():
        print_err(f"payload not found: {src}")
        return 1

    cp = _find_circuitpy()
    if not cp:
        print_err("CIRCUITPY drive not found")
        print_info("plug the Pico in with CircuitPython firmware installed")
        print_info("first-time setup: https://circuitpython.org/board/raspberry_pi_pico/")
        return 1

    # ensure libraries are present
    lib_dir = cp / "lib"
    lib_dir.mkdir(exist_ok=True)
    needed = ["adafruit_hid"]
    missing = [n for n in needed if not (lib_dir / n).exists()]
    if missing:
        print_warn(f"missing libraries on CIRCUITPY: {', '.join(missing)}")
        print_info("download from https://circuitpython.org/libraries")
        print_info(f"and place adafruit_hid/ in {lib_dir}")

    dst = cp / "code.py"
    print_info(f"installing payload to {dst}")
    try:
        shutil.copy2(src, dst)
    except OSError as e:
        print_err(f"copy failed: {e}")
        return 1
    # sync
    try:
        os.sync()
    except (AttributeError, OSError):
        pass
    time.sleep(0.5)
    print_ok(f"installed — the Pico will restart and run {src.name}")
    return 0


def cmd_autobuild(script_path: str) -> int:
    """DuckyScript -> CircuitPython -> install to CIRCUITPY."""
    from .duckyscript import cmd_parse
    print_info("compiling DuckyScript -> CircuitPython")
    if cmd_parse(script_path, "pico") != 0:
        return 1
    sp = Path(script_path)
    py = USB_DIR / f"{sp.stem}_pico.py"
    if not py.exists():
        print_err(f"expected {py} after parse")
        return 1
    return cmd_install(str(py))


def run_cli(args):
    if not args:
        print_err("usage: redsky usb pico <tools|install|autobuild> [args]")
        return 2
    sub = args[0].lower()
    if sub == "tools":
        return cmd_tools()
    if sub == "install":
        if len(args) < 2:
            print_err("install needs a .py file")
            return 2
        return cmd_install(args[1])
    if sub == "autobuild":
        if len(args) < 2:
            print_err("autobuild needs a DuckyScript file")
            return 2
        return cmd_autobuild(args[1])
    print_err(f"unknown pico sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
