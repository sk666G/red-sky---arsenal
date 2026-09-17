# language: Python, file: Program/usb/digispark.py, target: Red Sky usb — Digispark firmware builder
# Wraps arduino-cli to compile a DuckyScript .ino into Digispark/ATtiny85
# firmware, then micronucleus to flash it.

import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


USB_DIR = OUTPUT_DIR / "usb"


def _has_core() -> bool:
    if not shutil.which("arduino-cli"):
        return False
    try:
        r = subprocess.run(["arduino-cli", "core", "list"],
                           capture_output=True, text=True, timeout=15)
        return "digistump:avr" in r.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def cmd_tools() -> int:
    print_info("Digispark toolchain")
    print()
    for name, desc in (
        ("arduino-cli",  "compiles .ino"),
        ("micronucleus", "flashes .hex"),
        ("avrdude",      "fallback flasher"),
    ):
        p = shutil.which(name)
        mark = f"{OK}▓{RESET}" if p else f"{SCARLET}░{RESET}"
        status = p or f"missing ({desc})"
        print(f"  {mark} {BONE}{name:<16}{RESET} {ASH}{status}{RESET}")
    core = _has_core()
    mark = f"{OK}▓{RESET}" if core else f"{SCARLET}░{RESET}"
    status = "installed" if core else "run: redsky usb digispark install-core"
    print(f"  {mark} {BONE}{'digistump:avr':<16}{RESET} {ASH}{status}{RESET}")
    return 0


def cmd_install_core() -> int:
    if not shutil.which("arduino-cli"):
        print_err("arduino-cli not installed")
        print_info("  curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh")
        return 1
    print_info("adding Digistump board URL")
    subprocess.run(["arduino-cli", "config", "init", "--overwrite"], check=False)
    subprocess.run(["arduino-cli", "config", "add", "board_manager.additional_urls",
                    "http://digistump.com/package_digistump_index.json"], check=False)
    print_info("updating index")
    subprocess.run(["arduino-cli", "core", "update-index"], check=False)
    print_info("installing digistump:avr")
    r = subprocess.run(["arduino-cli", "core", "install", "digistump:avr"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print_err(f"install failed: {r.stderr[:400]}")
        return 1
    print_ok("digistump core installed")
    return 0


def _find_ino(path: str) -> Optional[Path]:
    p = Path(path)
    if p.is_file() and p.suffix == ".ino":
        return p
    if p.is_dir():
        inos = list(p.glob("*.ino"))
        if inos:
            return inos[0]
    return None


def cmd_build(ino_path: str, output_name: str = "") -> int:
    ino = _find_ino(ino_path)
    if not ino:
        print_err(f"no .ino found at {ino_path}")
        return 1
    if not shutil.which("arduino-cli"):
        print_err("arduino-cli missing")
        return 1
    if not _has_core():
        print_warn("digistump:avr not installed — run install-core first")
        return 1

    USB_DIR.mkdir(parents=True, exist_ok=True)
    out_dir = USB_DIR / "build"
    out_dir.mkdir(parents=True, exist_ok=True)

    print_info(f"compiling {ino.name}")
    cmd = ["arduino-cli", "compile",
           "--fqbn", "digistump:avr:digispark-tiny:clock=16mhz",
           "--output-dir", str(out_dir), str(ino)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print_err("compile failed")
        print(r.stderr[-2000:])
        return 1

    hex_file = out_dir / f"{ino.stem}.ino.hex"
    if not hex_file.exists():
        hexes = list(out_dir.glob("*.hex"))
        if not hexes:
            print_err("no .hex produced")
            return 1
        hex_file = hexes[0]

    final = USB_DIR / (output_name or f"{ino.stem}.hex")
    shutil.copy2(hex_file, final)
    print_ok(f"built {final} ({final.stat().st_size} bytes)")
    return 0


def cmd_flash(hex_path: str) -> int:
    h = Path(hex_path)
    if not h.exists():
        print_err(f"hex not found: {h}")
        return 1
    tool = shutil.which("micronucleus") or shutil.which("micronucleus.exe")
    if not tool:
        print_err("micronucleus missing")
        print_info("  sudo apt install micronucleus")
        return 1

    print_info(f"flashing {h.name} — plug the Digispark into USB now")
    print_info("waiting 10s for device...")
    time.sleep(10)
    try:
        r = subprocess.run([tool, "--run", str(h)],
                           capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print_err("flash timed out")
        return 1
    if r.returncode == 0:
        print_ok("flash complete")
        return 0
    print_err("flash failed")
    print(r.stderr[-1000:])
    return 1


def cmd_autobuild(script_path: str, flash: bool = False) -> int:
    from .duckyscript import cmd_parse
    print_info("compiling DuckyScript -> .ino")
    if cmd_parse(script_path, "digispark") != 0:
        return 1
    script_p = Path(script_path)
    ino = USB_DIR / f"{script_p.stem}_digispark.ino"
    if not ino.exists():
        print_err(f"expected {ino} after parse")
        return 1
    if cmd_build(str(ino)) != 0:
        return 1
    hex_file = USB_DIR / f"{ino.stem}.hex"
    if flash:
        return cmd_flash(str(hex_file))
    print()
    print_info(f"to flash: redsky usb digispark flash {hex_file}")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky usb digispark <tools|install-core|build|flash|autobuild> [args]")
        return 2
    sub = args[0].lower()
    if sub == "tools":
        return cmd_tools()
    if sub in ("install-core", "install"):
        return cmd_install_core()
    if sub == "build":
        if len(args) < 2:
            print_err("build needs an .ino or directory")
            return 2
        out = ""
        if "--out" in args:
            i = args.index("--out")
            if i + 1 < len(args):
                out = args[i + 1]
        return cmd_build(args[1], out)
    if sub == "flash":
        if len(args) < 2:
            print_err("flash needs a .hex")
            return 2
        return cmd_flash(args[1])
    if sub == "autobuild":
        if len(args) < 2:
            print_err("autobuild needs a DuckyScript file")
            return 2
        return cmd_autobuild(args[1], flash="--flash" in args)
    print_err(f"unknown digispark sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
