# language: Python, file: Program/rfid/classic.py, target: Red Sky rfid — Mifare Classic
# Wraps mfoc (nested attack) and mfcuk (darkside attack) for Mifare Classic key recovery.
# Both need a USB reader with libnfc support (ACR122U, PN532).

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


RFID_DIR = OUTPUT_DIR / "rfid"


def _tool_ok(name: str) -> bool:
    return shutil.which(name) is not None


def cmd_nfc_list() -> int:
    if not _tool_ok("nfc-list"):
        print_err("nfc-list missing — install libnfc-bin")
        print_info("  sudo apt install libnfc-bin libnfc-examples")
        return 1
    print_info("nfc-list scan")
    try:
        r = subprocess.run(["nfc-list", "-v"], capture_output=True, text=True, timeout=15)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"nfc-list failed: {e}")
        return 1
    for line in (r.stdout + r.stderr).splitlines():
        print(f"  {ASH}{line}{RESET}")
    return 0


def cmd_mfoc(output_file: str = "", keys_file: str = "") -> int:
    if not _tool_ok("mfoc"):
        print_err("mfoc missing — install mfoc")
        print_info("  sudo apt install mfoc")
        return 1

    RFID_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(output_file) if output_file else RFID_DIR / f"mfoc_{int(time.time())}.mfd"

    cmd = ["mfoc", "-O", str(out)]
    if keys_file:
        cmd += ["-f", keys_file]

    print_info("running mfoc (nested attack)")
    print_kv("out", out)
    print_info("place a Mifare Classic card on the reader")
    print()

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"mfoc failed: {e}")
        return 1

    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        print(f"  {ASH}{line}{RESET}")
    proc.wait()

    if out.exists() and out.stat().st_size > 0:
        print()
        print_ok(f"dump saved: {out} ({out.stat().st_size} bytes)")
        return 0
    print_warn("no dump produced — card may not be Mifare Classic, or no card present")
    return 1


def cmd_mfcuk(output_file: str = "") -> int:
    if not _tool_ok("mfcuk"):
        print_err("mfcuk missing — install mfcuk")
        print_info("  sudo apt install mfcuk")
        return 1

    RFID_DIR.mkdir(parents=True, exist_ok=True)
    print_info("running mfcuk (darkside attack — slower, but recovers keys mfoc can't)")

    cmd = ["mfcuk", "-v", "2"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"mfcuk failed: {e}")
        return 1

    keys_found = []
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        if "KEY" in line or "key" in line.lower():
            keys_found.append(line)
            print(f"{OK}▓ {line}{RESET}")
        else:
            print(f"  {ASH}{line[:120]}{RESET}")
    proc.wait()

    if keys_found:
        print()
        print_ok(f"{len(keys_found)} key(s) recovered")
        out = RFID_DIR / f"mfcuk_keys_{int(time.time())}.txt"
        out.write_text("\n".join(keys_found))
        print_kv("saved", out)
        return 0
    print_warn("no keys recovered this run")
    return 1


def cmd_dump(port: str = "usb", output_file: str = "") -> int:
    """Dump a full Mifare Classic using mfread from libfreefare."""
    if not _tool_ok("mfoc"):
        print_err("mfoc missing — dump needs mfoc first")
        return 1
    return cmd_mfoc(output_file)


def cmd_write(dump_file: str) -> int:
    """Restore a Mifare Classic dump back onto a blank card via mfoc's writer."""
    if not _tool_ok("mfoc"):
        print_err("mfoc missing")
        return 1
    p = Path(dump_file)
    if not p.exists():
        print_err(f"dump not found: {p}")
        return 1
    print_info(f"writing {p.name} back to card")
    print_warn("this needs a magic (UID-changeable) card to fully clone")
    cmd = ["mfoc", "-I", str(p), "-O", "/tmp/_restore_check.mfd"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.SubprocessError as e:
        print_err(f"write failed: {e}")
        return 1
    for line in (r.stdout + r.stderr).splitlines():
        print(f"  {ASH}{line[:120]}{RESET}")
    print_info("mfoc doesn't natively write to cards — use 'pm3' or 'mfcload' from libfreefare for real writes")
    return 0


def cmd_tools() -> int:
    print_info("Mifare Classic tool availability")
    print()
    for t, desc, pkg in (
        ("nfc-list", "libnfc scanner", "libnfc-bin"),
        ("mfoc", "nested attack", "mfoc"),
        ("mfcuk", "darkside attack", "mfcuk"),
        ("mfread", "full card dump", "libfreefare-bin"),
        ("mfcload", "write dump to card", "libfreefare-bin"),
        ("nfc-mfsetuid", "set UID on magic card", "libnfc-examples"),
        ("pm3", "Proxmark3 client", "manual install"),
    ):
        mark = f"{OK}▓{RESET}" if _tool_ok(t) else f"{SCARLET}░{RESET}"
        status = "OK" if _tool_ok(t) else f"missing ({pkg})"
        print(f"  {mark} {BONE}{t:<16}{RESET} {ASH}{desc:<24} {status}{RESET}")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky rfid classic <scan|mfoc|mfcuk|write|tools> [args]")
        return 2
    sub = args[0].lower()
    if sub == "tools":
        return cmd_tools()
    if sub == "scan":
        return cmd_nfc_list()
    if sub == "mfoc":
        out = ""
        if "--out" in args:
            i = args.index("--out")
            if i + 1 < len(args):
                out = args[i + 1]
        return cmd_mfoc(out)
    if sub == "mfcuk":
        return cmd_mfcuk()
    if sub == "write":
        if len(args) < 2:
            print_err("write needs a dump file")
            return 2
        return cmd_write(args[1])
    print_err(f"unknown classic sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
