# language: Python, file: Program/rfid/proxmark.py, target: Red Sky rfid — Proxmark3 integration
# Wraps the pm3 client. Drives a Proxmark3 over USB: read, sniff, emulate, clone.

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


RFID_DIR = OUTPUT_DIR / "rfid"


# pm3 commands that mean "we're on the device"
PM3_INFO = "hw version"
PM3_STATUS = "hw status"


def _pm3_bin() -> Optional[str]:
    for cand in ("pm3", "proxmark3"):
        p = shutil.which(cand)
        if p:
            return p
    return None


def _run_pm3(script: str, timeout: int = 30) -> Dict:
    """Feed a script of pm3 commands on stdin. Returns {stdout, stderr, rc}."""
    pm3 = _pm3_bin()
    if not pm3:
        return {"stdout": "", "stderr": "pm3 not installed", "rc": -1}

    # pm3 accepts commands via stdin when launched without an interactive tty
    try:
        proc = subprocess.run(
            [pm3],
            input=script + "\nexit\n",
            capture_output=True, text=True, timeout=timeout,
        )
        return {"stdout": proc.stdout, "stderr": proc.stderr, "rc": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "rc": -2}
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        return {"stdout": "", "stderr": str(e), "rc": -1}


def cmd_check() -> int:
    pm3 = _pm3_bin()
    if not pm3:
        print_err("pm3 / proxmark3 not installed")
        print_info("install from https://github.com/RfidResearchGroup/proxmark3")
        print_info("or: sudo apt install proxmark3")
        return 1
    print_ok(f"pm3 client at {pm3}")
    r = _run_pm3(PM3_INFO, timeout=15)
    for line in r["stdout"].splitlines():
        if line.strip():
            print(f"  {ASH}{line.strip()}{RESET}")
    if r["rc"] != 0:
        print_warn("device may not be connected")
        print_info(r["stderr"][:200])
    return 0


def cmd_read(timeout: int = 60, output: str = "") -> int:
    """lf search + hf search — detect and read any card present."""
    pm3 = _pm3_bin()
    if not pm3:
        print_err("pm3 not installed")
        return 1

    RFID_DIR.mkdir(parents=True, exist_ok=True)
    print_info("hf + lf search on Proxmark3")
    print_info("place a card on the antenna")
    print()

    script = "\n".join([
        "hf search",
        "lf search",
    ])

    try:
        proc = subprocess.Popen([pm3], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"pm3 launch failed: {e}")
        return 1

    lines_out = []
    def feed():
        for cmd in (script + "\nexit\n").splitlines(keepends=True):
            proc.stdin.write(cmd)
            proc.stdin.flush()
            time.sleep(0.3)
    import threading
    threading.Thread(target=feed, daemon=True).start()

    t0 = time.time()
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        lines_out.append(line)
        print(f"  {ASH}{line[:140]}{RESET}")
        if time.time() - t0 > timeout:
            break
    proc.terminate()

    if output or lines_out:
        out = Path(output) if output else RFID_DIR / f"pm3_read_{int(time.time())}.txt"
        out.write_text("\n".join(lines_out))
        print()
        print_kv("saved", out)
    return 0


def cmd_sniff(duration: int = 30) -> int:
    """Sniff 14a traffic between a card and a reader."""
    pm3 = _pm3_bin()
    if not pm3:
        print_err("pm3 not installed")
        return 1

    print_info(f"sniffing ISO14443-A traffic for {duration}s")
    print_info("hold the Proxmark3 near a live reader/card exchange")
    print()

    cmd = [pm3, "-c", "hf 14a sniff"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"pm3 sniff failed: {e}")
        return 1

    t0 = time.time()
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        print(f"  {ASH}{line[:140]}{RESET}")
        if time.time() - t0 > duration:
            break
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    print()
    print_info("to decode the trace: pm3 -c 'hf 14a list' after a sniff run")
    return 0


def cmd_clone(source_dump: str) -> int:
    """Write a dump back to a magic card."""
    pm3 = _pm3_bin()
    if not pm3:
        print_err("pm3 not installed")
        return 1
    p = Path(source_dump)
    if not p.exists():
        print_err(f"dump not found: {p}")
        return 1

    print_info(f"restoring {p.name} to card")
    print_warn("card must be a 'magic' Mifare Classic (UID writable) for a full clone")
    print()

    script = "\n".join([
        f"hf mf cload {p}",
        "hf mf info",
    ])
    r = _run_pm3(script, timeout=120)
    for line in (r["stdout"] + r["stderr"]).splitlines():
        if line.strip():
            print(f"  {ASH}{line[:140]}{RESET}")
    if r["rc"] == 0:
        print_ok("write complete")
        return 0
    print_err("write reported errors — check the output above")
    return 1


def cmd_emulate(uid_hex: str) -> int:
    """Emulate a card with a specific UID."""
    pm3 = _pm3_bin()
    if not pm3:
        print_err("pm3 not installed")
        return 1
    try:
        uid = bytes.fromhex(uid_hex.replace(":", "").replace(" ", ""))
    except ValueError:
        print_err("UID must be hex")
        return 1
    if len(uid) != 4:
        print_warn("most readers accept 4-byte UIDs only")

    print_info(f"emulating UID {uid.hex().upper()}")
    print_info("CTRL+C to stop")
    script = f"hf mf sim u {uid.hex()} 000000000000"
    try:
        proc = subprocess.Popen([pm3, "-c", script], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                print(f"  {ASH}{line[:140]}{RESET}")
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    except Exception as e:
        print_err(f"emulate failed: {e}")
        return 1
    return 0


def cmd_dump(output: str = "") -> int:
    """Full dump of a Mifare Classic using the Proxmark autopwn path."""
    pm3 = _pm3_bin()
    if not pm3:
        print_err("pm3 not installed")
        return 1

    RFID_DIR.mkdir(parents=True, exist_ok=True)
    prefix = Path(output) if output else RFID_DIR / f"pm3_mf_{int(time.time())}"

    print_info("running hf mf autopwn")
    print_info("this uses the Proxmark's own dictionary + nested attack")
    print()

    r = _run_pm3(f"hf mf autopwn -f {prefix}", timeout=900)
    for line in (r["stdout"] + r["stderr"]).splitlines():
        if line.strip():
            print(f"  {ASH}{line[:140]}{RESET}")

    dump_file = Path(str(prefix) + ".bin")
    if dump_file.exists():
        print()
        print_ok(f"dump: {dump_file} ({dump_file.stat().st_size} bytes)")
        return 0
    print_warn("no dump produced")
    return 1


def run_cli(args):
    if not args:
        print_err("usage: redsky rfid pm3 <check|read|sniff|dump|clone|emulate> [args]")
        return 2
    sub = args[0].lower()
    if sub == "check":
        return cmd_check()
    if sub == "read":
        dur = 60
        if "--timeout" in args:
            i = args.index("--timeout")
            if i + 1 < len(args):
                dur = int(args[i + 1])
        return cmd_read(dur)
    if sub == "sniff":
        dur = 30
        if "--duration" in args:
            i = args.index("--duration")
            if i + 1 < len(args):
                dur = int(args[i + 1])
        return cmd_sniff(dur)
    if sub == "dump":
        out = ""
        if "--out" in args:
            i = args.index("--out")
            if i + 1 < len(args):
                out = args[i + 1]
        return cmd_dump(out)
    if sub == "clone":
        if len(args) < 2:
            print_err("clone needs a dump file")
            return 2
        return cmd_clone(args[1])
    if sub == "emulate":
        if len(args) < 2:
            print_err("emulate needs a UID")
            return 2
        return cmd_emulate(args[1])
    print_err(f"unknown pm3 sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
