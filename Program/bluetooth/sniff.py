# language: Python, file: Program/bluetooth/sniff.py, target: Red Sky bluetooth — btmon live parser
# Runs btmon, parses the live HCI trace for advertising reports, scan requests,
# and L2CAP connection attempts. Prints what it sees, saves JSON.

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


BT_DIR = OUTPUT_DIR / "bluetooth"


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


ADV_RE = re.compile(r"Address:\s+([0-9A-F:]{17})\s+\(([^)]+)\)")
NAME_RE = re.compile(r"Name \(complete\):\s+(.+)")
NAME_SHORT_RE = re.compile(r"Name \(short\):\s+(.+)")
RSSI_RE = re.compile(r"RSSI:\s+(-?\d+)")
UUID_RE = re.compile(r"UUID:\s+([0-9a-fA-F-]{4,36})")
CONN_RE = re.compile(r"Connection:\s+handle (\d+), (.+)")


def cmd_sniff(duration: int = 30) -> int:
    if not _is_root():
        print_err("btmon needs root")
        return 1
    if not shutil.which("btmon"):
        print_err("btmon missing — install bluez")
        return 1

    BT_DIR.mkdir(parents=True, exist_ok=True)
    logfile = BT_DIR / f"btmon_{int(time.time())}.log"

    print_info(f"sniffing HCI trace for {duration}s")
    print_kv("log", logfile)
    print_info("CTRL+C to stop early")
    print()

    try:
        proc = subprocess.Popen(["btmon", "-w", str(logfile)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"btmon failed: {e}")
        return 1

    seen_devices: Dict[str, Dict] = {}
    adv_count = 0
    conn_count = 0

    t0 = time.time()
    try:
        for line in proc.stdout:
            line = line.rstrip()
            if time.time() - t0 > duration:
                break
            if not line:
                continue

            m = ADV_RE.search(line)
            if m:
                addr, addr_type = m.group(1), m.group(2)
                entry = seen_devices.setdefault(addr, {
                    "address": addr, "type": addr_type,
                    "name": "", "rssi": None, "uuids": [],
                })
                print(f"  {ARTERY}▓{RESET} ADV {BONE}{addr}{RESET} {ASH}({addr_type}){RESET}")
                adv_count += 1
                continue

            m = RSSI_RE.search(line)
            if m and seen_devices:
                last = list(seen_devices.values())[-1]
                last["rssi"] = int(m.group(1))
                continue

            m = NAME_RE.search(line) or NAME_SHORT_RE.search(line)
            if m and seen_devices:
                last = list(seen_devices.values())[-1]
                last["name"] = m.group(1).strip()
                continue

            m = UUID_RE.search(line)
            if m and seen_devices:
                last = list(seen_devices.values())[-1]
                u = m.group(1).lower()
                if u not in last["uuids"]:
                    last["uuids"].append(u)
                continue

            m = CONN_RE.search(line)
            if m:
                handle, status = m.group(1), m.group(2)
                conn_count += 1
                print(f"  {SCARLET}▓{RESET} CONN handle={handle} status={status[:40]}")

    except KeyboardInterrupt:
        print()
        print_info("stopped by user")
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    print_ok(f"adverts: {adv_count}, connections: {conn_count}")
    print_kv("devices seen", len(seen_devices))

    if seen_devices:
        print()
        for d in sorted(seen_devices.values(), key=lambda x: -(x.get("rssi") or -200)):
            rssi = f"{d['rssi']:>4}" if d["rssi"] is not None else "  ? "
            name = d.get("name") or "(unknown)"
            print(f"  {ARTERY}▓{RESET} {BONE}{d['address']}{RESET}  {SCARLET}{rssi}{RESET}  "
                  f"{BONE}{name[:32]:<32}{RESET} {ASH}{len(d['uuids'])} UUIDs{RESET}")

    out = BT_DIR / f"sniff_{int(time.time())}.json"
    out.write_text(json.dumps({
        "devices": list(seen_devices.values()),
        "adverts": adv_count,
        "connections": conn_count,
    }, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_parse(logpath: str) -> int:
    """Parse a previously captured btmon log."""
    p = Path(logpath)
    if not p.exists():
        print_err(f"log not found: {p}")
        return 1
    print_info(f"parsing {p.name}")
    devices: Dict[str, Dict] = {}
    adv = conn = 0
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = ADV_RE.search(line)
        if m:
            addr, atype = m.group(1), m.group(2)
            devices.setdefault(addr, {"address": addr, "type": atype,
                                      "name": "", "rssi": None, "uuids": []})
            adv += 1
            continue
        m = RSSI_RE.search(line)
        if m and devices:
            list(devices.values())[-1]["rssi"] = int(m.group(1))
            continue
        m = NAME_RE.search(line) or NAME_SHORT_RE.search(line)
        if m and devices:
            list(devices.values())[-1]["name"] = m.group(1).strip()
            continue
        m = UUID_RE.search(line)
        if m and devices:
            u = m.group(1).lower()
            if u not in list(devices.values())[-1]["uuids"]:
                list(devices.values())[-1]["uuids"].append(u)
            continue
        m = CONN_RE.search(line)
        if m:
            conn += 1

    print_ok(f"{len(devices)} device(s), {adv} adverts, {conn} connections")
    for d in devices.values():
        print(f"  {ARTERY}▓{RESET} {BONE}{d['address']}{RESET} {ASH}{d.get('name','')[:40]}{RESET}")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky bluetooth sniff [--duration N]")
        print_err("       redsky bluetooth parse <logfile>")
        return 2
    sub = args[0].lower()
    if sub == "parse":
        if len(args) < 2:
            print_err("parse needs a log path")
            return 2
        return cmd_parse(args[1])
    dur = 30
    if "--duration" in args:
        i = args.index("--duration")
        if i + 1 < len(args):
            dur = int(args[i + 1])
    return cmd_sniff(dur)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
