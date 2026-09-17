# language: Python, file: Program/wifi/recon.py, target: Red Sky wifi — recon
# Interface detection, monitor mode toggling, and AP/client scan via airodump-ng.

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


NEEDS_ROOT = "monitor mode and airodump-ng need root"


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _run(cmd, timeout=60, check=False):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def list_interfaces():
    out = []
    if not shutil.which("iw"):
        return out
    try:
        r = _run(["iw", "dev"])
    except (subprocess.SubprocessError, FileNotFoundError):
        return out

    current = None
    for line in r.stdout.splitlines():
        s = line.strip()
        if s.startswith("Interface"):
            if current:
                out.append(current)
            current = {"name": s.split()[-1], "type": "", "channel": "", "phy": ""}
        elif current and s.startswith("type "):
            current["type"] = s.split()[-1]
        elif current and s.startswith("channel "):
            current["channel"] = s.split()[1]
    if current:
        out.append(current)
    return out


def cmd_interfaces():
    ifaces = list_interfaces()
    if not ifaces:
        print_warn("no wireless interfaces found")
        return 1
    print_info(f"{len(ifaces)} wireless interface(s)")
    print()
    for i in ifaces:
        mark = f"{OK}▓{RESET}" if i["type"] == "managed" else f"{ARTERY}▓{RESET}"
        print(f"  {mark} {BONE}{i['name']:<12}{RESET} "
              f"{ASH}type={i['type']:<10} ch={i['channel'] or '?':<4}{RESET}")
    return 0


def cmd_monitor(iface, stop=False):
    if not _is_root():
        print_err(NEEDS_ROOT)
        return 1
    if not shutil.which("iw"):
        print_err("iw missing")
        return 1

    mon = iface if iface.endswith("mon") else f"{iface}mon"

    if stop:
        print_info(f"stopping monitor on {mon}")
        _run(["ip", "link", "set", mon, "down"], timeout=10)
        _run(["iw", "dev", mon, "del"], timeout=10)
        print_ok(f"removed {mon}")
        return 0

    print_info(f"enabling monitor mode on {iface} -> {mon}")
    _run(["ip", "link", "set", iface, "down"], timeout=10)
    r = _run(["iw", "dev", iface, "interface", "add", mon, "type", "monitor"], timeout=15)
    if r.returncode != 0:
        print_err(f"iw add monitor failed: {r.stderr.strip()}")
        _run(["ip", "link", "set", iface, "up"], timeout=10)
        return 1
    _run(["ip", "link", "set", mon, "up"], timeout=10)
    _run(["ip", "link", "set", iface, "up"], timeout=10)
    print_ok(f"{mon} is up in monitor mode")
    print_info(f"when done: redsky wifi recon monitor {mon} --stop")
    return 0


def _parse_csv(path):
    aps, clients = [], []
    section = "ap"
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return aps, clients
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("BSSID"):
            section = "ap"
            continue
        if line.startswith("Station MAC"):
            section = "client"
            continue
        parts = [p.strip() for p in line.split(",")]
        if section == "ap" and len(parts) >= 14:
            try:
                power = int(parts[8]) if parts[8].lstrip("-").isdigit() else None
            except ValueError:
                power = None
            aps.append({
                "bssid": parts[0],
                "channel": parts[3],
                "privacy": parts[5],
                "cipher": parts[6],
                "auth": parts[7],
                "power": power,
                "beacons": parts[9],
                "essid": parts[13].rstrip(),
            })
        elif section == "client" and len(parts) >= 6:
            clients.append({
                "bssid": parts[0],
                "power": parts[3],
                "ap": parts[5] if parts[5] != "(not associated)" else "",
                "probed": parts[6] if len(parts) > 6 else "",
            })
    return aps, clients


def cmd_scan(iface, duration=30):
    if not _is_root():
        print_err(NEEDS_ROOT)
        return 1
    if not shutil.which("airodump-ng"):
        print_err("airodump-ng missing")
        return 1

    outdir = OUTPUT_DIR / "wifi"
    outdir.mkdir(parents=True, exist_ok=True)
    prefix = outdir / f"scan_{iface}_{int(time.time())}"

    print_info(f"scanning on {iface} for {duration}s")
    print_kv("prefix", prefix)

    cmd = ["airodump-ng", "--write", str(prefix), "--output-format", "csv",
           "--band", "abg", iface]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"airodump-ng launch failed: {e}")
        return 1

    for i in range(duration):
        time.sleep(1)
        if (i + 1) % 5 == 0:
            print(f"  {ARTERY}▓{RESET} scanning... {i + 1}s")

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    csv_path = Path(str(prefix) + "-01.csv")
    if not csv_path.exists():
        print_err("no scan output produced")
        return 1

    aps, clients = _parse_csv(csv_path)
    print()
    print_ok(f"{len(aps)} AP(s), {len(clients)} client(s)")
    print()
    print(f"{ARTERY}{BOLD}  access points{RESET}")
    for a in sorted(aps, key=lambda x: -(x.get("power") or -100)):
        enc = a.get("privacy", "")[:8]
        print(f"  {ARTERY}▓{RESET} {BONE}{a['bssid']}{RESET} "
              f"{SCARLET}ch {a.get('channel','?'):<3}{RESET} "
              f"{ASH}pwr {a.get('power','?'):<5} {enc:<8}{RESET} "
              f"{BONE}{a.get('essid', '')[:40]}{RESET}")
    print()
    print(f"{ARTERY}{BOLD}  clients{RESET}")
    for c in clients[:40]:
        print(f"  {ARTERY}▓{RESET} {BONE}{c['bssid']}{RESET}  "
              f"{ASH}-> {c.get('ap','') or '(not associated)':<20} "
              f"{c.get('probed','')[:40]}{RESET}")

    out_json = outdir / f"scan_{iface}_{int(time.time())}.json"
    out_json.write_text(json.dumps({"aps": aps, "clients": clients}, indent=2))
    print()
    print_kv("saved", out_json)
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky wifi recon <interfaces|monitor|scan> [iface] [--stop] [--duration N]")
        return 2
    sub = args[0].lower()
    if sub in ("interfaces", "list"):
        return cmd_interfaces()
    if sub == "monitor":
        if len(args) < 2:
            print_err("monitor needs an interface name")
            return 2
        return cmd_monitor(args[1], stop="--stop" in args)
    if sub == "scan":
        if len(args) < 2:
            print_err("scan needs an interface name (usually wlan0mon)")
            return 2
        dur = 30
        if "--duration" in args:
            i = args.index("--duration")
            if i + 1 < len(args):
                dur = int(args[i + 1])
        return cmd_scan(args[1], dur)
    print_err(f"unknown recon sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
