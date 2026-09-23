# language: Python, file: Program/wireless/scan.py, target: Red Sky wireless — interface + AP survey
# Enumerates wireless interfaces, reads driver/mode/channel via iw, then runs
# a passive scan (iw dev <iface> scan) and parses the results into a table.
# No monitor mode needed for the survey pass. Monitor mode is enabled on demand
# for the deauth / handshake modules.

import json
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


WL_DIR = OUTPUT_DIR / "wireless"
WL_DIR.mkdir(parents=True, exist_ok=True)


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(args: List[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def list_interfaces() -> List[Dict]:
    """Read /sys/class/net and pull wireless info for each."""
    out = []
    net = Path("/sys/class/net")
    if not net.exists():
        return out
    for iface in sorted(net.iterdir()):
        name = iface.name
        if not (iface / "wireless").exists():
            continue
        info = {"name": name, "mode": "", "channel": "", "driver": "", "mac": "", "state": ""}
        try:
            info["mac"] = (iface / "address").read_text().strip()
            info["state"] = (iface / "operstate").read_text().strip()
        except OSError:
            pass
        # driver symlink
        try:
            drv = (iface / "device" / "driver").resolve()
            info["driver"] = drv.name
        except OSError:
            pass
        # iw dev <name> info
        iw = _which("iw")
        if iw:
            txt = _run([iw, "dev", name, "info"], timeout=10)
            for line in txt.splitlines():
                line = line.strip()
                if line.startswith("type "):
                    info["mode"] = line.split()[1]
                elif line.startswith("channel "):
                    m = re.search(r"channel\s+(\d+)", line)
                    if m:
                        info["channel"] = m.group(1)
        out.append(info)
    return out


def parse_iw_scan(raw: str) -> List[Dict]:
    """Parse `iw dev <iface> scan` output into AP records."""
    aps = []
    cur = None
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("BSS "):
            if cur:
                aps.append(cur)
            mac = s.split()[1].split("(")[0]
            cur = {"bssid": mac, "ssid": "", "channel": "", "freq": "", "signal": "",
                   "security": "", "wpa": "", "wps": "", "country": "", "vendor": ""}
        elif cur is None:
            continue
        elif s.startswith("freq:"):
            cur["freq"] = s.split(":", 1)[1].strip()
        elif s.startswith("signal:"):
            m = re.search(r"(-?\d+\.?\d*)", s)
            if m:
                cur["signal"] = m.group(1)
        elif s.startswith("SSID:"):
            cur["ssid"] = s.split(":", 1)[1].strip()
        elif s.startswith("DS Parameter set: channel"):
            cur["channel"] = s.split("channel", 1)[1].strip()
        elif "* primary channel:" in s:
            cur["channel"] = s.split(":", 1)[1].strip()
        elif s.startswith("RSN:"):
            cur["security"] = "WPA2" if not cur["security"] else cur["security"]
        elif s.startswith("WPA:"):
            cur["security"] = "WPA"
        elif s.startswith("WPS:"):
            cur["wps"] = "yes"
        elif s.startswith("Country:"):
            cur["country"] = s.split(":", 1)[1].strip()
        elif s.startswith("Capability:") and "Privacy" in s:
            if not cur["security"]:
                cur["security"] = "WEP"
    if cur:
        aps.append(cur)
    # default hidden security
    for a in aps:
        if not a["security"]:
            a["security"] = "OPEN"
        if not a["ssid"]:
            a["ssid"] = "<hidden>"
    return aps


def scan_interface(iface: str) -> List[Dict]:
    iw = _which("iw")
    if not iw:
        print_err("iw not on PATH — install iw (apt install iw)")
        return []
    print_info("running iw dev " + iface + " scan (passive — takes ~10s)")
    raw = _run([iw, "dev", iface, "scan"], timeout=60)
    if not raw:
        print_warn("scan returned nothing — check the interface is up and you have permission")
        return []
    return parse_iw_scan(raw)


def cmd_list() -> int:
    ifaces = list_interfaces()
    if not ifaces:
        print_warn("no wireless interfaces found")
        print_info("check: ip link ; lspci | grep -i wireless ; lsusb")
        return 0

    print_info(str(len(ifaces)) + " wireless interface(s)")
    print()
    for i in ifaces:
        mark = SCARLET + "▓" + RESET if i["state"] == "up" else ASH + "░" + RESET
        print("  " + mark + " " + BONE + i["name"] + RESET + "  "
              + ASH + i["mac"] + RESET)
        print("      mode    " + ARTERY + (i["mode"] or "?") + RESET)
        print("      channel " + ARTERY + (i["channel"] or "?") + RESET)
        print("      driver  " + ARTERY + (i["driver"] or "?") + RESET)
        print("      state   " + ARTERY + (i["state"] or "?") + RESET)
    return 0


def cmd_scan(iface: str, out_file: str) -> int:
    if not iface:
        ifaces = list_interfaces()
        if not ifaces:
            print_err("no wireless interfaces — pass --iface or run `redsky wireless scan list`")
            return 2
        iface = ifaces[0]["name"]
        print_info("defaulting to interface: " + iface)

    aps = scan_interface(iface)
    if not aps:
        return 1

    print()
    print_info(str(len(aps)) + " AP(s) found")
    print()

    # sort by signal strength (descending)
    def _sig(a):
        try:
            return float(a["signal"])
        except (ValueError, TypeError):
            return -999
    aps.sort(key=_sig, reverse=True)

    # header
    print("  " + BONE + "SSID".ljust(28) + "BSSID".ljust(20)
          + "CH".ljust(4) + "SIG".ljust(6) + "SEC".ljust(8) + "WPS" + RESET)
    print("  " + ASH + "-" * 78 + RESET)
    for a in aps:
        ssid = a["ssid"][:27]
        sec = a["security"][:7]
        sig = a["signal"][:5]
        wps = SCARLET + "yes" + RESET if a["wps"] else ASH + "no" + RESET
        print("  " + BONE + ssid.ljust(28) + RESET
              + ARTERY + a["bssid"].ljust(20) + RESET
              + ASH + (a["channel"] or "?").ljust(4) + RESET
              + ASH + sig.ljust(6) + RESET
              + SCARLET + sec.ljust(8) + RESET
              + wps)

    out = Path(out_file) if out_file else WL_DIR / ("scan_" + iface + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"iface": iface, "aps": aps}, indent=2))
    print()
    print_kv("saved", out)

    # hint at the next step based on what was found
    targets = [a for a in aps if a["security"] in ("WPA", "WPA2")]
    if targets:
        print()
        print_info("next: pick a target and run handshake capture:")
        print_info("  redsky wireless handshake capture --iface " + iface + " --bssid " + targets[0]["bssid"] + " --channel " + (targets[0]["channel"] or "1"))
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky wireless scan", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="scan", choices=["scan", "list"])
    p.add_argument("--iface", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky wireless scan [--iface wlan0] [--out file.json]")
        print_err("       redsky wireless scan list")
        return 2

    if ns.help:
        print_info("redsky wireless scan                # default iface, passive AP survey")
        print_info("redsky wireless scan --iface wlan1  # pick an iface")
        print_info("redsky wireless scan list           # just list ifaces")
        return 0

    if ns.action == "list":
        return cmd_list()
    return cmd_scan(ns.iface, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
