# language: Python, file: Program/interface.py, target: Red Sky menu
# Numbered menu that dispatches to the same modules as the CLI.

import sys
import traceback
from typing import List

from .theme import print_banner, print_smear, print_header
from .theme.palette import SCARLET, ARTERY, BONE, ASH, CLOT, BLOOD, RESET, BOLD
from .utils import load_config, print_ok, print_err, print_warn, print_info, print_kv
from .utils.paths import ensure_dirs


# (label, cli-command, admin_needed)
MENU = [
    ("Recon", [
        ("Scan network",          "recon",   False),
        ("Fingerprint a host",    "recon",   False),
        ("Subdomain enum",        "recon",   False),
        ("IP geolocation",        "geoip",   False),
        ("IP grabber",            "ipgrab",  False),
    ]),
    ("Web", [
        ("Fingerprint + CVE match", "web",   False),
        ("Deface a webroot",        "web",   False),
        ("CCTV discover",           "cctv",  False),
        ("CCTV default-creds sweep","cctv",  False),
        ("Open a CCTV stream",      "cctv",  False),
    ]),
    ("Credentials", [
        ("Harvest browser creds",   "creds", False),
        ("Password spray",          "creds", False),
        ("Kerberoast / ASREP",      "creds", False),
        ("DCSync",                  "creds", False),
        ("CSINT query",             "csint", False),
    ]),
    ("Payloads", [
        ("Build a beacon",          "payload", False),
        ("Build a dropper",         "payload", False),
        ("BadUSB builder",          "usb",   False),
        ("Shellcode generator",     "shellcode", False),
        ("AV/EDR bypass generator", "av_bypass", False),
    ]),
    ("Post-exploitation", [
        ("Persistence",             "payload", False),
        ("Privilege escalation",    "creds", False),
        ("Lateral movement",        "ad_attack", False),
        ("Container escape",        "container_escape", False),
        ("Anti-forensics",          "anti_forensics", False),
    ]),
    ("Wireless / Physical", [
        ("WiFi recon",              "wifi",      False),
        ("BLE scan",                "bluetooth", False),
        ("RFID read / clone",       "rfid",      False),
        ("Lock bypass guide",       "lock_bypass", False),
    ]),
    ("Cracking", [
        ("Classify a binary",       "crack",        False),
        ("Patch a check",           "crack",        False),
        ("Automated keygen",        "keygen_factory", False),
        ("Fuzzer",                  "fuzzer",       False),
    ]),
    ("Botnet", [
        ("Start C2 listener",       "c2",     False),
        ("Open operator panel",     "botnet", False),
        ("Build a beacon",          "botnet", False),
    ]),
    ("System", [
        ("Show config",             None,     False),
        ("List plugins",            None,     False),
        ("Show banner",             None,     False),
    ]),
]


def _flatten():
    flat = []
    idx = 1
    for section, items in MENU:
        for label, cmd, admin in items:
            flat.append((idx, section, label, cmd, admin))
            idx += 1
    return flat


def _draw():
    print_banner()
    print_smear(72, ARTERY)
    print(f"{BOLD}{SCARLET}  RED SKY // menu{RESET}")
    print_smear(72, ARTERY)

    current_section = None
    for idx, section, label, cmd, admin in _flatten():
        if section != current_section:
            current_section = section
            print(f"\n  {BOLD}{BLOOD}▌ {section}{RESET}")
        mark = f"{ARTERY}▓{RESET}" if cmd else f"{CLOT}░{RESET}"
        tag = f" {ASH}[{cmd}]{RESET}" if cmd else ""
        print(f"  {idx:>3}. {mark} {BONE}{label}{RESET}{tag}")

    print()
    print(f"  {ARTERY}  0.{RESET} {BONE}Exit{RESET}")
    print(f"  {ARTERY}  b.{RESET} {BONE}Back to banner{RESET}")
    print()


def _dispatch(command: str, extra: List[str]) -> int:
    from .cli import dispatch
    if not command:
        return 0
    return dispatch(command, extra)


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        v = input(f"{ARTERY}?{RESET} {BONE}{prompt}{RESET}{ASH}{suffix}{RESET}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return v or default


def _interactive_for(cmd: str) -> int:
    """Ask the operator for the pieces each module needs, then dispatch."""
    from .cli import dispatch

    args: List[str] = []

    if cmd == "recon":
        what = _ask("what (sweep / fingerprint / subs / osint)", "sweep")
        target = _ask("target (CIDR or host)")
        if what == "sweep":
            args = ["sweep", target]
        elif what == "fingerprint":
            args = ["fingerprint", target]
        elif what == "subs":
            args = ["subs", target]
        elif what == "osint":
            args = ["osint", target]
    elif cmd == "geoip":
        ip = _ask("ip")
        args = [ip]
    elif cmd == "ipgrab":
        port = _ask("port", "8080")
        decoy = _ask("decoy URL", "https://www.youtube.com/")
        args = [port, decoy]
    elif cmd == "web":
        what = _ask("what (triage / deface)", "triage")
        target = _ask("target URL")
        args = [what, target]
    elif cmd == "cctv":
        what = _ask("what (discover / creds / stream)", "discover")
        target = _ask("target CIDR or host")
        args = [what, target]
    elif cmd == "creds":
        what = _ask("what (browsers / spray / kerberoast / dcsync)", "browsers")
        args = [what]
    elif cmd == "csint":
        what = _ask("what (email / domain / password / doc)", "email")
        target = _ask("target")
        args = [what, target]
    elif cmd == "payload":
        what = _ask("what (beacon / dropper / persistence)", "beacon")
        args = [what]
    elif cmd == "usb":
        args = _ask("payload path").split()
    elif cmd == "shellcode":
        arch = _ask("arch (x64 / x86)", "x64")
        args = [arch]
    elif cmd == "av_bypass":
        what = _ask("what (crypter / packer / amsi)", "crypter")
        args = [what]
    elif cmd == "ad_attack":
        what = _ask("what (bloodhound / kerberoast / dcsync)", "bloodhound")
        args = [what]
    elif cmd == "container_escape":
        args = _ask("image or pid").split()
    elif cmd == "anti_forensics":
        args = [_ask("what (logs / prefetch / all)", "all")]
    elif cmd == "wifi":
        iface = _ask("interface", "wlan0")
        args = [iface]
    elif cmd == "bluetooth":
        args = [_ask("seconds", "30")]
    elif cmd == "rfid":
        args = [_ask("action (read / clone)", "read")]
    elif cmd == "lock_bypass":
        args = [_ask("lock type", "pin")]
    elif cmd == "crack":
        what = _ask("what (classify / patch / keygen)", "classify")
        path = _ask("binary path")
        args = [what, path]
    elif cmd == "keygen_factory":
        path = _ask("binary path")
        args = [path]
    elif cmd == "fuzzer":
        what = _ask("what (protocol / binary)", "binary")
        target = _ask("target path or host:port")
        args = [what, target]
    elif cmd == "c2":
        args = [_ask("bind port", "443")]
    elif cmd == "botnet":
        args = [_ask("action (panel / build)", "panel")]
    elif cmd == "ddos":
        target = _ask("authorized target URL")
        rps = _ask("rps (max 50)", "10")
        args = [target, rps]

    return dispatch(cmd, args)


def run_menu() -> int:
    ensure_dirs()
    while True:
        _draw()
        try:
            choice = input(f"{SCARLET}>{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice in ("0", "q", "quit", "exit"):
            print()
            print_info("the sky goes dark.")
            return 0

        if choice in ("b", "banner"):
            print_banner()
            continue

        if choice in ("", None):
            continue

        try:
            idx = int(choice)
        except ValueError:
            print_warn("type a number, not that")
            continue

        entry = next((e for e in _flatten() if e[0] == idx), None)
        if not entry:
            print_warn("no such option")
            continue

        _, _, label, cmd, _ = entry

        if cmd is None:
            if "config" in label.lower():
                from .cli import show_config
                show_config()
            elif "plugin" in label.lower():
                from Plugins.loader import get_manager
                get_manager().show()
            elif "banner" in label.lower():
                print_banner()
            continue

        print()
        print_header(label, 72)
        try:
            _interactive_for(cmd)
        except Exception:
            print_err("module raised:")
            traceback.print_exc()

        print()
        try:
            input(f"{ASH}enter to return to menu…{RESET}")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


if __name__ == "__main__":
    sys.exit(run_menu())
