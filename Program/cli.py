# language: Python, file: Program/cli.py, target: Red Sky CLI dispatcher
# Parses argv, routes to the right module or plugin. Every module is
# imported lazily so a broken module doesn't break the whole CLI.

import argparse
import sys
import traceback
from typing import List, Optional

from .theme import print_banner, print_smear, print_header
from .theme.palette import SCARLET, ARTERY, BONE, ASH, CLOT, BLOOD, RESET, BOLD
from .utils import load_config, get_logger, print_ok, print_err, print_warn, print_info, print_kv
from .utils.paths import ensure_dirs

log = get_logger("cli")


# ─────────────────────────────────────────────────────────────
# module registry — name -> (import path, callable name, help)
# ─────────────────────────────────────────────────────────────
MODULES = {
    # recon / network
    "ipgrab":        ("Program.ipgrab.dispatch", "run_cli", "IP logger + geo + webhook"),
    "cctv":          ("Program.cctv.dispatch",   "run_cli", "CCTV discover / creds / stream / kill"),
    "web":           ("Program.web.dispatch",    "run_cli", "web fingerprint + CVE match + deface"),
    "recon":         ("Program.recon.dispatch",  "run_cli", "host sweep + fingerprint + subs + osint"),
    "geoip":         ("Program.geoip.dispatch",    "run_cli", "multi-source IP geolocation"),

    # offensive
    "phish":         ("Program.phish.dispatch",  "run_cli", "phishing campaign framework"),
    "creds":         ("Program.creds.dispatch",  "run_cli", "credential operations"),
    "payload":       ("Program.payload.dispatch","run_cli", "payload builder"),
    "evade":         ("Program.evade.dispatch",  "run_cli", "AMSI/ETW/unhook helpers"),
    "crack":         ("Program.crack.dispatch",  "run_cli", "application cracking pipeline"),
    "botnet":        ("Program.botnet.dispatch", "run_cli", "botnet operator console"),
    "c2":            ("Program.c2.dispatch",     "run_cli", "C2 listener"),
    "csint":         ("Program.csint.dispatch","run_cli","closed-source intelligence"),
    "wifi":          ("Program.wifi.dispatch",      "run_cli", "WiFi recon + handshake capture"),
    "bluetooth":     ("Program.bluetooth.dispatch",  "run_cli", "BLE scan + service dump"),
    "rfid":          ("Program.rfid.dispatch",     "run_cli", "NFC / Mifare / HID read+clone"),
    "usb":           ("Program.usb.dispatch",      "run_cli", "BadUSB / Rubber Ducky builder"),
    "social":        ("Program.social.dispatch",  "run_cli", "OSINT person profile"),
    "evasion":       ("Program.evasion.dispatch","run_cli","AV/EDR evasion kit"),
    "crypto_malware":("Program.crypto_malware.dispatch","run_cli","ransomware kit"),
    "dns":           ("Program.dns.dispatch","run_cli","DNS attack kit"),
    "tor":           ("Program.tor.dispatch","run_cli","Tor attack kit"),
    "ics":           ("Program.ics.dispatch","run_cli","ICS/SCADA attack kit"),
    "macro":         ("Program.macro.dispatch","run_cli","Office macro kit"),
    "browser":       ("Program.browser.dispatch","run_cli","browser attack kit"),
    "drone":         ("Program.drone.dispatch","run_cli","MAVLink drone recon + cmd injection"),
    "wireless_jam":  ("Program.wireless_jam.dispatch","run_cli","802.11 interference"),
    "lock_bypass":   ("Program.lock_bypass.dispatch","run_cli","interactive lock worksheet"),
    "keygen_factory":("Program.keygen_factory.dispatch","run_cli","license analysis + keygen"),
    "fuzzer":       ("Program.fuzzer.dispatch","run_cli","mutation fuzzer + wrappers"),
    "av_bypass":     ("Program.av_bypass.dispatch","run_cli","on-target AV/EDR detection"),
    "shellcode":     ("Program.shellcode.dispatch","run_cli","shellcode plumbing + stubs"),
    "fiber_tap":     ("Program.fiber_tap.dispatch","run_cli","SPAN/TAP capture + pcap analysis"),
    "anti_forensics":("Program.anti_forensics.dispatch","run_cli","log/artifact cleanup + timestomp"),
    "memory_forensics":("Program.memory_forensics.dispatch","run_cli","live memory / process forensics"),
    "vm_detect":     ("Program.vm_detect.dispatch","run_cli","remote VM fingerprint"),
    "report":        ("Program.report.dispatch","run_cli","report kit"),
    "cron":          ("Program.cron.dispatch","run_cli","cron kit"),
    "ai_agent":      ("Program.ai_agent.dispatch","run_cli","autonomous agent"),
    "osint_face":    ("Program.osint_face.dispatch","run_cli","face search + reverse image"),
    "mail_trace":    ("Program.mail_trace.dispatch","run_cli","email header + SPF/DKIM recon"),
    "ad_attack":     ("Program.ad_attack.dispatch","run_cli","AD attack chain"),
    "cloud_pwn":     ("Program.cloud_pwn.dispatch",   "run_cli", "AWS / Azure / GCP attack chain"),
    "container_escape":("Program.container_escape.dispatch","run_cli","container escape"),
    "supply_chain":  ("Program.supply_chain.dispatch","run_cli","supply chain attacks"),
    "mobile":        ("Program.mobile.dispatch","run_cli","mobile attack kit"),
    "wireless":      ("Program.wireless.dispatch","run_cli","wireless attack kit"),
    "physical":      ("Program.physical.dispatch","run_cli","physical security kit"),
    "ai":            ("Program.ai.dispatch","run_cli","AI attack kit"),
    "iot":           ("Program.iot.dispatch","run_cli","IoT attack kit"),
    "cloud":         ("Program.cloud.dispatch","run_cli","cloud attack kit"),
    "crypto":        ("Program.crypto.dispatch","run_cli","crypto attack kit"),
    "phishing":     ("Program.phishing.dispatch","run_cli","phishing kit"),
    "ddos":          ("Program.ddos.dispatch",  "run_cli", "load-test simulator (gated)"),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redsky",
        description="Red Sky — modular offensive framework",
        add_help=False,
    )
    p.add_argument("-h", "--help", action="store_true", help="show help")
    p.add_argument("-v", "--version", action="store_true", help="show version")
    p.add_argument("-m", "--menu", action="store_true",
                   help="launch interactive menu")
    p.add_argument("--list", action="store_true",
                   help="list every module")
    p.add_argument("--plugins", action="store_true",
                   help="list plugins")
    p.add_argument("--plugin", nargs=argparse.REMAINDER,
                   help="run a plugin by name")
    p.add_argument("--config", action="store_true",
                   help="show current config")
    p.add_argument("--ack", action="store_true",
                   help="acknowledge authorized-use notice")
    p.add_argument("command", nargs="?", help="module to run")
    p.add_argument("args", nargs=argparse.REMAINDER,
                   help="arguments passed to the module")
    return p


def show_version():
    print(f"{SCARLET}Red Sky{RESET} {BONE}v0.1.0{RESET}  "
          f"{ASH}authorized engagements only{RESET}")


def show_help():
    print_banner()
    print_smear(72, ARTERY)
    print(f"{BOLD}{SCARLET}  usage{RESET}")
    print_smear(72, ARTERY)
    print(f"  {BONE}redsky{RESET} {ASH}<command> [args...]{RESET}")
    print(f"  {BONE}redsky{RESET} {ASH}-m{RESET}                {ASH}interactive menu{RESET}")
    print(f"  {BONE}redsky{RESET} {ASH}--list{RESET}            {ASH}list every module{RESET}")
    print(f"  {BONE}redsky{RESET} {ASH}--plugins{RESET}         {ASH}list plugins{RESET}")
    print(f"  {BONE}redsky{RESET} {ASH}--plugin <name> ...{RESET} run a plugin")
    print(f"  {BONE}redsky{RESET} {ASH}--config{RESET}          {ASH}show config{RESET}")
    print(f"  {BONE}redsky{RESET} {ASH}--ack{RESET}             {ASH}acknowledge authorized-use{RESET}")
    print(f"  {BONE}redsky{RESET} {ASH}-v{RESET}                {ASH}version{RESET}")
    print()
    print_header("modules", 72)
    for name, (_, _, desc) in sorted(MODULES.items()):
        print(f"  {ARTERY}▓{RESET} {BONE}{name:<20}{RESET} {ASH}{desc}{RESET}")
    print()


def show_config():
    cfg = load_config()
    print_header("config", 72)
    print_kv("handle",   cfg.get("operator.handle"))
    print_kv("email",    cfg.get("operator.email"))
    print_kv("c2.host",  cfg.get("c2.host") or "(unset)")
    print_kv("c2.port",  cfg.get("c2.port"))
    print_kv("panel",    f"{cfg.get('botnet.panel_host')}:{cfg.get('botnet.panel_port')}")
    print_kv("skin",     cfg.get("theme.skin"))
    print_kv("ack",      cfg.get("safety.authorized_use_ack"))
    print()


def ack_authorized():
    cfg = load_config()
    cfg.set("safety.authorized_use_ack", True)
    cfg.save()
    print_ok("authorized-use acknowledged")


def dispatch(command: str, args: List[str]) -> int:
    if command not in MODULES:
        print_err(f"unknown command: {command}")
        print_info("run 'redsky --list' to see every module")
        return 2

    import_path, fn_name, _ = MODULES[command]
    try:
        mod = __import__(import_path, fromlist=[fn_name])
    except ImportError as e:
        print_err(f"module not yet built: {command}")
        print(f"  {ASH}{import_path} — {e}{RESET}")
        return 3

    fn = getattr(mod, fn_name, None)
    if not callable(fn):
        print_err(f"{import_path}.{fn_name} missing")
        return 3

    try:
        return int(fn(args)) if fn(args) else 0
    except SystemExit as e:
        return int(e.code or 0)
    except Exception:
        print_err(f"module {command} raised:")
        traceback.print_exc()
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    ensure_dirs()
    parser = build_parser()
    ns = parser.parse_args(argv)

    if ns.version:
        show_version()
        return 0

    if ns.help and not ns.command:
        show_help()
        return 0

    if ns.ack:
        ack_authorized()
        return 0

    if ns.config:
        show_config()
        return 0

    if ns.list and not ns.command:
        show_help()
        return 0

    if ns.plugins:
        from Plugins.loader import get_manager
        get_manager().show()
        return 0

    if ns.plugin:
        from Plugins.loader import get_manager
        if not ns.plugin:
            print_err("--plugin needs a name")
            return 2
        name, *rest = ns.plugin
        return get_manager().run(name, rest)

    if ns.menu or not ns.command:
        from .interface import run_menu
        return run_menu()

    return dispatch(ns.command, ns.args)


if __name__ == "__main__":
    sys.exit(main())
