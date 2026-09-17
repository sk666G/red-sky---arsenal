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
    "rfid":          ("Program.rfid.reader",     "run_cli", "NFC / Mifare / HID read+clone"),
    "usb":           ("Program.usb.badusb",      "run_cli", "BadUSB / Rubber Ducky builder"),
    "social":        ("Program.social.profile",  "run_cli", "OSINT person profile"),
    "osint_face":    ("Program.osint_face.search","run_cli","face search + reverse image"),
    "mail_trace":    ("Program.mail_trace.header","run_cli","email header + SPF/DKIM recon"),
    "ad_attack":     ("Program.ad_attack.bloodhound","run_cli","AD attack chain"),
    "cloud_pwn":     ("Program.cloud_pwn.aws",   "run_cli", "AWS / Azure / GCP attack chain"),
    "container_escape":("Program.container_escape.docker","run_cli","container escape"),
    "supply_chain":  ("Program.supply_chain.typosquat","run_cli","supply chain attacks"),
    "firmware":      ("Program.firmware.extract","run_cli","firmware extraction + analysis"),
    "satcom":        ("Program.satcom.recon",    "run_cli", "satellite / GPS recon"),
    "ics_scada":     ("Program.ics_scada.scan",  "run_cli", "Modbus / DNP3 / BACnet / S7"),
    "av_bypass":     ("Program.av_bypass.crypter","run_cli","AV/EDR bypass generator"),
    "shellcode":     ("Program.shellcode.gen",   "run_cli", "shellcode generator"),
    "proxy_chain":   ("Program.proxy_chain.route","run_cli","multi-hop proxy routing"),
    "anti_forensics":("Program.anti_forensics.wipe","run_cli","log wipe + cleanup"),
    "vm_detect":     ("Program.vm_detect.check", "run_cli", "sandbox / VM detection"),
    "drone":         ("Program.drone.telemetry", "run_cli", "drone telemetry recon"),
    "keygen_factory":("Program.keygen_factory.auto","run_cli","automated keygen pipeline"),
    "fuzzer":        ("Program.fuzzer.afl",      "run_cli", "protocol + binary fuzzer"),
    "burp_suite":    ("Program.burp_suite.headless","run_cli","headless web app scanner"),
    "wireless_jam":  ("Program.wireless_jam.rf", "run_cli", "RF jamming research tools"),
    "fiber_tap":     ("Program.fiber_tap.analyze","run_cli","optical tap analysis"),
    "lock_bypass":   ("Program.lock_bypass.guide","run_cli","physical lock bypass"),
    "memory_forensics":("Program.memory_forensics.dump","run_cli","live memory acquisition"),
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
