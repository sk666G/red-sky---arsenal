# language: Python, file: Program/wifi/dispatch.py, target: Red Sky wifi router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky wifi <sub-command> [args...]")
    print_info("  recon <interfaces|monitor|scan> [iface] [--stop] [--duration N]")
    print_info("  handshake <capture|pmkid> <iface> [--bssid MAC] [--channel N] [--duration S] [--no-deauth]")
    print_info("  crack <aircrack|hashcat|show> <file> [--wordlist PATH] [--mode N]")
    print_info("  wps <scan|attack> <iface> [--duration S] [--bssid MAC] [--channel N] [--mode pixie|pin:NNN]")
    print_info("")
    print_info("  needs root for monitor mode, capture, and reaver")
    print_info("  requires: aircrack-ng, hcxdumptool, hcxtools, reaver")
    print_info("  install: sudo apt install aircrack-ng hcxdumptool hcxtools reaver")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub == "recon":
        from .recon import run_cli as _r
        return int(_r(args[1:]))
    if sub in ("handshake", "hs"):
        from .handshake import run_cli as _h
        return int(_h(args[1:]))
    if sub == "crack":
        from .crack import run_cli as _c
        return int(_c(args[1:]))
    if sub == "wps":
        from .wps import run_cli as _w
        return int(_w(args[1:]))

    print_err(f"unknown wifi sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
