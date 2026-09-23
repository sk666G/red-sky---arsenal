# language: Python, file: Program/wireless/dispatch.py, target: Red Sky wireless router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky wireless <sub-command> [args...]")
    print_info("")
    print_info("  scan [list] [--iface wlan0] [--out file.json]")
    print_info("      interface enumeration + passive AP survey")
    print_info("")
    print_info("  deauth <one|all|monitor> --iface wlan0mon --bssid AA:BB:CC:DD:EE:FF [--client ...]")
    print_info("      send 802.11 deauth frames (one client or broadcast)")
    print_info("")
    print_info("  evil_twin <run|hits|portal> --iface wlan1 --ssid 'FreeWiFi' [--passphrase pw] [--uplink eth0]")
    print_info("      rogue AP + dnsmasq + captive portal credential capture")
    print_info("")
    print_info("  handshake <capture|crack|list> [opts]")
    print_info("      WPA/WPA2 PMKID or 4-way handshake capture + hashcat/aircrack crack")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("scan", "survey", "s"):
        from .scan import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("deauth", "kick", "d"):
        from .deauth import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("evil_twin", "eviltwin", "et", "e"):
        from .evil_twin import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("handshake", "hs", "h"):
        from .handshake import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown wireless sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
