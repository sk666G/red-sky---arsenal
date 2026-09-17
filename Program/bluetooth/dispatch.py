# language: Python, file: Program/bluetooth/dispatch.py, target: Red Sky bluetooth router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky bluetooth <sub-command> [args...]")
    print_info("  scan [--duration N]              BLE device enumeration")
    print_info("  services <MAC> [--timeout S]     GATT service/characteristic dump")
    print_info("  services <MAC> --legacy          force gatttool path")
    print_info("  sniff [--duration N]             live HCI trace (root)")
    print_info("  parse <logfile>                  parse a saved btmon log")
    print_info("")
    print_info("  needs root for sniff; hci0 must be up:")
    print_info("  sudo hciconfig hci0 up")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("scan", "s"):
        from .scan import run_cli as _s
        return int(_s(args[1:]))
    if sub in ("services", "gatt"):
        from .services import run_cli as _sv
        return int(_sv(args[1:]))
    if sub in ("sniff", "monitor"):
        from .sniff import run_cli as _sn
        return int(_sn(args[1:]))
    if sub == "parse":
        from .sniff import run_cli as _sn
        return int(_sn(args[1:]))

    print_err(f"unknown bluetooth sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
