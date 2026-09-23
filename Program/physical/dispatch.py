# language: Python, file: Program/physical/dispatch.py, target: Red Sky physical router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky physical <sub-command> [args...]")
    print_info("")
    print_info("  rfid <info|read|write|emulate|list|tools> [lf|hf|mf] [--dump file]")
    print_info("      proxmark3-driven tag read/dump/clone/emulate")
    print_info("")
    print_info("  lock <catalog|blanks|cut-sheet> [--filter X] [--code KW1 --cuts 3-5-2-1-4]")
    print_info("      lock bypass reference + key blank dimensions + cut sheets")
    print_info("")
    print_info("  usb_drop <list|gen> [payload|all] [--target ducky|digispark|p4wnp1|all]")
    print_info("      generate HID-drop payloads for Ducky / Digispark / P4wnP1 / O.MG")
    print_info("")
    print_info("  badge_clone <read|decode|encode|write|emulate> --type hid|em|iclass|mifare")
    print_info("      HID Prox / iCLASS / EM4100 badge read/clone/emulate")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("rfid", "nfc", "r"):
        from .rfid import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("lock", "lockpick", "l"):
        from .lock import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("usb_drop", "usb", "drop", "u"):
        from .usb_drop import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("badge_clone", "badge", "b"):
        from .badge_clone import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown physical sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
