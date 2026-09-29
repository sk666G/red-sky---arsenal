# language: Python, file: Program/physical/dispatch.py, target: Red Sky physical router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky physical <sub-command> [args...]")
    print_info("")
    print_info("  rfid detect")
    print_info("  rfid read [--keys FILE]")
    print_info("  rfid clone --dump FILE [--keys FILE]")
    print_info("      MIFARE Classic read/clone via proxmark3 or PN532")
    print_info("")
    print_info("  lockbypass ...      (coming)")
    print_info("  usb_drop ...        (coming)")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("rfid", "r"):
        from .rfid import run_cli as _f
        return int(_f(args[1:]))

    if sub in ("lockbypass", "lock", "l"):
        print_info("physical lockbypass: not yet wired — coming in this build")
        return 0
    if sub in ("usb_drop", "usb", "u"):
        print_info("physical usb_drop: not yet wired — coming in this build")
        return 0

    print_err("unknown physical sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
