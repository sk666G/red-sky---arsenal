# language: Python, file: Program/wireless_jam/dispatch.py, target: Red Sky wireless_jam router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky wireless_jam <sub-command> [args...]")
    print_info("")
    print_info("  jam <tools|deauth|mdk4|dwell|plan> [opts]")
    print_info("      802.11 interference: deauth flood, mdk4 modes, dwell pattern")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("jam", "j"):
        from .jam import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown wireless_jam sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
