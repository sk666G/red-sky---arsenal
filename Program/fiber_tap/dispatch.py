# language: Python, file: Program/fiber_tap/dispatch.py, target: Red Sky fiber_tap router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky fiber_tap <sub-command> [args...]")
    print_info("")
    print_info("  capture <list|capture|parse|extract> [opts]")
    print_info("      SPAN / TAP capture, pcap summarization, credential extraction")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("capture", "cap", "c"):
        from .capture import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown fiber_tap sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
