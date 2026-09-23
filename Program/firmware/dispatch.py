# language: Python, file: Program/firmware/dispatch.py, target: Red Sky firmware router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky firmware <sub-command> [args...]")
    print_info("")
    print_info("  analyze <identify|unpack|uefi|squashfs|cve> [opts]")
    print_info("      generic firmware analysis: identify, extract, UEFI, squashfs, cve")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("analyze", "a"):
        from .analyze import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown firmware sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
