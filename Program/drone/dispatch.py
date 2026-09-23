# language: Python, file: Program/drone/dispatch.py, target: Red Sky drone router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky drone <sub-command> [args...]")
    print_info("")
    print_info("  mavlink <scan|sniff|cmd> [opts]")
    print_info("      MAVLink recon + COMMAND_LONG injection")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("mavlink", "mav", "m"):
        from .mavlink import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown drone sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
