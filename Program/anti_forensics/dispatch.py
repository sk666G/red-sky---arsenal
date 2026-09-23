# language: Python, file: Program/anti_forensics/dispatch.py, target: Red Sky anti_forensics router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky anti_forensics <sub-command> [args...]")
    print_info("")
    print_info("  logs <list|wipe|timestomp> [opts]")
    print_info("      artifact cleanup: logs, history, journal, timestomp")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("logs", "log", "l"):
        from .logs import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown anti_forensics sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
