# language: Python, file: Program/social/dispatch.py, target: Red Sky social router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky social <sub-command> [args...]")
    print_info("  profile <email|phone|name|username> [--deep]")
    print_info("      build an OSINT dossier on a target")
    print_info("")
    print_info("  --deep also scans every platform for the username")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("profile", "p"):
        from .profile import run_cli as _p
        return int(_p(args[1:]))

    print_err(f"unknown social sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
