# language: Python, file: Program/burp_suite/dispatch.py, target: Red Sky burp_suite router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky burp_suite <sub-command> [args...]")
    print_info("")
    print_info("  drive <find|launch|ext|api|proxy> [opts]")
    print_info("      Burp launcher, extension scaffolder, REST client, browser proxy")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("drive", "d"):
        from .drive import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown burp_suite sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
