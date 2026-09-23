# language: Python, file: Program/cron/dispatch.py, target: Red Sky cron router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky cron <sub-command> [args...]")
    print_info("")
    print_info("  scheduler <cron|systemd|windows|macos|list|remove> [opts]")
    print_info("      cross-platform scheduled persistence")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("scheduler", "sched", "s"):
        from .scheduler import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown cron sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
