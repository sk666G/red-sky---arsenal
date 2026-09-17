# language: Python, file: Program/ddos/dispatch.py, target: Red Sky ddos router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky ddos <sub-command> [args...]")
    print_info("  test <target> [--rps N] [--duration N]   run capped load test")
    print_info("  authorize <target>                       add to authorized list")
    print_info("  authorize --remove <target>              remove from list")
    print_info("  list                                     show authorized targets")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub not in ("test", "authorize", "list"):
        print_err(f"unknown ddos sub-command: {sub}")
        _usage()
        return 2
    from .simulator import run_cli as _run
    return int(_run(args))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
