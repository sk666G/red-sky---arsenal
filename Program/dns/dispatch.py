# language: Python, file: Program/dns/dispatch.py, target: Red Sky dns router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky dns <sub-command> [args...]")
    print_info("")
    print_info("  tunnel   server | send")
    print_info("      DNS exfil via TXT/A queries, base32 chunked")
    print_info("")
    print_info("  rebind   serve | payload")
    print_info("      DNS rebinding for SSRF same-origin bypass")
    print_info("")
    print_info("  poison   catalog | info <name> | snoop")
    print_info("      cache poisoning reference + RD=0 cache snooping")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("tunnel", "t"):
        from .tunnel import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("rebind", "r"):
        from .rebind import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("poison", "p", "cache"):
        from .poison import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown dns sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
