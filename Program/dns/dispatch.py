# language: Python, file: Program/dns/dispatch.py, target: Red Sky dns router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky dns <sub-command> [args...]")
    print_info("")
    print_info("  tunnel <send|serve|check|decode> [opts]")
    print_info("      DNS tunnel over TXT/A/NULL/CNAME. base32/base64/hex encodings.")
    print_info("")
    print_info("  rebind <server|http|timings|plan> [opts]")
    print_info("      DNS rebinding: rotate A records between attacker and target IPs")
    print_info("")
    print_info("  poison <snoop|forge|kaminsky> [opts]")
    print_info("      cache snooping, forged responses, birthday-attack scaffold")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("tunnel", "tun", "t"):
        from .tunnel import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("rebind", "rb", "r"):
        from .rebind import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("poison", "p"):
        from .poison import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown dns sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
