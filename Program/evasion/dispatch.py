# language: Python, file: Program/evasion/dispatch.py, target: Red Sky evasion router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky evasion <sub-command> [args...]")
    print_info("")
    print_info("  av <list|show|plan> [vendor]")
    print_info("      per-vendor AV/EDR bypass cookbook (defender, crowdstrike, ...)")
    print_info("")
    print_info("  loader <list|gen> [technique] [--shellcode HEX] [--out file.cpp] [--with-hellsgate]")
    print_info("      shellcode loader generator: virtualalloc / ntmap / modstomp / callback / fiber / apc / earlybird / hollow")
    print_info("")
    print_info("  sandbox <check|emit|list> [--out file]")
    print_info("      anti-VM checks against this host, or emit C++ sandbox detector")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("av", "edr", "av_bypass", "a"):
        from .av_bypass import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("loader", "loaders", "l"):
        from .loader import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("sandbox", "sbx", "anti-vm", "s"):
        from .sandbox import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown evasion sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
