# language: Python, file: Program/proxy_chain/dispatch.py, target: Red Sky proxy_chain router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky proxy_chain <sub-command> [args...]")
    print_info("")
    print_info("  chain <add|list|test|chain|rotate|tor> [opts]")
    print_info("      proxy pool management + proxychains config")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("chain", "c"):
        from .chain import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown proxy_chain sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
