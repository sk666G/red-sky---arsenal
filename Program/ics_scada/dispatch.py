# language: Python, file: Program/ics_scada/dispatch.py, target: Red Sky ics_scada router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky ics_scada <sub-command> [args...]")
    print_info("")
    print_info("  protocols <scan|enip|profinet|bacnet|opcua|list> [opts]")
    print_info("      EtherNet/IP, Profinet DCP, BACnet/IP, OPC-UA + combined port map")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("protocols", "proto", "p"):
        from .protocols import run_cli as _f
        return int(_f(args[1:]))
    print_err("unknown ics_scada sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
