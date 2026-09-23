# language: Python, file: Program/ics/dispatch.py, target: Red Sky ics router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky ics <sub-command> [args...]")
    print_info("")
    print_info("  modbus <scan|units|read|write|enumerate|probe> [opts]")
    print_info("      Modbus/TCP scanner and read/write toolkit")
    print_info("")
    print_info("  s7 <scan|info|state|start|stop|read|write> [opts]")
    print_info("      Siemens S7comm over ISO-TSAP: SZL reads, memory access, CPU control")
    print_info("")
    print_info("  dnp3 <scan|info|poll|operate|restart|unsolicited> [opts]")
    print_info("      DNP3 outstation probe: integrity poll, CROB/AO control, restart")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("modbus", "mb", "m"):
        from .modbus import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("s7", "s7comm", "siemens", "s"):
        from .s7 import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("dnp3", "dnp", "d"):
        from .dnp3 import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown ics sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
