# language: Python, file: Program/macro/dispatch.py, target: Red Sky macro router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky macro <sub-command> [args...]")
    print_info("")
    print_info("  vba <list|gen> [kind] --cmd '...' [--trigger X] [--obfuscate Y] [--delay ms]")
    print_info("      VBA macro generator: shell / wmi / win32 / powershell / download / persist")
    print_info("")
    print_info("  dde <word|excel|msdt|rtf|html> [opts]")
    print_info("      DDE field code / formula / ms-msdt / RTF / HTML smuggling")
    print_info("")
    print_info("  xlm <exec|register|download|obfuscated|wk1> [opts]")
    print_info("      Excel 4.0 macro generator (EXEC, REGISTER+CALL, download)")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("vba", "vb"):
        from .vba import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("dde", "word", "excel"):
        from .dde import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("xlm", "excel4"):
        from .xlm import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown macro sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
