# language: Python, file: Program/vm_detect/dispatch.py, target: Red Sky vm_detect router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky vm_detect <sub-command> [args...]")
    print_info("")
    print_info("  probe <ip> [--ports 22,80,443,3389,5900]")
    print_info("      network-side VM/hypervisor fingerprint")
    print_info("  list")
    print_info("      show the marker strings")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    if sub in ("probe", "p", "list", "l"):
        from .detect import run_cli as _f
        return int(_f(args))
    print_err("unknown vm_detect sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
