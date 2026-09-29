# language: Python, file: Program/cloud/dispatch.py, target: Red Sky cloud router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky cloud <sub-command> [args...]")
    print_info("")
    print_info("  metadata     probe --cloud aws|gcp|azure [--out FILE]")
    print_info("  metadata     chain")
    print_info("      hit instance metadata service, harvest credentials")
    print_info("")
    print_info("  iam_enum     whoami | walk")
    print_info("      sts:GetCallerIdentity + full IAM walk + SimulatePrincipalPolicy")
    print_info("")
    print_info("  privesc      chains | chain <name> | run <driver> --target X")
    print_info("      IAM privesc chain catalog + runnable escalation drivers")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("metadata", "md", "m"):
        from .metadata import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("iam_enum", "iam", "enum", "i"):
        from .iam_enum import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("privesc", "priv", "p"):
        from .privesc import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown cloud sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
