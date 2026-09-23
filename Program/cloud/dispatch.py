# language: Python, file: Program/cloud/dispatch.py, target: Red Sky cloud router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky cloud <sub-command> [args...]")
    print_info("")
    print_info("  aws <whoami|enumerate|privesc|s3|assume> [--profile X] [--region Y]")
    print_info("      STS identity, IAM/S3/EC2/Lambda inventory, privesc scoring, AssumeRole")
    print_info("")
    print_info("  azure <tenant|userenum|device-code|device-poll|imds|arm-enum> [opts]")
    print_info("      tenant resolve, user enum, device-code phish, IMDS token, ARM enum")
    print_info("")
    print_info("  gcp <whoami|privesc|metadata|list> [--sa key.json]")
    print_info("      SA identity, privesc catalog match, metadata server theft")
    print_info("")
    print_info("  metadata <probe|ssrf|payloads> [--target URL-with-FUZZ]")
    print_info("      multi-cloud IMDS probe + SSRF payload generator")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("aws", "a"):
        from .aws import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("azure", "az", "z"):
        from .azure import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("gcp", "google", "g"):
        from .gcp import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("metadata", "imds", "meta", "m"):
        from .metadata import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown cloud sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
