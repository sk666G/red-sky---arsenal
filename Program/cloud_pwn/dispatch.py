# language: Python, file: Program/cloud_pwn/dispatch.py, target: Red Sky cloud_pwn router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky cloud_pwn <sub-command> [args...]")
    print_info("")
    print_info("  metadata [--providers aws|azure|gcp|all] [--proxy URL]")
    print_info("      pull cloud IMDS credentials via SSRF")
    print_info("")
    print_info("  iam <whoami|enum|privesc> [--access-key K --secret-key K] [--region R]")
    print_info("      IAM identity, effective permissions, privesc chain detection")
    print_info("")
    print_info("  buckets <org-or-domain> [--provider s3|azure|gcs|all] [--dump]")
    print_info("      brute bucket names, check public access, list contents")
    print_info("")
    print_info("  k8s <whoami|enum|secrets> [--host URL] [--token TOKEN]")
    print_info("      Kubernetes API enumeration from an in-pod service account")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub == "metadata":
        from .metadata import run_cli as _m
        return int(_m(args[1:]))
    if sub == "iam":
        from .iam import run_cli as _i
        return int(_i(args[1:]))
    if sub in ("buckets", "bucket"):
        from .buckets import run_cli as _b
        return int(_b(args[1:]))
    if sub in ("k8s", "kubernetes"):
        from .k8s import run_cli as _k
        return int(_k(args[1:]))

    print_err(f"unknown cloud_pwn sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
