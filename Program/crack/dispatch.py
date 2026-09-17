# language: Python, file: Program/crack/dispatch.py, target: Red Sky crack router
import sys
from typing import List
from Program.utils import print_info, print_err

SUB = {
    "classify":  "classifier",
    "classifier":"classifier",
    "patch":     "patcher",
    "patcher":   "patcher",
    "keygen":    "keygen",
    "mitm":      "mitm_license",
    "license":   "mitm_license",
    "tools":     "toolchain",
    "toolchain": "toolchain",
    "strings":   "toolchain",
    "rabin2":    "toolchain",
    "r2":        "toolchain",
    "frida":     "toolchain",
    "ghidra":    "toolchain",
}


def _usage():
    print_info("redsky crack <sub-command> [args...]")
    print_info("  classify <binary>                         packer + scheme detect")
    print_info("  patch <binary> [--offset 0x...] [--mode invert|nop]")
    print_info("  keygen [--algo luhn|checksum|md5|sha256|random] [--count N]")
    print_info("  mitm <serve|dump> [--port N] [--format json|xml|text]")
    print_info("  tools check                               toolchain availability")
    print_info("  tools strings <binary> [--filter k1,k2]")
    print_info("  tools rabin2 <binary>                     sections + imports")
    print_info("  tools r2 <binary> [r2-commands]           r2 analysis")
    print_info("  tools frida <binary> [module] [func]      frida trace")
    print_info("  tools ghidra <binary> [project]           ghidra headless")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0
    target = SUB.get(sub)
    if not target:
        print_err(f"unknown crack sub-command: {sub}")
        _usage()
        return 2

    mod = __import__(f"Program.crack.{target}", fromlist=["run_cli"])

    # for `tools <sub>`, pass the rest through (toolchain handles it)
    if sub in ("tools", "toolchain"):
        return int(mod.run_cli(args[1:]))
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
