# language: Python, file: Program/evade/dispatch.py, target: Red Sky evade router
import sys
from typing import List
from Program.utils import print_info, print_err

SUB = {
    "amsi":         "amsi",
    "etw":          "etw",
    "unhook":       "unhook",
    "sandbox":      "sandbox",
    "anti_debug":   "anti_debug",
    "anti-debug":   "anti_debug",
    "string_crypt": "string_crypt",
    "string-crypt": "string_crypt",
    "syscall_stub": "syscall_stub",
    "syscall":      "syscall_stub",
}


def _usage():
    print_info("redsky evade <sub-command> [args...]")
    print_info("  amsi <list|ps|cs|cpp|url>                 AMSI bypass code")
    print_info("  etw <list|cpp|ps>                         ETW patch code")
    print_info("  unhook <list|disk|knowndll|per-fn>        NTDLL unhook code")
    print_info("  sandbox show                              sandbox detect code")
    print_info("  anti_debug show                           anti-debug code")
    print_info("  string_crypt <str> [--key hex] [--out f]  string obfuscator")
    print_info("  syscall_stub [--funcs a,b,c] [--out f]    syscall stub generator")


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
        print_err(f"unknown evade sub-command: {sub}")
        _usage()
        return 2
    mod = __import__(f"Program.evade.{target}", fromlist=["run_cli"])
    return int(mod.run_cli(args[1:]))


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
