# language: Python, file: Program/ai/dispatch.py, target: Red Sky ai router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky ai <sub-command> [args...]")
    print_info("")
    print_info("  prompt_inject   catalog | show <cat> | build --tech CAT --goal TEXT")
    print_info("      prompt injection payloads (direct, roleplay, delim, chain, encode, indirect)")
    print_info("")
    print_info("  extraction      catalog | leak | fingerprint | distill")
    print_info("      system-prompt leak probes, behavioral fingerprinting, distillation loops")
    print_info("")
    print_info("  adversarial     classes | class <name> | gen | all")
    print_info("      attack-class reference + text-transform adversarial variants")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("prompt_inject", "inject", "pi"):
        from .prompt_inject import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("extraction", "extract", "ex"):
        from .extraction import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("adversarial", "adv", "ad"):
        from .adversarial import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown ai sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
