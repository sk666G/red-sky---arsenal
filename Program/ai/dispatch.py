# language: Python, file: Program/ai/dispatch.py, target: Red Sky ai router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky ai <sub-command> [args...]")
    print_info("")
    print_info("  inject <list|test> [--category C] [--id PAYLOAD_ID] [--config target.json]")
    print_info("      prompt injection payload catalog + tester against a target API")
    print_info("")
    print_info("  leak <list|run> [--config target.json] [--strategy X]")
    print_info("      system prompt extraction — 24 probes across 8 strategies")
    print_info("")
    print_info("  extract <list|collect|convert|train> [--config X] [--dataset Y]")
    print_info("      model extraction / distillation dataset builder + converter")
    print_info("")
    print_info("  adversarial <list|gen> [generator|all] --prompt 'text' [--n 5]")
    print_info("      typo / homoglyph / invisible / bidi / tag-smuggle / gcg-suffix / encoded")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("inject", "inj", "i"):
        from .inject import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("leak", "l"):
        from .leak import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("extract", "distill", "e"):
        from .extract import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("adversarial", "adv", "a"):
        from .adversarial import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown ai sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
