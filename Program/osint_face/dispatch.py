# language: Python, file: Program/osint_face/dispatch.py, target: Red Sky osint_face router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky osint_face <sub-command> [args...]")
    print_info("  embed <image>              extract faces + vectors from one image")
    print_info("  build <directory>          build a searchable face index from a folder")
    print_info("  query <image> [--top N] [--threshold 0.4]")
    print_info("                              find matching faces in the index")
    print_info("  stats                      show index size")
    print_info("  clear --yes                wipe the index")
    print_info("")
    print_info("  model: InsightFace buffalo_l (ArcFace, 512-d)")
    print_info("  downloads ~300 MB on first use")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub == "embed":
        from .embedder import run_cli as _e
        return int(_e(args[1:]))
    if sub in ("build", "query", "find", "stats", "clear"):
        from .index import run_cli as _i
        return int(_i(args))

    print_err(f"unknown osint_face sub-command: {sub}")
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
