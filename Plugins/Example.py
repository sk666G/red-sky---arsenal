# language: Python, file: Plugins/Example.py, target: Red Sky example plugin
# Minimal plugin showing the ABI. Copy this file, rename, edit register().

from Program.utils import print_ok, print_kv, print_bullet


def register() -> dict:
    return {
        "name": "example",
        "description": "example plugin — prints a greeting",
        "author": "sk666G",
        "version": "0.1.0",
        "run": run,
    }


def run(args: list) -> int:
    who = args[0] if args else "operator"
    print_ok(f"example plugin says hello, {who}")
    print_kv("args", args)
    print_bullet("edit Plugins/Example.py to build your own")
    return 0
