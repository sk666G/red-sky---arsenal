# language: Python, file: Program/payload/__init__.py, target: Red Sky payload package
# Payload builder — dropper, persistence, LOLBin, obfuscator, macro, HTA, ISO.

from .dispatch import run_cli

__all__ = ["run_cli"]
