# language: Python, file: Program/phish/__init__.py, target: Red Sky phish package
# Phishing framework — clone templates, catch credentials, track hits, send mail.

from .dispatch import run_cli

__all__ = ["run_cli"]
