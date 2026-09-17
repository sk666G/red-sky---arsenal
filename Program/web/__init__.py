# language: Python, file: Program/web/__init__.py, target: Red Sky web package
# Web triage, deface, exploit match.

from .dispatch import run_cli
from .triage import run_cli as triage_cli
from .defacer import run_cli as defacer_cli
from .exploit_match import run_cli as exploit_cli

__all__ = ["run_cli", "triage_cli", "defacer_cli", "exploit_cli"]
