# language: Python, file: Program/creds/__init__.py, target: Red Sky creds package
# Credential operations — LSASS parse, spray, kerberoast, asrep, dcsync, token.

from .dispatch import run_cli
from .spray import run_cli as spray_cli
from .kerberoast import run_cli as kerberoast_cli
from .asrep import run_cli as asrep_cli
from .dcsync import run_cli as dcsync_cli
from .token import run_cli as token_cli

try:
    from .lsass import run_cli as lsass_cli
except ImportError:
    lsass_cli = None

__all__ = ["run_cli", "spray_cli", "kerberoast_cli",
           "asrep_cli", "dcsync_cli", "token_cli", "lsass_cli"]
