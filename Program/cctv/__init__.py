# language: Python, file: Program/cctv/__init__.py, target: Red Sky cctv package
# CCTV discover / default-creds / stream / kill.

from .dispatch import run_cli
from .discover import run_cli as discover_cli
from .default_creds import run_cli as creds_cli
from .stream import run_cli as stream_cli
from .kill import run_cli as kill_cli

__all__ = ["run_cli", "discover_cli", "creds_cli", "stream_cli", "kill_cli"]
