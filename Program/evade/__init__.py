# language: Python, file: Program/evade/__init__.py, target: Red Sky evade package
# Detection-defeat helpers — AMSI, ETW, unhook, sandbox, anti-debug, string crypt,
# syscall stub generation.

from .dispatch import run_cli
from .amsi import run_cli as amsi_cli
from .etw import run_cli as etw_cli
from .unhook import run_cli as unhook_cli
from .sandbox import run_cli as sandbox_cli
from .anti_debug import run_cli as anti_debug_cli
from .string_crypt import run_cli as string_crypt_cli
from .syscall_stub import run_cli as syscall_stub_cli

__all__ = ["run_cli", "amsi_cli", "etw_cli", "unhook_cli", "sandbox_cli",
           "anti_debug_cli", "string_crypt_cli", "syscall_stub_cli"]
