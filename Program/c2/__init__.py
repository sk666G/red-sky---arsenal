# language: Python, file: Program/c2/__init__.py, target: Red Sky c2 package
# C2 — protocol, listener, session store, channels, malleable profiles.

from .protocol import Message, encode_packet, decode_packet
from .session import SessionStore

__all__ = ["Message", "encode_packet", "decode_packet", "SessionStore"]


def run_cli(args):
    from .dispatch import run_cli as _run
    return _run(args)
