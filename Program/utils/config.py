# language: Python, file: Program/utils/config.py, target: Red Sky config loader
# JSON-backed config, dot-notation getter, atomic save.

import json
import threading
from pathlib import Path
from typing import Any

from .paths import CONFIG_FILE, DATA_DIR, ensure_dirs


_DEFAULTS = {
    "operator": {
        "handle": "operator",
        "email": "",
    },
    "paths": {
        "output": "Output",
        "loot": "Output/loot",
    },
    "network": {
        "timeout": 5,
        "threads": 128,
        "user_agent": "random",
        "proxy": "",
        "verify_tls": True,
    },
    "c2": {
        "host": "",
        "port": 443,
        "path": "/api/beacon",
        "tls": True,
        "sleep": 30000,
        "jitter": 0.3,
        "aes_key": "",
    },
    "botnet": {
        "db": "Data/botnet.sqlite",
        "panel_port": 8443,
        "panel_host": "127.0.0.1",
        "auth_user": "operator",
        "auth_pass_hash": "",
        "totp_secret": "",
        "ip_allowlist": [],
    },
    "phish": {
        "catcher_host": "",
        "catcher_port": 443,
        "smtp_relay": "",
        "smtp_user": "",
        "smtp_pass": "",
        "from_addr": "",
    },
    "cctv": {
        "rtsp_port": 554,
        "http_ports": [80, 8000, 8080, 8899],
        "ffmpeg_path": "ffmpeg",
    },
    "ddos": {
        "authorized_targets": [],
        "max_rps": 50,
    },
    "theme": {
        "skin": "blood",
        "emoji": True,
        "banner_drip_ms": 20,
    },
    "safety": {
        "authorized_use_ack": False,
    },
}


def _deep_merge(base: dict, overlay: dict) -> dict:
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, path: Path = None, data: dict = None):
        self.path = path or CONFIG_FILE
        self._lock = threading.Lock()
        self.data = data if data is not None else {}

    def get(self, dotted: str, default: Any = None) -> Any:
        parts = dotted.split(".")
        node = self.data
        for p in parts:
            if not isinstance(node, dict) or p not in node:
                return default
            node = node[p]
        return node

    def set(self, dotted: str, value: Any):
        parts = dotted.split(".")
        with self._lock:
            node = self.data
            for p in parts[:-1]:
                node = node.setdefault(p, {})
            node[parts[-1]] = value

    def save(self):
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    def __getitem__(self, key):
        return self.data[key]

    def __contains__(self, key):
        return key in self.data


def load_config(path: Path = None) -> Config:
    ensure_dirs()
    p = path or CONFIG_FILE
    if p.exists():
        try:
            on_disk = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            on_disk = {}
    else:
        on_disk = {}
    merged = _deep_merge(_DEFAULTS, on_disk)
    cfg = Config(p, merged)
    if not p.exists():
        cfg.save()
    return cfg


def save_config(cfg: Config):
    cfg.save()
