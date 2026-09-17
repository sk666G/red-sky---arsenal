# language: Python, file: Program/utils/logger.py, target: Red Sky logger
# Timestamped event log. Writes to Output/redsky.log and stdout.

import sys
import threading
from datetime import datetime
from pathlib import Path

from .paths import OUTPUT_DIR, ensure_dirs


_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}


class Logger:
    def __init__(self, name: str = "redsky", level: str = "INFO", to_file: bool = True):
        self.name = name
        self.level = _LEVELS.get(level.upper(), 20)
        self.to_file = to_file
        self._lock = threading.Lock()
        if to_file:
            ensure_dirs()
            self.path = OUTPUT_DIR / f"{name}.log"
        else:
            self.path = None

    def _emit(self, level: str, msg: str):
        if _LEVELS[level] < self.level:
            return
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} [{level:<5}] [{self.name}] {msg}"
        with self._lock:
            print(line, file=sys.stderr if level in ("WARN", "ERROR") else sys.stdout)
            if self.to_file and self.path:
                try:
                    with self.path.open("a", encoding="utf-8") as f:
                        f.write(line + "\n")
                except OSError:
                    pass

    def debug(self, msg: str): self._emit("DEBUG", msg)
    def info(self, msg: str):  self._emit("INFO", msg)
    def warn(self, msg: str):  self._emit("WARN", msg)
    def error(self, msg: str): self._emit("ERROR", msg)


_loggers = {}
_lock = threading.Lock()


def get_logger(name: str = "redsky", level: str = "INFO") -> Logger:
    with _lock:
        if name not in _loggers:
            _loggers[name] = Logger(name, level)
        return _loggers[name]
