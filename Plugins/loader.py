# language: Python, file: Plugins/loader.py, target: Red Sky plugin loader
# Discovers Plugins/*.py, validates they export a register() callable,
# exposes them to the CLI and interface.

import importlib.util
import inspect
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from Program.utils import get_logger, print_ok, print_err, print_warn, print_bullet
from Program.utils.paths import PLUGINS_DIR


@dataclass
class Plugin:
    name: str
    path: Path
    description: str
    author: str
    version: str
    entry: Callable


def _load_module_from_path(path: Path):
    spec = importlib.util.spec_from_file_location(f"redsky_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build import spec for {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class PluginManager:
    def __init__(self, plugin_dir: Path = None):
        self.dir = plugin_dir or PLUGINS_DIR
        self.log = get_logger("plugin_loader")
        self.plugins: Dict[str, Plugin] = {}

    def discover(self) -> List[Plugin]:
        self.plugins.clear()
        if not self.dir.exists():
            self.dir.mkdir(parents=True, exist_ok=True)
            return []

        for path in sorted(self.dir.glob("*.py")):
            if path.name.startswith("_") or path.name == "loader.py":
                continue
            try:
                mod = _load_module_from_path(path)
            except Exception:
                self.log.warn(f"plugin load failed: {path.name}")
                traceback.print_exc()
                continue

            register = getattr(mod, "register", None)
            if not callable(register):
                self.log.warn(f"plugin missing register(): {path.name}")
                continue

            try:
                info = register() or {}
            except Exception:
                self.log.warn(f"plugin register() raised: {path.name}")
                continue

            name = info.get("name") or path.stem
            entry = info.get("run")
            if not callable(entry):
                self.log.warn(f"plugin has no run(): {path.name}")
                continue

            plugin = Plugin(
                name=name,
                path=path,
                description=info.get("description", ""),
                author=info.get("author", "unknown"),
                version=info.get("version", "0.0.0"),
                entry=entry,
            )
            self.plugins[name] = plugin
            self.log.info(f"loaded plugin: {name} ({path.name})")

        return list(self.plugins.values())

    def list(self) -> List[Plugin]:
        if not self.plugins:
            self.discover()
        return list(self.plugins.values())

    def get(self, name: str) -> Optional[Plugin]:
        if not self.plugins:
            self.discover()
        return self.plugins.get(name)

    def run(self, name: str, args: List[str]) -> int:
        p = self.get(name)
        if not p:
            print_err(f"plugin not found: {name}")
            return 1
        try:
            result = p.entry(args)
            return int(result) if isinstance(result, int) else 0
        except Exception:
            print_err(f"plugin {name} raised:")
            traceback.print_exc()
            return 1

    def show(self):
        plugins = self.list()
        if not plugins:
            print_warn("no plugins found in Plugins/")
            return
        print_ok(f"{len(plugins)} plugin(s):")
        for p in plugins:
            print_bullet(f"{p.name:<20} {p.description}  (v{p.version} — {p.author})")


_manager: Optional[PluginManager] = None


def get_manager() -> PluginManager:
    global _manager
    if _manager is None:
        _manager = PluginManager()
    return _manager
