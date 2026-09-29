# language: Python, file: Program/physical/rfid.py, target: Red Sky physical — RFID read/clone
# Drives either a Proxmark3 (via the `pm3` or `proxmark3` client) or a PN532
# (via nfc-tools: nfc-mfclassic, nfc-list). Detects which is on PATH at call
# time; if both, prefers Proxmark.
#
# Outputs a card dump in both nfc-tools format (.bin + .json keys) and a
# human-readable summary. Clones from a dump by writing sectors back with
# the captured keys.

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


RF_DIR = OUTPUT_DIR / "physical" / "rfid"

# Common MIFARE Classic default keys — every reader ships these
DEFAULT_KEYS = [
    "FFFFFFFFFFFF",
    "A0A1A2A3A4A5",
    "D3F7D3F7D3F7",
    "000000000000",
    "B0B1B2B3B4B5",
    "4D3A99C351DD",
    "1A982C7E459A",
    "AABBCCDDEEFF",
    "714C5C886E97",
    "587EE5F9350F",
    "A0478CC39091",
    "533CB6C723F6",
    "8FD0A4F256E9",
]


# ── tool detection ──────────────────────────────────────────────────────────

def _which(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def detect_tool() -> Tuple[str, Optional[str]]:
    """Returns ('proxmark'|'pn532'|'none', path)."""
    pm = _which("pm3", "proxmark3")
    if pm:
        return "proxmark", pm
    nfc = _which("nfc-mfclassic", "nfc-list")
    if nfc:
        return "pn532", nfc
    return "none", None


def _run(cmd: List[str], timeout: int = 60, input_text: str = "") -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=input_text,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)


# ── proxmark3 backend ───────────────────────────────────────────────────────

def pm3_script(pm3: str, commands: List[str], timeout: int = 90) -> Tuple[int, str, str]:
    """Feed a list of proxmark3 client commands to stdin."""
    text = "\n".join(commands) + "\nquit\n"
    return _run([pm3], timeout=timeout, input_text=text)


def pm3_read(pm3: str, out_dir: Path) -> Optional[Dict]:
    """hf mf autopwn — reads keys, dumps all sectors, writes binaries locally."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmds = [
        "hf mf autopwn",
    ]
    rc, out, err = pm3_script(pm3, cmds, timeout=180)
    if rc != 0:
        print_err("proxmark autopwn rc=" + str(rc))
        if err:
            print_warn(err.strip().splitlines()[-1] if err.strip() else "")
        return None

    # autopwn writes dump + keys under the pm3 client's cwd — collect them
    found = {}
    for candidate in [
        Path.home() / ".proxmark3" / "dumps",
        Path.home() / ".proxmark3",
        Path.cwd(),
        out_dir,
    ]:
        if not candidate.exists():
            continue
        for f in candidate.glob("*.bin"):
            found.setdefault("bin", []).append(f)
        for f in candidate.glob("*.json"):
            found.setdefault("json", []).append(f)

    return {"raw_out": out, "raw_err": err, "files": {k: [str(p) for p in v] for k, v in found.items()}}


def pm3_clone(pm3: str, dump_path: Path, key_path: Optional[Path]) -> bool:
    """hf mf cload <dump> — writes an existing dump to a blank tag."""
    if not dump_path.exists():
        print_err("dump missing: " + str(dump_path))
        return False
    cmds = ["hf mf cload -f " + str(dump_path)]
    rc, out, err = pm3_script(pm3, cmds, timeout=120)
    if rc != 0:
        print_err("proxmark cload rc=" + str(rc))
        return False
    return True


# ── nfc-tools (PN532) backend ───────────────────────────────────────────────

def pn532_list() -> Optional[str]:
    rc, out, err = _run(["nfc-list"], timeout=15)
    if rc != 0:
        print_err("nfc-list rc=" + str(rc))
        if err:
            print_warn(err.strip())
        return None
    return out


def pn532_read(out_dir: Path, key_file: Optional[Path]) -> Optional[Path]:
    """nfc-mfclassic r a <dump> <keyfile> — reads a MIFARE Classic 1K with the key file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    dump = out_dir / ("dump_" + str(int(time.time())) + ".bin")

    # if no key file provided, write a default-key file to disk first
    if key_file is None or not key_file.exists():
        key_file = out_dir / "default_keys.mfd"
        # nfc-mfclassic wants a 6-byte-per-key file, 2 keys per sector (A and B)
        # we build a file with sector-A = default A0A1A2A3A4A5, sector-B = FFFFFFFFFFFF
        keys = b""
        for _ in range(40):
            keys += bytes.fromhex("A0A1A2A3A4A5") + bytes.fromhex("FFFFFFFFFFFF")
        key_file.write_bytes(keys)
        print_info("wrote default key file: " + str(key_file))

    rc, out, err = _run(["nfc-mfclassic", "r", "a", str(dump), str(key_file)], timeout=60)
    if rc != 0:
        print_err("nfc-mfclassic read rc=" + str(rc))
        if err:
            print_warn(err.strip().splitlines()[-1] if err.strip() else "")
        return None
    return dump


def pn532_clone(dump_path: Path, key_file: Optional[Path]) -> bool:
    if not dump_path.exists():
        print_err("dump missing: " + str(dump_path))
        return False
    if key_file is None or not key_file.exists():
        print_err("clone requires --keys <file>")
        return False
    rc, out, err = _run(["nfc-mfclassic", "w", "a", str(dump_path), str(key_file)], timeout=60)
    if rc != 0:
        print_err("nfc-mfclassic write rc=" + str(rc))
        if err:
            print_warn(err.strip().splitlines()[-1] if err.strip() else "")
        return False
    return True


# ── summary / index ─────────────────────────────────────────────────────────

def write_index(out_dir: Path, tool: str, dump: Optional[Path], extra: Dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    idx = out_dir / "index.json"
    data = {
        "tool": tool,
        "dump": str(dump) if dump else None,
        "ts": int(time.time()),
        "default_keys_tried": DEFAULT_KEYS,
        "extra": extra,
    }
    idx.write_text(json.dumps(data, indent=2))
    return idx


# ── commands ────────────────────────────────────────────────────────────────

def cmd_detect() -> int:
    tool, path = detect_tool()
    print_info("rfid tool detection")
    print_kv("backend", tool)
    print_kv("path", path or "(none)")
    if tool == "none":
        print()
        print_warn("install one of:")
        print_warn("  proxmark3:  apt install proxmark3  # or build from RfidResearchGroup")
        print_warn("  pn532:      apt install libnfc-bin libnfc-examples")
        return 1
    return 0


def cmd_read(keys: Optional[str]) -> int:
    tool, path = detect_tool()
    if tool == "none":
        print_err("no rfid backend on PATH — run `redsky physical rfid detect`")
        return 1

    RF_DIR.mkdir(parents=True, exist_ok=True)
    key_path = Path(keys) if keys else None

    print_info("rfid read")
    print_kv("backend", tool)
    print()

    if tool == "proxmark":
        res = pm3_read(path, RF_DIR)
        if not res:
            return 1
        print_ok("read complete")
        if res.get("files"):
            for kind, paths in res["files"].items():
                for p in paths:
                    print_kv(kind, p)
        idx = write_index(RF_DIR, tool, None, res)
        print_kv("index", idx)
        return 0

    # pn532
    dump = pn532_read(RF_DIR, key_path)
    if not dump:
        return 1
    print_ok("dump written: " + str(dump))
    idx = write_index(RF_DIR, tool, dump, {})
    print_kv("index", idx)
    return 0


def cmd_clone(dump: str, keys: Optional[str]) -> int:
    tool, path = detect_tool()
    if tool == "none":
        print_err("no rfid backend on PATH")
        return 1

    dump_path = Path(dump)
    if not dump_path.exists():
        print_err("dump not found: " + dump)
        return 1

    key_path = Path(keys) if keys else None

    print_info("rfid clone")
    print_kv("backend", tool)
    print_kv("dump", dump_path)
    print_kv("keys", key_path or "(default)")
    print()

    ok = False
    if tool == "proxmark":
        ok = pm3_clone(path, dump_path, key_path)
    else:
        ok = pn532_clone(dump_path, key_path)

    if ok:
        print_ok("clone written")
        return 0
    return 1


# ── cli ─────────────────────────────────────────────────────────────────────

def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky physical rfid", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    sub = args[0] if args else "detect"
    rest = args[1:] if args else []

    if sub in ("-h", "--help"):
        print_info("redsky physical rfid <sub-command>")
        print_info("")
        print_info("  detect")
        print_info("      show which rfid backend is installed")
        print_info("  read [--keys FILE]")
        print_info("      proxmark: hf mf autopwn   |   pn532: nfc-mfclassic r a")
        print_info("  clone --dump FILE [--keys FILE]")
        print_info("      proxmark: hf mf cload     |   pn532: nfc-mfclassic w a")
        return 0

    if sub == "detect":
        return cmd_detect()

    if sub == "read":
        p2 = argparse.ArgumentParser(prog="redsky physical rfid read", add_help=False)
        p2.add_argument("--keys", default="")
        try:
            ns = p2.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky physical rfid read [--keys FILE]")
            return 2
        return cmd_read(ns.keys or None)

    if sub in ("clone", "write"):
        p2 = argparse.ArgumentParser(prog="redsky physical rfid clone", add_help=False)
        p2.add_argument("--dump", required=False, default="")
        p2.add_argument("--keys", default="")
        try:
            ns = p2.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky physical rfid clone --dump FILE [--keys FILE]")
            return 2
        if not ns.dump:
            print_err("--dump required")
            return 2
        return cmd_clone(ns.dump, ns.keys or None)

    print_err("unknown rfid sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
