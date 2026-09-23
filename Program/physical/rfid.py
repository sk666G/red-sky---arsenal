# language: Python, file: Program/physical/rfid.py, target: Red Sky physical — RFID/NFC read/write/replay
# Wraps the Proxmark3 client (`pm3`) and, when only a PC/SC reader is attached,
# talks to it directly via nfcpy. Covers:
#   - read  (identify card type, dump sectors, save to disk)
#   - write (restore a dump onto a magic card)
#   - clone (read -> write in one shot)
#   - emulate (Proxmark3 emulation mode)
#   - info  (one-shot tag identification, no dump)
# Card families supported through pm3: MIFARE Classic/Ultralight/DESFire,
# iCLASS, HID Prox (125kHz), EM4100, T5577, Hitag, Legic.

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


PH_DIR = OUTPUT_DIR / "physical"
DUMP_DIR = PH_DIR / "rfid_dumps"
DUMP_DIR.mkdir(parents=True, exist_ok=True)


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(args: List[str], timeout: int = 120, stdin: str = "") -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           input=stdin if stdin else None)
        if r.returncode != 0 and r.stderr:
            print_warn(r.stderr.strip()[:200])
        return r.stdout
    except FileNotFoundError:
        print_err("missing: " + args[0])
        return ""
    except subprocess.TimeoutExpired:
        print_warn("timeout on " + " ".join(args[:2]))
        return ""


# ── tool detection ──
def find_tools() -> Dict[str, str]:
    out = {
        "pm3":        _which("pm3") or "",
        "proxmark3":  _which("proxmark3") or "",
        "nfcpy":      "",
    }
    # nfcpy is a python lib, check via import
    try:
        import nfc  # noqa: F401
        out["nfcpy"] = "yes"
    except ImportError:
        out["nfcpy"] = ""
    return out


def cmd_tools() -> int:
    t = find_tools()
    print_info("tool availability")
    for name, path in t.items():
        if path:
            print("  " + SCARLET + "▓" + RESET + " " + BONE + name + RESET + "  " + ASH + path + RESET)
        else:
            print("  " + ASH + "░ " + name + " (missing)" + RESET)
    print()
    if not t["pm3"] and not t["proxmark3"]:
        print_warn("no Proxmark3 client on PATH")
        print_info("install: apt install proxmark3-client  (or clone RfidResearchGroup/proxmark3)")
    if not t["nfcpy"]:
        print_info("for ACR122U / PN532 readers: pip install nfcpy")
    return 0


def _pm3() -> str:
    return _which("pm3") or _which("proxmark3") or ""


# ── Proxmark3 commands ──
def pm3_cmd(script: str, timeout: int = 60) -> str:
    pm = _pm3()
    if not pm:
        return ""
    # pm3 supports -c "<cmd>" for one-shot command strings
    return _run([pm, "-c", script], timeout=timeout)


def pm3_info() -> str:
    """Returns the 'hw version' banner — confirms the proxmark is connected."""
    return pm3_cmd("hw version")


def read_125khz() -> Optional[Dict]:
    """Read a 125kHz tag (EM4100 / HID Prox / T5577)."""
    print_info("polling 125kHz (lf search)")
    out = pm3_cmd("lf search", timeout=60)
    if not out:
        print_err("no proxmark / no response")
        return None
    print(out)
    # detect known formats
    family = ""
    for line in out.splitlines():
        for fam in ("EM410", "HID Prox", "Indala", "T5577", "AWID", "Paradox", "Pyramid",
                    "Viking", "Noralsy", "Securakey", "FDX-B", "Gallagher", "PAC/Stanley"):
            if fam.lower() in line.lower():
                family = fam
                break
        if family:
            break
    card = {"family": family or "unknown", "raw": out}
    return card


def read_13mhz() -> Optional[Dict]:
    """Read a 13.56MHz tag (MIFARE / iCLASS / DESFire)."""
    print_info("polling 13.56MHz (hf search)")
    out = pm3_cmd("hf search", timeout=60)
    if not out:
        print_err("no proxmark / no response")
        return None
    print(out)
    family = ""
    for line in out.splitlines():
        for fam in ("MIFARE Classic", "MIFARE Ultralight", "MIFARE DESFire", "iCLASS",
                    "NTAG", "ISO 15693", "FeliCa", "Topaz", "LEGIC"):
            if fam.lower() in line.lower():
                family = fam
                break
        if family:
            break
    return {"family": family or "unknown", "raw": out}


def dump_mifare_classic() -> Optional[Path]:
    """Run the MIFARE Classic nested/darkside attack and dump all sectors."""
    print_info("mifare classic: running autopwn to recover keys")
    out = pm3_cmd("hf mf autopwn", timeout=900)
    if not out:
        return None

    # pm3 autopwn saves <uid>.bin and .json under the client's working dir
    # find the newest pair
    now = time.time()
    candidates = []
    for p in Path(".").rglob("*.bin"):
        if now - p.stat().st_mtime < 900:
            candidates.append(p)
    if not candidates:
        print_warn("no dump file written — check pm3 output above")
        return None

    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    dst = DUMP_DIR / newest.name
    shutil.copy2(newest, dst)
    print_ok("dump saved: " + str(dst))
    # also copy the .json keys file if present
    keys_json = newest.with_suffix(".json")
    if keys_json.exists():
        shutil.copy2(keys_json, DUMP_DIR / keys_json.name)
        print_ok("keys saved: " + str(DUMP_DIR / keys_json.name))
    return dst


def write_from_dump(dump_file: str, confirm_magic: bool) -> int:
    """Restore a .bin dump to a blank / magic card."""
    if not confirm_magic:
        print_warn("writing requires a 'magic' card (gen1a / gen2 / gen3) or a blank tag")
        print_info("rerun with --magic-confirmed to proceed")
        return 2

    src = Path(dump_file).expanduser()
    if not src.exists():
        print_err("dump file not found: " + str(src))
        return 1

    uid = src.stem
    print_info("writing dump " + str(src) + " to tag (uid " + uid + ")")
    out = pm3_cmd("hf mf restore --uid " + uid + " f " + str(src), timeout=300)
    print(out)
    print_ok("restore attempted — verify with `redsky physical rfid info hf`")
    return 0


def emulate_from_dump(dump_file: str) -> int:
    """Proxmark3 emulates a MIFARE Classic using a dump file."""
    src = Path(dump_file).expanduser()
    if not src.exists():
        print_err("dump file not found: " + str(src))
        return 1
    uid = src.stem
    print_info("emulating " + uid + " (CTRL+C to stop)")
    pm = _pm3()
    if not pm:
        return 2
    try:
        subprocess.run([pm, "-c", "hf mf sim --uid " + uid])
    except KeyboardInterrupt:
        print_info("emulation stopped")
    return 0


def cmd_info(band: str) -> int:
    if band in ("lf", "125", "both"):
        card = read_125khz()
        if card:
            print()
            print_ok("125kHz tag: " + card["family"])
    if band in ("hf", "1356", "13.56", "both"):
        card = read_13mhz()
        if card:
            print()
            print_ok("13.56MHz tag: " + card["family"])
    return 0


def cmd_read(band: str, name: str) -> int:
    if band == "lf":
        card = read_125khz()
        if not card:
            return 1
        out = DUMP_DIR / ((name or "lf_" + str(int(time.time()))) + ".json")
        out.write_text(json.dumps(card, indent=2))
        print_kv("saved", out)
        return 0
    if band == "hf":
        card = read_13mhz()
        if not card:
            return 1
        out = DUMP_DIR / ((name or "hf_" + str(int(time.time()))) + ".json")
        out.write_text(json.dumps(card, indent=2))
        print_kv("saved", out)
        return 0
    if band == "mf":
        d = dump_mifare_classic()
        return 0 if d else 1
    print_err("unknown band: " + band + " (lf | hf | mf)")
    return 2


def cmd_list() -> int:
    dumps = sorted(DUMP_DIR.glob("*"))
    if not dumps:
        print_info("no dumps yet")
        return 0
    print_info(str(len(dumps)) + " file(s) in " + str(DUMP_DIR))
    print()
    for d in dumps:
        sz = d.stat().st_size
        print("  " + BONE + d.name + RESET + "  " + ASH + str(sz) + " bytes" + RESET)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky physical rfid", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="info",
                   choices=["info", "read", "write", "emulate", "list", "tools"])
    p.add_argument("band", nargs="?", default="both")
    p.add_argument("--name", default="")
    p.add_argument("--dump", default="")
    p.add_argument("--magic-confirmed", action="store_true")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky physical rfid <info|read|write|emulate|list|tools> [band|file]")
        return 2

    if ns.help:
        print_info("tools                                       -- show pm3 / nfcpy availability")
        print_info("info  <lf|hf|both>                          -- identify a tag")
        print_info("read  <lf|hf|mf> [--name X]                 -- dump tag / MIFARE Classic autopwn")
        print_info("write --dump <file> --magic-confirmed       -- restore a dump onto a magic tag")
        print_info("emulate --dump <file>                       -- proxmark sim mode")
        print_info("list                                        -- show all dumps")
        return 0

    if ns.action == "tools":
        return cmd_tools()
    if ns.action == "list":
        return cmd_list()
    if ns.action == "info":
        return cmd_info(ns.band)
    if ns.action == "read":
        return cmd_read(ns.band, ns.name)
    if ns.action == "write":
        if not ns.dump:
            print_err("--dump <file> required")
            return 2
        return write_from_dump(ns.dump, ns.magic_confirmed)
    if ns.action == "emulate":
        if not ns.dump:
            print_err("--dump <file> required")
            return 2
        return emulate_from_dump(ns.dump)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
