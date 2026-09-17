# language: Python, file: Program/rfid/reader.py, target: Red Sky rfid — nfcpy reader
# Talks to an ACR122U / PN532 / any reader supported by nfcpy over USB.
# Detects tags, reads UID, dumps NDEF, identifies card type.

import binascii
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


RFID_DIR = OUTPUT_DIR / "rfid"


def _nfcpy_available() -> bool:
    try:
        import nfc  # noqa: F401
        return True
    except ImportError:
        return False


def _tag_info(tag) -> Dict:
    """Extract as much as we can from an nfcpy tag object."""
    info = {
        "type": type(tag).__name__,
        "identifier": binascii.hexlify(tag.identifier).decode() if hasattr(tag, "identifier") else "",
        "product": getattr(tag, "product", ""),
    }
    if hasattr(tag, "ndef") and tag.ndef:
        try:
            records = []
            for rec in tag.ndef.records:
                records.append({
                    "tnf": rec.tnf,
                    "type": binascii.hexlify(rec.type).decode() if isinstance(rec.type, bytes) else str(rec.type),
                    "text": rec.text if hasattr(rec, "text") else "",
                    "data": binascii.hexlify(rec.data).decode() if hasattr(rec, "data") and isinstance(rec.data, bytes) else "",
                })
            info["ndef_records"] = records
        except Exception as e:
            info["ndef_error"] = str(e)
    return info


def cmd_list_readers() -> int:
    if not _nfcpy_available():
        print_err("nfcpy not installed")
        print_info("  pip install --break-system-packages nfcpy")
        return 1
    import nfc
    try:
        readers = nfc.ContactlessFrontend("usb")
    except Exception as e:
        print_warn(f"no USB reader detected: {e}")
        print_info("plug in an ACR122U, PN532, or other nfcpy-compatible reader")
        return 1
    info = readers.device
    print_ok("reader attached")
    print_kv("chipset", info.chipset)
    print_kv("firmware", info.version)
    print_kv("connection", str(readers.device))
    readers.close()
    return 0


def cmd_read(duration: int = 10, output: bool = True) -> int:
    if not _nfcpy_available():
        print_err("nfcpy not installed")
        return 1
    import nfc

    RFID_DIR.mkdir(parents=True, exist_ok=True)
    print_info(f"listening for NFC tags for {duration}s")
    print_info("place a tag on the reader...")
    print()

    collected: List[Dict] = []

    def on_connect(tag):
        info = _tag_info(tag)
        collected.append(info)
        print(f"  {ARTERY}▓{RESET} {BONE}{info['type']:<24}{RESET} "
              f"{SCARLET}UID {info['identifier']}{RESET}")
        if info.get("product"):
            print(f"      {ASH}product: {info['product']}{RESET}")
        for rec in info.get("ndef_records", []):
            txt = rec.get("text") or rec.get("data", "")
            print(f"      {ARTERY}▶{RESET} {BONE}{txt[:80]}{RESET}")
        return False  # don't stay on the tag

    try:
        with nfc.ContactlessFrontend("usb") as clf:
            clf.connect(rdwr={"on-connect": on_connect},
                        llcp={"on-connect": on_connect},
                        terminate=lambda: time.time() > _start + duration
                        if (_start := time.time()) else False)
    except Exception as e:
        print_err(f"reader error: {e}")
        return 1

    if output and collected:
        out = RFID_DIR / f"read_{int(time.time())}.json"
        out.write_text(json.dumps(collected, indent=2))
        print()
        print_kv("tags read", len(collected))
        print_kv("saved", out)
    elif not collected:
        print_warn("no tags detected")
    return 0


def cmd_emulate(identifier_hex: str) -> int:
    """Emulate a card with the given UID. Requires a reader that supports card emulation."""
    if not _nfcpy_available():
        print_err("nfcpy not installed")
        return 1
    import nfc
    try:
        uid = bytes.fromhex(identifier_hex.replace(":", "").replace(" ", ""))
    except ValueError:
        print_err("identifier must be hex")
        return 1
    if not (4 <= len(uid) <= 10):
        print_err("UID must be 4 to 10 bytes")
        return 1

    print_info(f"emulating card UID {uid.hex().upper()}")
    print_info("CTRL+C to stop")

    try:
        with nfc.ContactlessFrontend("usb") as clf:
            target = nfc.clf.RemoteTarget("106A")
            target.sens_res = bytearray.fromhex("4400")
            target.sdd_res = uid
            target.sel_res = bytearray.fromhex("00")
            clf.listen(target, terminate=lambda: False)
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    except Exception as e:
        print_err(f"emulation failed: {e}")
        print_info("not all readers support card emulation over USB")
        return 1
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky rfid read <list|dump|emulate> [args]")
        print_err("  list                     show attached reader")
        print_err("  dump [--duration N]      read NFC tags")
        print_err("  emulate <UID-hex>        emulate a card")
        return 2
    sub = args[0].lower()
    if sub == "list":
        return cmd_list_readers()
    if sub == "dump" or sub == "read":
        dur = 10
        if "--duration" in args:
            i = args.index("--duration")
            if i + 1 < len(args):
                dur = int(args[i + 1])
        return cmd_read(dur)
    if sub == "emulate":
        if len(args) < 2:
            print_err("emulate needs a UID")
            return 2
        return cmd_emulate(args[1])
    print_err(f"unknown reader sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
