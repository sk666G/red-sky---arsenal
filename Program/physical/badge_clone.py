# language: Python, file: Program/physical/badge_clone.py, target: Red Sky physical — badge clone workflow
# Three stages: read, decode, write/emulate. Uses the proxmark3 client for
# 125kHz (HID Prox / EM4100 / Indala) and 13.56MHz (iCLASS / MIFARE Classic /
# DESFire) badges, plus a decode helper that turns the raw hex into the
# facility code + card number pair used by HID formats.

import json
import re
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
BADGE_DIR = PH_DIR / "badges"
BADGE_DIR.mkdir(parents=True, exist_ok=True)


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(args: List[str], timeout: int = 120) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and r.stderr:
            print_warn(r.stderr.strip()[:200])
        return r.stdout
    except FileNotFoundError:
        print_err("missing: " + args[0])
        return ""
    except subprocess.TimeoutExpired:
        return ""


def _pm3() -> str:
    return _which("pm3") or _which("proxmark3") or ""


def pm3(script: str, timeout: int = 60) -> str:
    pm = _pm3()
    if not pm:
        print_err("no proxmark3 client on PATH")
        return ""
    return _run([pm, "-c", script], timeout=timeout)


# ── stage 1: read ──
def read_125khz_hid() -> Optional[Dict]:
    """Read a HID Prox badge (or EM4100 / Indala). Returns decoded fields."""
    print_info("lf hid read")
    out = pm3("lf hid read", timeout=45)
    if not out:
        return None
    print(out)

    # HID H10301 format: 26-bit. Facility = bits 1-8, Card = bits 9-24, parity = 25,26
    # pm3 output looks like: "HID Prox - 2006ec1234 (26)  FC: 123  CN: 45678"
    fc = None
    cn = None
    uid = None
    raw = None

    m = re.search(r"FC[:\s]+(\d+)", out)
    if m:
        fc = int(m.group(1))
    m = re.search(r"CN[:\s]+(\d+)", out)
    if m:
        cn = int(m.group(1))
    m = re.search(r"HID Prox\s*-\s*([0-9a-fA-F]+)", out)
    if m:
        raw = m.group(1)
    m = re.search(r"UID[:\s]+([0-9a-fA-F ]+)", out)
    if m:
        uid = m.group(1).strip()

    return {"format": "HID H10301 (26-bit)", "facility_code": fc, "card_number": cn,
            "raw": raw, "uid": uid, "tool_output": out}


def read_125khz_em4100() -> Optional[Dict]:
    print_info("lf em 410x_read")
    out = pm3("lf em 410x_read", timeout=45)
    if not out:
        return None
    print(out)
    m = re.search(r"EM 410x ID ([0-9a-fA-F]+)", out)
    eid = m.group(1) if m else None
    return {"format": "EM4100", "id": eid, "tool_output": out}


def read_iclass() -> Optional[Dict]:
    print_info("hf iclass reader")
    out = pm3("hf iclass reader", timeout=60)
    if not out:
        return None
    print(out)
    csn = None
    m = re.search(r"CSN[:\s]+([0-9a-fA-F ]+)", out)
    if m:
        csn = m.group(1).strip()
    m = re.search(r"Credential[:\s]+(\d+)", out)
    cred = int(m.group(1)) if m else None
    return {"format": "iCLASS", "csn": csn, "credential": cred, "tool_output": out}


def read_mifare_classic_uid() -> Optional[Dict]:
    print_info("hf 14a reader")
    out = pm3("hf 14a reader", timeout=45)
    if not out:
        return None
    print(out)
    uid = None
    m = re.search(r"UID[:\s]+([0-9a-fA-F ]+)", out)
    if m:
        uid = m.group(1).strip()
    return {"format": "MIFARE Classic", "uid": uid, "tool_output": out}


# ── stage 2: decode ──
def decode_hid(raw_hex: str) -> Dict:
    """Decode a raw HID Prox hex string (from pm3 'lf hid read' output) into
    facility code + card number. Handles the common bit lengths:
      26-bit H10301  -> FC 8 bits, CN 16 bits
      35-bit H10306  -> FC 12 bits, CN 20 bits
      37-bit H10302  -> no FC, CN 35 bits (corporate 1000)
    raw_hex is the em4100-encoded hex of the raw bits (msb first)."""
    h = raw_hex.strip().replace(" ", "").lower()
    try:
        val = int(h, 16)
    except ValueError:
        return {"error": "invalid hex: " + raw_hex}

    bit_len = len(h) * 4
    # trim leading zeros to find the actual bit length
    stripped = h.lstrip("0")
    real_bits = len(stripped) * 4

    # H10301 (26-bit): layout = [1p][8 FC][16 CN][1p]
    # the facility code sits in bits 17..24 (1-indexed from MSB, 26-bit)
    out = {"raw_hex": h, "bit_length_guess": real_bits}

    if real_bits <= 26:
        # 26-bit H10301
        fc = (val >> 17) & 0xFF
        cn = (val >> 1) & 0xFFFF
        out.update({"format": "H10301 (26-bit)", "facility_code": fc, "card_number": cn})
    elif real_bits <= 35:
        # H10306 (35-bit): FC is 12 bits, CN is 20 bits
        fc = (val >> 21) & 0xFFF
        cn = (val >> 1) & 0xFFFFF
        out.update({"format": "H10306 (35-bit)", "facility_code": fc, "card_number": cn})
    else:
        # H10302 (37-bit): no facility, CN is 35 bits
        cn = (val >> 1) & ((1 << 35) - 1)
        out.update({"format": "H10302 (37-bit, corporate 1000)", "facility_code": None, "card_number": cn})

    return out


def encode_hid_26(fc: int, cn: int) -> str:
    """Encode facility + card into a 26-bit H10301 value, with even/odd parity.
    Returns the hex string ready to feed pm3: lf hid clone <hex>."""
    if fc < 0 or fc > 0xFF:
        print_warn("facility code should be 0-255 for 26-bit")
    if cn < 0 or cn > 0xFFFF:
        print_warn("card number should be 0-65535 for 26-bit")

    # structure: p0 | fc[8] | cn[16] | p1
    # p0 = even parity over bits 2..13 (fc[7:0] + cn[15:12])
    # p1 = odd parity  over bits 14..25
    body = ((fc & 0xFF) << 16) | (cn & 0xFFFF)  # 24 bits
    # build the 24-bit body as bits 24..1 of the 26-bit word
    word = body << 1  # room for p1 at bit 0
    # even parity of top 12 bits of body (fc + top 4 of cn)
    top12 = (body >> 12) & 0xFFF
    p0 = bin(top12).count("1") % 2  # 0 -> even
    # odd parity of bottom 12 bits of body (low 12 of cn)
    bot12 = body & 0xFFF
    p1 = 1 - (bin(bot12).count("1") % 2)  # 1 -> odd
    word |= p0 << 25
    word |= p1

    return "{:07x}".format(word)


# ── stage 3: write / emulate ──
def write_hid_26(fc: int, cn: int, t5577: bool) -> int:
    raw = encode_hid_26(fc, cn)
    print_info("writing HID 26-bit to tag (FC=" + str(fc) + " CN=" + str(cn) + ")")
    print_kv("encoded hex", raw)
    if t5577:
        script = "lf hid clone --r " + raw + " f"
    else:
        script = "lf hid clone " + raw
    out = pm3(script, timeout=90)
    print(out)
    print_ok("clone complete (verify with: redsky physical badge read --type hid)")
    return 0


def emulate_hid_26(fc: int, cn: int) -> int:
    raw = encode_hid_26(fc, cn)
    pm = _pm3()
    if not pm:
        return 2
    print_info("emulating HID 26-bit FC=" + str(fc) + " CN=" + str(cn))
    try:
        subprocess.run([pm, "-c", "lf hid sim " + raw])
    except KeyboardInterrupt:
        print_info("emulation stopped")
    return 0


def emulate_em4100(eid: str) -> int:
    pm = _pm3()
    if not pm:
        return 2
    print_info("emulating EM4100 id=" + eid)
    try:
        subprocess.run([pm, "-c", "lf em 410x sim " + eid])
    except KeyboardInterrupt:
        print_info("emulation stopped")
    return 0


# ── CLI ──
def cmd_read(badge_type: str, out_name: str) -> int:
    card = None
    if badge_type == "hid":
        card = read_125khz_hid()
    elif badge_type == "em":
        card = read_125khz_em4100()
    elif badge_type == "iclass":
        card = read_iclass()
    elif badge_type == "mifare":
        card = read_mifare_classic_uid()
    else:
        print_err("unknown type: " + badge_type + " (hid | em | iclass | mifare)")
        return 2

    if not card:
        return 1

    out = BADGE_DIR / ((out_name or badge_type + "_" + str(int(time.time()))) + ".json")
    out.write_text(json.dumps(card, indent=2))
    print()
    print_ok("saved " + str(out))
    return 0


def cmd_decode(raw_hex: str, out_name: str) -> int:
    d = decode_hid(raw_hex)
    if "error" in d:
        print_err(d["error"])
        return 1
    print_info("decoded HID")
    for k, v in d.items():
        print("  " + ARTERY + k + RESET + "  " + BONE + str(v) + RESET)
    out = BADGE_DIR / ((out_name or "decode_" + str(int(time.time()))) + ".json")
    out.write_text(json.dumps(d, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_encode(fc: int, cn: int, out_name: str) -> int:
    raw = encode_hid_26(fc, cn)
    print_info("encoded HID 26-bit")
    print_kv("facility_code", fc)
    print_kv("card_number", cn)
    print_kv("hex", raw)
    out = BADGE_DIR / ((out_name or "encode_" + str(int(time.time()))) + ".json")
    out.write_text(json.dumps({"facility_code": fc, "card_number": cn, "hex": raw}, indent=2))
    print_kv("saved", out)
    return 0


def cmd_write(fc: int, cn: int, t5577: bool) -> int:
    return write_hid_26(fc, cn, t5577)


def cmd_emulate(badge_type: str, fc: int, cn: int, eid: str) -> int:
    if badge_type == "hid":
        return emulate_hid_26(fc, cn)
    if badge_type == "em":
        if not eid:
            print_err("need --eid for EM4100 emulation")
            return 2
        return emulate_em4100(eid)
    print_err("unknown emulate type: " + badge_type)
    return 2


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky physical badge_clone", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="read",
                   choices=["read", "decode", "encode", "write", "emulate"])
    p.add_argument("--type", default="hid", choices=["hid", "em", "iclass", "mifare"])
    p.add_argument("--raw", default="")
    p.add_argument("--fc", type=int, default=0)
    p.add_argument("--cn", type=int, default=0)
    p.add_argument("--eid", default="")
    p.add_argument("--t5577", action="store_true", help="write to a T5577 blank (rewritable)")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky physical badge_clone <read|decode|encode|write|emulate> [opts]")
        return 2

    if ns.help:
        print_info("read    --type hid|em|iclass|mifare   -- read a badge")
        print_info("decode  --raw 2006ec1234               -- decode raw hex into FC/CN")
        print_info("encode  --fc 123 --cn 45678            -- encode FC/CN to raw hex")
        print_info("write   --fc 123 --cn 45678 [--t5577]  -- write to a magic/T5577 tag")
        print_info("emulate --type hid --fc 123 --cn 45678 -- proxmark sim mode")
        return 0

    if ns.action == "read":
        return cmd_read(ns.type, ns.out)
    if ns.action == "decode":
        if not ns.raw:
            print_err("--raw <hex> required")
            return 2
        return cmd_decode(ns.raw, ns.out)
    if ns.action == "encode":
        return cmd_encode(ns.fc, ns.cn, ns.out)
    if ns.action == "write":
        return cmd_write(ns.fc, ns.cn, ns.t5577)
    if ns.action == "emulate":
        return cmd_emulate(ns.type, ns.fc, ns.cn, ns.eid)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
