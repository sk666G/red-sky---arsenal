# language: Python, file: Program/iot/firmware.py, target: Red Sky IoT — firmware teardown
# Firmware image analysis. Three-stage pipeline:
#
#   1. Carve / extract. If `binwalk` is present, shell to `binwalk -Me`.
#      Otherwise, walk the file, detect known magics (squashfs, gzip, cpio,
#      ubifs, jffs2, ELF), and carve each region to its own file. The pure-
#      Python carve is a fallback — binwalk does it better.
#   2. Secret sweep. Walk the extracted tree looking for:
#        - hardcoded passwords / API keys / bearer tokens
#        - private keys (RSA / EC / ed25519)
#        - /etc/shadow / /etc/passwd entries
#        - hardcoded URLs, IPs, MQTT brokers, Wi-Fi creds (wpa_supplicant.conf)
#        - device vendor strings (buildroot, openwrt identifiers)
#   3. Report. Write findings to a JSON + a human-readable summary.

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


IOT_DIR = OUTPUT_DIR / "iot"
FW_DIR = IOT_DIR / "firmware"


# Known filesystem / archive magics. Each entry is (magic_bytes, offset, name).
MAGICS = [
    (b"hsqs",     0, "squashfs-le"),
    (b"sqsh",     0, "squashfs-be"),
    (b"\x1f\x8b\x08", 0, "gzip"),
    (b"BZh",      0, "bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz"),
    (b"070701",   0, "cpio-newc"),
    (b"070702",   0, "cpio-crc"),
    (b"\x7fELF", 0, "elf"),
    (b"UBI#",     0, "ubifs"),
    (b"\x19\x85", 0, "jffs2-le"),
    (b"\x85\x19", 0, "jffs2-be"),
    (b"\x27\x05\x19\x56", 0, "uimage"),
    (b"\x28\x05\x19\x56", 0, "uimage-old"),
    (b"ANDROID!", 0, "android-boot"),
    (b"\xd0\x0d\xfe\xed", 0, "android-sparse"),
    (b"PK\x03\x04", 0, "zip"),
    (b"\x1f\x9d", 0, "zlib"),
    (b"LZMA",     0, "lzma"),
    (b"\x89LZO\x00\x0d\x0a\x1a\x0a", 0, "lzop"),
]


# Secret patterns. Each is (label, compiled regex).
PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("password_assign",     re.compile(rb"(?i)\b(password|passwd|pwd)\s*[=:]\s*[\x22\x27]?([^\x22\x27\s]{3,64})")),
    ("api_key",             re.compile(rb"(?i)\b(api[_-]?key|apikey|api[_-]?token|access[_-]?token|secret[_-]?key)\s*[=:]\s*[\x22\x27]?([A-Za-z0-9_\-+/=]{8,128})")),
    ("bearer",              re.compile(rb"(?i)bearer\s+([A-Za-z0-9_\-.]{16,})")),
    ("aws_key",             re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("aws_secret",          re.compile(rb"(?i)aws_?secret_?access_?key[\x22\x27]?\s*[=:]\s*[\x22\x27]?([A-Za-z0-9/+=]{40})")),
    ("private_key_rsa",     re.compile(rb"-----BEGIN RSA PRIVATE KEY-----")),
    ("private_key_ec",      re.compile(rb"-----BEGIN EC PRIVATE KEY-----")),
    ("private_key_openssh", re.compile(rb"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("private_key_generic", re.compile(rb"-----BEGIN (?:PRIVATE|ENCRYPTED) KEY-----")),
    ("shadow_root",         re.compile(rb"^root:[^:]{13,}:")),
    ("shadow_hash",         re.compile(rb"\b[\w.$-]+:\$[156]\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+")),
    ("wpa_psk",             re.compile(rb"psk\s*=\s*[\x22]?([0-9a-fA-F]{32,64})[\x22]?")),
    ("wifi_ssid",           re.compile(rb"ssid\s*=\s*[\x22]([^\x22\n]{1,64})[\x22]")),
    ("mqtt_url",            re.compile(rb"mqtts?://([A-Za-z0-9.\-]+(?::\d+)?)")),
    ("http_url",            re.compile(rb"https?://([A-Za-z0-9.\-]+(?::\d+)?)")),
    ("ipv4",                re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("email",               re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("jwt",                 re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("env_flag",            re.compile(rb"(?i)\b(debug|dev|test|verbose)\s*=\s*(1|true|yes)")),
    ("telnet_port",         re.compile(rb"(?i)telnetd|busybox\s+telnetd")),
    ("ssh_authorized",      re.compile(rb"ssh-rsa\s+AAAA[A-Za-z0-9+/=]{100,}")),
    ("openwrt",             re.compile(rb"(OpenWrt|LEDE|BARRIER BREAKER|CHAOS CALMER|ATTITUDE ADJUSTMENT)")),
    ("buildroot",           re.compile(rb"buildroot[- ]?(\d{4}\.\d{2}(\.\d+)?)")),
    ("ddwrt",               re.compile(rb"DD-WRT")),
    ("tplink",              re.compile(rb"TP-LINK|TP-Link")),
    ("dlink",               re.compile(rb"D-Link")),
    ("hikvision",           re.compile(rb"Hikvision|HIKVISION")),
    ("dahua",               re.compile(rb"Dahua|DAHUA")),
    ("samsung_magicinfo",   re.compile(rb"MagicInfo")),
]


# Files / dirs to skip during the sweep — huge binaries whose noise buries signal.
SKIP_EXT = {".so", ".ko", ".bin", ".img", ".dat", ".pkg", ".pcap"}
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB


# ── carve ───────────────────────────────────────────────────────────────────

def carve(raw: bytes, out_dir: Path) -> List[Dict]:
    """Walk the buffer, cut each region starting at a magic into its own file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    n = len(raw)
    i = 0
    seen_offsets = set()
    while i < n:
        matched = None
        for magic, offset, name in MAGICS:
            if raw[i:i+len(magic)] == magic:
                matched = (magic, offset, name)
                break
        if matched and i not in seen_offsets:
            magic, _, name = matched
            # find the next magic as an approximation of end
            j = i + len(magic)
            end = n
            for magic2, _, _ in MAGICS:
                k = raw.find(magic2, j)
                if k != -1 and k < end:
                    end = k
            region = raw[i:end]
            # gzip / cpio etc are small — cap
            if len(region) > 4 * 1024 * 1024:
                region = region[:4 * 1024 * 1024]
            fn = out_dir / (format(i, "08x") + "_" + name + ".bin")
            fn.write_bytes(region)
            seen_offsets.add(i)
            results.append({"offset": i, "magic": name, "size": len(region), "file": str(fn)})
            i = end
        else:
            i += 1
            # speed up — step faster between magics
            if i % 4096 == 0 and not matched:
                next_magic_offset = n
                for magic, _, _ in MAGICS:
                    k = raw.find(magic, i)
                    if k != -1 and k < next_magic_offset:
                        next_magic_offset = k
                if next_magic_offset > i:
                    i = next_magic_offset
    return results


# ── extraction ──────────────────────────────────────────────────────────────

def run_binwalk(fw: Path, out_dir: Path) -> Optional[Path]:
    bw = shutil.which("binwalk")
    if not bw:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    print_info("binwalk -Me " + str(fw))
    try:
        p = subprocess.run(
            [bw, "-e", "--directory", str(out_dir), str(fw)],
            capture_output=True, text=True, timeout=1800,
        )
        if p.returncode != 0:
            print_warn("binwalk rc=" + str(p.returncode))
        # binwalk -Me writes into <out_dir>/_<fw>.<ext>.extracted/
        candidates = list(out_dir.glob("_*"))
        for c in candidates:
            if c.is_dir() and "extracted" in c.name:
                return c
        return out_dir
    except subprocess.TimeoutExpired:
        print_warn("binwalk timeout")
        return out_dir
    except Exception as e:
        print_warn("binwalk failed: " + str(e))
        return None


# ── sweep ───────────────────────────────────────────────────────────────────

def _should_skip(p: Path) -> bool:
    if p.is_dir():
        return False
    if p.suffix.lower() in SKIP_EXT:
        try:
            return p.stat().st_size > 512 * 1024
        except OSError:
            return True
    try:
        if p.stat().st_size > MAX_FILE_SIZE:
            return True
    except OSError:
        return True
    return False


def _scan_text_blob(blob: bytes) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for label, rx in PATTERNS:
        try:
            for m in rx.finditer(blob):
                vals = [g.decode("utf-8", errors="replace") if isinstance(g, bytes) else g
                        for g in m.groups()] if m.groups() else [m.group(0).decode("utf-8", errors="replace")]
                val = next((v for v in vals if v), "")
                if not val and m.group(0):
                    val = m.group(0).decode("utf-8", errors="replace")
                if val:
                    found.setdefault(label, []).append(val[:200])
        except Exception:
            continue
    return found


def sweep(root: Path) -> List[Dict]:
    findings = []
    count = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            p = Path(dirpath) / fn
            if _should_skip(p):
                continue
            try:
                blob = p.read_bytes()
            except Exception:
                continue
            count += 1
            hits = _scan_text_blob(blob)
            if hits:
                findings.append({"file": str(p), "relative": str(p.relative_to(root)), "findings": hits})
    return findings


# ── commands ────────────────────────────────────────────────────────────────

def cmd_analyze(fw_path: str, use_binwalk: bool) -> int:
    fw = Path(fw_path)
    if not fw.exists():
        print_err("firmware not found: " + fw_path)
        return 1
    FW_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = FW_DIR / (fw.stem + "_" + ts)
    base.mkdir(parents=True, exist_ok=True)
    raw_dir = base / "carve"
    root = None

    print_info("firmware analyze")
    print_kv("image", fw)
    print_kv("size", str(fw.stat().st_size) + " bytes")
    print_kv("workdir", base)
    print()

    if use_binwalk:
        bw_out = run_binwalk(fw, base)
        if bw_out:
            root = bw_out
            print_ok("binwalk extracted to " + str(bw_out))

    if root is None:
        print_info("carving magics (pure-python fallback)")
        raw = fw.read_bytes()
        carved = carve(raw, raw_dir)
        print_kv("regions", len(carved))
        for c in carved[:20]:
            print("  " + ASH + format(c["offset"], "08x") + RESET + " " + BONE + c["magic"] + RESET + " " + str(c["size"]) + "B")
        if len(carved) > 20:
            print("  " + ASH + "... +" + str(len(carved) - 20) + " more" + RESET)
        root = base  # sweep the whole workdir including the original image

    print()
    print_info("secret sweep over " + str(root))
    findings = sweep(root)

    # summary by label
    label_counts: Dict[str, int] = {}
    for f in findings:
        for label in f["findings"]:
            label_counts[label] = label_counts.get(label, 0) + len(f["findings"][label])

    print()
    for label, n in sorted(label_counts.items(), key=lambda kv: -kv[1]):
        print("  " + SCARLET + label.ljust(20) + RESET + " " + BONE + str(n) + RESET)

    report = {
        "image": str(fw),
        "size": fw.stat().st_size,
        "root": str(root),
        "label_counts": label_counts,
        "findings": findings,
    }
    out = base / "report.json"
    out.write_text(json.dumps(report, indent=2))
    print()
    print_kv("files scanned", len(findings))
    print_kv("report", out)
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "help"
    rest = args[1:] if args else []

    if sub in ("-h", "--help", "help"):
        print_info("redsky iot firmware <sub-command>")
        print_info("")
        print_info("  analyze --image FILE [--no-binwalk]")
        print_info("      carve + extract + secret sweep; writes report.json")
        return 0

    if sub == "analyze":
        p = argparse.ArgumentParser(prog="redsky iot firmware analyze", add_help=False)
        p.add_argument("--image", required=False, default="")
        p.add_argument("--no-binwalk", action="store_true")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky iot firmware analyze --image FILE [--no-binwalk]")
            return 2
        if not ns.image:
            print_err("--image required")
            return 2
        return cmd_analyze(ns.image, use_binwalk=not ns.no_binwalk)

    print_err("unknown firmware sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
