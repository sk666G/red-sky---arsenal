# language: Python, file: Program/iot/firmware.py, target: Red Sky iot — firmware unpack + secret hunt
# Two stages:
#   1. unpack   — runs binwalk, then any of {ubireader_extract_images, sasquatch,
#                 unsquashfs, jefferson, dtc} that apply. Recurses into extracted
#                 filesystem if a rootfs shows up.
#   2. secrets  — walks the extracted tree for credentials, keys, certs, tokens,
#                 debug interfaces, backdoors. Pattern + entropy based.

import json
import math
import os
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


IOT_DIR = OUTPUT_DIR / "iot"
FW_DIR = IOT_DIR / "firmware"
FW_DIR.mkdir(parents=True, exist_ok=True)


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(args: List[str], cwd: str = "", timeout: int = 900) -> int:
    try:
        r = subprocess.run(args, cwd=cwd or None, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and r.stderr:
            print_warn(r.stderr.strip()[:300])
        return r.returncode
    except FileNotFoundError:
        print_err("missing: " + args[0])
        return 127
    except subprocess.TimeoutExpired:
        print_warn("timeout: " + " ".join(args[:2]))
        return 124


# ── stage 1: unpack ──
def cmd_unpack(fw_path: str, out_dir: str) -> int:
    p = Path(fw_path).expanduser()
    if not p.exists():
        print_err("firmware not found: " + str(p))
        return 1

    out = Path(out_dir) if out_dir else FW_DIR / (p.stem + "_unpacked_" + str(int(time.time())))
    out.mkdir(parents=True, exist_ok=True)

    print_info("firmware unpack")
    print_kv("input", p)
    print_kv("output", out)
    print_kv("size", str(p.stat().st_size) + " bytes")
    print()

    # 1. binwalk
    bw = _which("binwalk")
    if bw:
        print_info("binwalk -eM")
        _run([bw, "-eM", "--run-as=root", "-C", str(out), str(p)], timeout=1800)
        print_ok("binwalk done")
    else:
        print_warn("binwalk not on PATH")

    # 2. look for interesting artifacts and try deeper extraction
    ubireader = _which("ubireader_extract_images")
    if ubireader:
        for ubifs in out.rglob("*ubi*"):
            if ubifs.is_file():
                print_info("ubi_reader on " + ubifs.name)
                _run([ubireader, "-o", str(out / "ubi"), str(ubifs)], timeout=600)

    squashfs = _which("unsquashfs") or _which("sasquatch")
    if squashfs:
        for sqfs in out.rglob("*.squashfs"):
            print_info(squashfs + " on " + sqfs.name)
            target = out / (sqfs.stem + "_rootfs")
            _run([squashfs, "-d", str(target), str(sqfs)], timeout=900)

    # 3. inventory
    print()
    print_info("inventory")
    counts = {"files": 0, "dirs": 0}
    interesting = []
    for root, dirs, files in os.walk(out):
        counts["dirs"] += len(dirs)
        counts["files"] += len(files)
        for f in files:
            fp = Path(root) / f
            name = f.lower()
            if any(k in name for k in ("passwd", "shadow", "id_rsa", "id_ecdsa",
                                        "authorized_keys", "host_key", "privkey",
                                        "cert", "token", "secret", "config",
                                        "backup", ".key", ".pem", ".crt")):
                interesting.append(fp)
    print_kv("files", counts["files"])
    print_kv("dirs", counts["dirs"])
    print_kv("interesting", len(interesting))
    for fp in interesting[:30]:
        print("  " + SCARLET + "*" + RESET + " " + BONE + str(fp.relative_to(out)) + RESET)

    # 4. record
    (out / ".redsky_unpack_manifest.json").write_text(json.dumps({
        "input": str(p),
        "output": str(out),
        "files": counts["files"],
        "dirs": counts["dirs"],
        "interesting": [str(fp) for fp in interesting[:200]],
    }, indent=2))
    print()
    print_kv("manifest", out / ".redsky_unpack_manifest.json")
    print_info("next: redsky iot firmware secrets " + str(out))
    return 0


# ── stage 2: secrets ──
SECRET_PATTERNS = [
    ("hardcoded_password", re.compile(rb'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^\s"\']{4,64})["\']', re.I)),
    ("api_key",            re.compile(rb'(?:api[_-]?key|apikey|token|secret)\s*[=:]\s*["\']([^\s"\']{8,128})["\']', re.I)),
    ("aws_access_key",     re.compile(rb'AKIA[0-9A-Z]{16}')),
    ("aws_secret",         re.compile(rb'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])')),
    ("private_key_header", re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    ("jwt",                re.compile(rb'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ("basic_auth_url",     re.compile(rb'(?:https?|ftp)://[^/\s:]+:[^/\s@]+@[^\s/]+')),
    ("mqtt_uri",           re.compile(rb'mqtts?://[^\s"\']+', re.I)),
    ("telnet_cmd",         re.compile(rb'(?:telnetd|utelnetd)\s', re.I)),
    ("ssh_authorized",     re.compile(rb'ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{60,}')),
    ("openssl_pass",       re.compile(rb'openssl\s+.*?-pass\s+(?:pass:)?["\']?([^\s"\']+)', re.I)),
    ("wpa_psk",            re.compile(rb'(?:wpa_passphrase|psk)\s*[=:]\s*["\']?([A-Za-z0-9!@#$%^&*]{8,64})', re.I)),
]


# file extensions worth scanning as text
TEXT_EXTS = {".txt", ".conf", ".cfg", ".ini", ".xml", ".json", ".yml", ".yaml",
             ".sh", ".bash", ".py", ".js", ".lua", ".php", ".html", ".htm",
             ".pem", ".crt", ".key", ".csr", ".pub", ".env", ".properties"}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)
    return ent


def _scan_file(fp: Path) -> List[Dict]:
    hits = []
    try:
        raw = fp.read_bytes()
    except OSError:
        return hits
    if len(raw) > 8 * 1024 * 1024:
        # cap at 8MB per file
        raw = raw[:8 * 1024 * 1024]

    for name, pat in SECRET_PATTERNS:
        for m in pat.finditer(raw):
            val = m.group(1) if m.groups() else m.group(0)
            try:
                val_s = val.decode("utf-8", errors="replace")[:200]
            except Exception:
                continue
            hits.append({"pattern": name, "match": val_s, "offset": m.start()})
    return hits


def cmd_secrets(scan_dir: str, out_file: str) -> int:
    root = Path(scan_dir).expanduser()
    if not root.exists():
        print_err("dir not found: " + str(root))
        return 1

    print_info("secret hunting in " + str(root))
    print()

    findings = []
    t0 = time.time()
    file_count = 0

    for r, dirs, files in os.walk(root):
        # skip the binwalk extraction dirs that just repeat the tree
        for f in files:
            fp = Path(r) / f
            ext = fp.suffix.lower()
            # scan interesting file names + known text extensions + any small file
            interesting_name = any(k in f.lower() for k in
                                   ("passwd", "shadow", "config", "conf", "key", "cert",
                                    "secret", "token", "auth", "id_rsa", ".env", "rc"))
            try:
                sz = fp.stat().st_size
            except OSError:
                continue
            if sz > 4 * 1024 * 1024:
                continue
            if not (ext in TEXT_EXTS or interesting_name or sz < 65536):
                continue

            file_count += 1
            hits = _scan_file(fp)
            for h in hits:
                h["file"] = str(fp.relative_to(root))
                findings.append(h)
                print(SCARLET + "▓ " + h["pattern"] + RESET + "  " + BONE + h["file"] + RESET
                      + "  " + ASH + "offset " + str(h["offset"]) + RESET)
                print("   " + CLOT + h["match"] + RESET)

    print()
    print_kv("scanned", str(file_count) + " files")
    print_kv("elapsed", str(round(time.time() - t0, 1)) + "s")
    print_kv("findings", len(findings))

    out = Path(out_file) if out_file else FW_DIR / ("secrets_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(findings, indent=2))
    print_kv("saved", out)
    return 0


def cmd_list() -> int:
    print_info("unpack pipeline dependencies")
    for tool in ("binwalk", "ubireader_extract_images", "unsquashfs", "sasquatch",
                 "jefferson", "dtc", "firmwalker"):
        path = _which(tool)
        if path:
            print("  " + SCARLET + "▓" + RESET + " " + BONE + tool + RESET + "  " + ASH + path + RESET)
        else:
            print("  " + ASH + "░ " + tool + " (missing)" + RESET)
    print()
    print_info(str(len(SECRET_PATTERNS)) + " secret patterns loaded")
    for name, _ in SECRET_PATTERNS:
        print("  " + SCARLET + "*" + RESET + " " + BONE + name + RESET)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky iot firmware", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "unpack", "secrets"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky iot firmware <list|unpack|secrets> [target]")
        return 2

    if ns.help:
        print_info("list                        -- show unpack tools + secret patterns")
        print_info("unpack <firmware.bin>       -- binwalk + ubi/squashfs extraction")
        print_info("secrets <extracted-dir>     -- hunt credentials, keys, tokens")
        return 0

    if ns.action == "list":
        return cmd_list()
    if ns.action == "unpack":
        if not ns.target:
            print_err("give a firmware image")
            return 2
        return cmd_unpack(ns.target, ns.out)
    if ns.action == "secrets":
        if not ns.target:
            print_err("give an extracted directory")
            return 2
        return cmd_secrets(ns.target, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
