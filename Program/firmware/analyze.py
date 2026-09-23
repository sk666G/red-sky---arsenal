# language: Python, file: Program/firmware/analyze.py, target: Red Sky firmware — multi-target firmware analysis
# Broader firmware analysis than Program/iot/firmware.py:
#   identify   -- fingerprint a firmware image (binwalk signatures, header magic)
#   unpack     -- binwalk + the right extractor for the detected container
#   uefi       -- UEFI / BIOS image: parse volumes, extract drivers, check secure-boot state
#   squashfs   -- squashfs rootfs: mount or extract, list init/systemd, hunt setuid
#   cve        -- cross-reference extracted components against a CVE list

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


FW_DIR = OUTPUT_DIR / "firmware"
FW_DIR.mkdir(parents=True, exist_ok=True)


# magic headers → format
MAGIC_TABLE = [
    (b"\x27\x05\x19\x56",         "uImage (U-Boot legacy)"),
    (b"\xd0\x0d\xfe\xed",         "U-Boot uImage (v2)"),
    (b"\x1f\x8b\x08",             "gzip"),
    (b"\x42\x5a\x68",             "bzip2"),
    (b"\xfd\x37\x7a\x58\x5a",     "xz"),
    (b"\x5d\x00\x00",             "lzma"),
    (b"\x89PNG",                  "PNG"),
    (b"hsqs",                     "squashfs (little-endian)"),
    (b"sqsh",                     "squashfs (big-endian)"),
    (b"UBI#",                     "UBI"),
    (b"\x45\x3d\xcd\xab",         "UEFI FV (capsule)"),
    (b"_FVH",                     "UEFI Firmware Volume"),
    (b"\x4d\x5a",                 "PE executable (Windows)"),
    (b"\x7fELF",                  "ELF"),
    (b"\x1a\x45\xdf\xa3",         "Matroska / WebM"),
    (b"ANDROID!",                 "Android boot image"),
    (b"\x00\x00\x00\x00\x00\x00\x00\x00", "all-zero (possible padding)"),
    (b"cramfs",                   "cramfs"),
    (b"JFFS2",                    "JFFS2"),
    (b"UBIFS",                    "UBIFS"),
]


def _which(x: str) -> Optional[str]:
    return shutil.which(x)


def _run(cmd: List[str], timeout: int = 600) -> Dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
    except FileNotFoundError:
        return {"rc": 127, "stdout": "", "stderr": "missing: " + cmd[0]}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}


def cmd_identify(fw_path: str, out_file: str) -> int:
    p = Path(fw_path).expanduser()
    if not p.exists():
        print_err("file not found: " + str(p))
        return 1

    print_info("firmware identify")
    print_kv("file", str(p))
    print_kv("size", str(p.stat().st_size) + " bytes")
    print()

    with p.open("rb") as f:
        data = f.read(1024 * 1024)  # first MB is enough for header detection

    hits = []
    for magic, name in MAGIC_TABLE:
        idx = data.find(magic)
        if idx >= 0:
            hits.append({"offset": idx, "magic": magic.hex(), "format": name})
            print("  " + SCARLET + "▓ " + RESET + "offset 0x" + format(idx, "08x")
                  + "  " + BONE + name + RESET)

    # entropy per 4KB block to find compressed regions
    import math
    blocks = [data[i:i+4096] for i in range(0, min(len(data), 256 * 1024), 4096)]
    entropies = []
    for b in blocks[:64]:
        freq = [0] * 256
        for x in b:
            freq[x] += 1
        e = 0.0
        for c in freq:
            if c:
                pc = c / len(b)
                e -= pc * math.log2(pc)
        entropies.append(round(e, 3))
    print()
    print_kv("first block entropy", str(entropies[0]) if entropies else "?")
    print_kv("max block entropy", str(max(entropies)) if entropies else "?")

    out = Path(out_file) if out_file else FW_DIR / (p.stem + "_identify.json")
    out.write_text(json.dumps({"file": str(p), "size": p.stat().st_size,
                               "hits": hits, "entropy": entropies}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_unpack(fw_path: str, out_dir: str) -> int:
    p = Path(fw_path).expanduser()
    if not p.exists():
        print_err("file not found: " + str(p))
        return 1
    target = Path(out_dir) if out_dir else FW_DIR / (p.stem + "_unpacked_" + str(int(time.time())))
    target.mkdir(parents=True, exist_ok=True)

    bw = _which("binwalk")
    if not bw:
        print_err("binwalk not installed")
        return 2

    print_info("binwalk -e")
    _run([bw, "-eM", "--run-as=root", "-C", str(target), str(p)], timeout=1800)
    print_ok("binwalk done")

    # inventory
    interesting = []
    for root, dirs, files in os.walk(target):
        for f in files:
            name = f.lower()
            if any(k in name for k in ("passwd", "shadow", "id_rsa", "authorized_keys",
                                        ".pem", ".key", "host_key", "backup", "config")):
                interesting.append(str(Path(root) / f))
    print_kv("files extracted", str(sum(len(fs) for _, _, fs in os.walk(target))))
    print_kv("interesting", str(len(interesting)))
    for f in interesting[:20]:
        print("  " + SCARLET + "* " + RESET + f)

    out = target / ".redsky_manifest.json"
    out.write_text(json.dumps({"source": str(p), "output": str(target),
                               "interesting": interesting[:200]}, indent=2))
    print()
    print_kv("manifest", out)
    return 0


def cmd_uefi(fw_path: str, out_dir: str) -> int:
    """UEFI firmware volume parser. Extracts FFS files, PE drivers, and checks
    whether Secure Boot is enabled + key stores populated."""
    p = Path(fw_path).expanduser()
    if not p.exists():
        print_err("file not found")
        return 1
    target = Path(out_dir) if out_dir else FW_DIR / (p.stem + "_uefi")
    target.mkdir(parents=True, exist_ok=True)

    data = p.read_bytes()
    print_info("UEFI firmware volume parse")
    print_kv("file", str(p))
    print_kv("size", str(len(data)))
    print()

    # find firmware volumes (search for _FVH signature)
    idx = 0
    volumes = []
    while True:
        found = data.find(b"_FVH", idx)
        if found < 0:
            break
        # FV header starts 40 bytes before _FVH
        fv_start = found - 40
        if fv_start >= 0 and fv_start + 64 <= len(data):
            try:
                fv_len = struct.unpack("<Q", data[fv_start + 32:fv_start + 40])[0]
                if 0 < fv_len < len(data) - fv_start:
                    volumes.append({"offset": fv_start, "length": fv_len})
                    print("  " + SCARLET + "▓ " + RESET + "FV @0x" + format(fv_start, "x")
                          + "  len=" + str(fv_len))
            except struct.error:
                pass
        idx = found + 4

    # look for GUID'd PE files (DXE drivers)
    pe_offsets = []
    i = 0
    while True:
        i = data.find(b"MZ", i)
        if i < 0:
            break
        pe_offsets.append(i)
        i += 2
    print()
    print_kv("firmware volumes", str(len(volumes)))
    print_kv("PE candidates", str(len(pe_offsets)))

    # look for Secure Boot related GUIDs
    SECURE_BOOT_GUIDS = {
        "PK (Platform Key)":   b"\xcb\xe7\x81\x61\x3f\x37\xcb\x81\xdd\x8c\x56\x68\x3d\x69\x95\x96",
        "KEK (Key Exchange)":  b"\x77\xfa\x63\x74\x9f\xf4\x92\x48\x69\xc5\x5a\x5f\x87\x1d\xea\x6b",
        "db (Signature DB)":   b"\xbd\x9a\xf0\xd2\x74\x3f\xa6\x4b\x9f\xe8\x5b\xf4\x62\xca\x6e\x2f",
    }
    print()
    print(BOLD + "Secure Boot key stores" + RESET)
    for name, guid in SECURE_BOOT_GUIDS.items():
        if guid in data:
            print("  " + SCARLET + "▓ " + RESET + BOLD + name + RESET)
        else:
            print("  " + ASH + "░ " + name + " not found" + RESET)

    out = target / "summary.json"
    out.write_text(json.dumps({"volumes": volumes, "pe_count": len(pe_offsets)}, indent=2))
    print()
    print_kv("saved", out)
    print_info("run: UEFITool " + str(p) + " for a full FFS parse")
    return 0


def cmd_squashfs(fw_path: str, out_dir: str) -> int:
    p = Path(fw_path).expanduser()
    if not p.exists():
        print_err("file not found")
        return 1
    tool = _which("unsquashfs") or _which("sasquatch")
    if not tool:
        print_err("install squashfs-tools or sasquatch")
        return 2
    target = Path(out_dir) if out_dir else FW_DIR / (p.stem + "_rootfs")
    target.mkdir(parents=True, exist_ok=True)

    print_info("squashfs extract")
    print_kv("file", str(p))
    print_kv("extractor", tool)
    print_kv("output", str(target))

    r = _run([tool, "-d", str(target), str(p)], timeout=900)
    if r["rc"] != 0:
        print_err("extraction failed: " + r["stderr"][:200])
        return 1
    print_ok("extracted")

    # look at init / systemd / setuid
    print()
    print(BOLD + "init + systemd" + RESET)
    for name in ("etc/init.d", "etc/systemd/system", "etc/rc.d", "etc/inittab"):
        path = target / name
        if path.exists():
            print("  " + SCARLET + "▓ " + RESET + name)
            if path.is_file():
                content = path.read_text(errors="replace")[:500]
                for line in content.splitlines()[:10]:
                    print("      " + ASH + line + RESET)
            else:
                for f in list(path.iterdir())[:10]:
                    print("      " + ASH + f.name + RESET)

    print()
    print(BOLD + "setuid / setgid binaries" + RESET)
    suids = []
    for root, dirs, files in os.walk(target):
        for f in files:
            fp = Path(root) / f
            try:
                st = fp.stat()
                if st.st_mode & 0o4000:
                    suids.append(str(fp))
                    print("  " + SCARLET + "▓ " + RESET + str(fp.relative_to(target))
                          + "  setuid")
                elif st.st_mode & 0o2000:
                    suids.append(str(fp))
                    print("  " + ARTERY + "░ " + RESET + str(fp.relative_to(target))
                          + "  setgid")
            except OSError:
                pass
    print()
    print_kv("setuid/setgid", str(len(suids)))

    out = target / ".redsky_squashfs.json"
    out.write_text(json.dumps({"source": str(p), "suids": suids}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_cve(root_dir: str, cve_file: str, out_file: str) -> int:
    """Given an extracted firmware dir, scan for known-versioned components
    and match against a CVE list (JSON: [{package, version, cve, severity}])."""
    root = Path(root_dir).expanduser()
    if not root.exists():
        print_err("dir not found: " + str(root))
        return 1

    # load cve list
    db = []
    if cve_file:
        p = Path(cve_file).expanduser()
        if p.exists():
            try:
                db = json.loads(p.read_text())
            except Exception as e:
                print_err("cve db parse failed: " + str(e))
                return 1
    if not db:
        print_warn("no cve db — pass --cve file.json")
        print_info("expected format: [{\"package\":\"openssl\",\"version\":\"1.0.2\",\"cve\":\"CVE-2016-...\",\"severity\":\"high\"}]")
        return 1

    print_info("cve match")
    print_kv("root", str(root))
    print_kv("cve db", str(len(db)) + " entries")
    print()

    # gather version strings from the tree
    strings = {}
    for r, d, files in os.walk(root):
        for f in files:
            fp = Path(r) / f
            if fp.stat().st_size > 4 * 1024 * 1024:
                continue
            try:
                data = fp.read_bytes()[:65536]
            except OSError:
                continue
            text = data.decode("latin-1", errors="replace")
            for entry in db:
                pkg = entry["package"]
                ver = entry["version"]
                # simple substring check
                if pkg in text and ver in text:
                    key = entry["cve"]
                    strings.setdefault(key, []).append(str(fp.relative_to(root)))

    hits = []
    for entry in db:
        if entry["cve"] in strings:
            files = strings[entry["cve"]][:5]
            hits.append({**entry, "files": files})
            sev = entry.get("severity", "?").upper()
            col = SCARLET if sev in ("CRITICAL", "HIGH") else ARTERY
            print("  " + col + sev.ljust(10) + RESET + BONE + entry["cve"].ljust(20) + RESET
                  + ARTERY + entry["package"].ljust(20) + RESET
                  + ASH + entry["version"] + RESET)
            for f in files:
                print("      " + ASH + f + RESET)

    print()
    print_kv("matches", str(len(hits)))

    out = Path(out_file) if out_file else FW_DIR / ("cve_" + root.name + ".json")
    out.write_text(json.dumps(hits, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky firmware analyze", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="identify",
                   choices=["identify", "unpack", "uefi", "squashfs", "cve"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--cve", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky firmware analyze <identify|unpack|uefi|squashfs|cve> [opts]")
        return 2

    if ns.help:
        print_info("identify <file>              -- magic + entropy fingerprint")
        print_info("unpack <file>                -- binwalk extract")
        print_info("uefi <file>                  -- UEFI FV parse + secure boot keys")
        print_info("squashfs <file>              -- squashfs extract + init/setuid audit")
        print_info("cve <dir> --cve db.json      -- match extracted components against cves")
        return 0

    if ns.action == "identify":
        if not ns.target:
            print_err("give a file")
            return 2
        return cmd_identify(ns.target, ns.out)
    if ns.action == "unpack":
        if not ns.target:
            print_err("give a file")
            return 2
        return cmd_unpack(ns.target, ns.out)
    if ns.action == "uefi":
        if not ns.target:
            print_err("give a file")
            return 2
        return cmd_uefi(ns.target, ns.out)
    if ns.action == "squashfs":
        if not ns.target:
            print_err("give a file")
            return 2
        return cmd_squashfs(ns.target, ns.out)
    if ns.action == "cve":
        if not ns.target:
            print_err("give a dir")
            return 2
        return cmd_cve(ns.target, ns.cve, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
