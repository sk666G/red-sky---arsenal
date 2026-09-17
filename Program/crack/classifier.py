# language: Python, file: Program/crack/classifier.py, target: Red Sky crack — classifier
# Detect packer + licensing scheme. Uses DIE if installed, PE heuristics otherwise.

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


PACKER_SIGNATURES = {
    "UPX":       [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "MPRESS":    [b".MPRESS1", b".MPRESS2"],
    "Themida":   [b".themida", b"Themida"],
    "VMProtect": [b".vmp0", b".vmp1", b".vmp2"],
    "ASPack":    [b".aspack", b".adata"],
    "PECompact": [b"PEC2", b"PECompact2"],
    "Enigma":    [b".enigma1", b".enigma2"],
    "Armadillo": [b".text1", b"Armadillo"],
    "Petite":    [b".petite"],
    "FSG":       [b".FSG!"],
    "NsPack":    [b".nsp0", b".nsp1"],
    "Obsidium":  [b".obsidium"],
}

LICENSE_KEYWORDS = {
    "trial":      [b"trial", b"Trial", b"TRIAL", b"days remaining", b"expire"],
    "serial":     [b"serial", b"Serial", b"license key", b"License Key", b"product key"],
    "activation": [b"activate", b"Activate", b"activation", b"Activation"],
    "online":     [b"POST /activate", b"/api/license", b"http://license"],
    "dll_check":  [b"license.dll", b"License.dll", b"keygen"],
    "file_check": [b".lic", b"license.dat", b"license.key"],
}


def _run_die(path: str) -> str:
    if not shutil.which("diec"):
        return ""
    try:
        r = subprocess.run(["diec", "-j", path], capture_output=True, text=True, timeout=30)
        return r.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def _pe_packer_check(data: bytes) -> List[str]:
    found = []
    for packer, sigs in PACKER_SIGNATURES.items():
        for sig in sigs:
            if sig in data:
                found.append(packer)
                break
    return found


def _scan_strings_for_scheme(data: bytes) -> Dict[str, List[str]]:
    hits = {}
    for scheme, keywords in LICENSE_KEYWORDS.items():
        matches = []
        for kw in keywords:
            idx = data.find(kw)
            if idx >= 0:
                start = max(0, idx - 20)
                end = min(len(data), idx + len(kw) + 40)
                ctx = data[start:end].decode("ascii", errors="replace")
                matches.append(ctx.strip())
        if matches:
            hits[scheme] = matches[:5]
    return hits


def _pe_imports(path: str) -> List[str]:
    try:
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ])
        funcs = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii", errors="replace")
            for imp in entry.imports:
                if imp.name:
                    funcs.append(f"{dll}!{imp.name.decode('ascii', errors='replace')}")
        return funcs
    except (pefile.PEFormatError, OSError):
        return []
    finally:
        try:
            pe.close()
        except Exception:
            pass


def cmd_classify(path: str) -> int:
    p = Path(path)
    if not p.exists():
        print_err(f"file not found: {path}")
        return 1

    data = p.read_bytes()
    size_kb = len(data) / 1024

    print_info(f"classifying {p.name}")
    print_kv("size", f"{size_kb:.1f} KB")
    print_kv("sha256", hashlib.sha256(data).hexdigest()[:32] + "…")
    print_kv("md5", hashlib.md5(data).hexdigest())
    print()

    packers = _pe_packer_check(data)
    print(f"{ARTERY}{BOLD}  packers{RESET}")
    if packers:
        for pk in packers:
            print(f"  {SCARLET}▓{RESET} {BONE}{pk}{RESET}")
    else:
        print(f"  {CLOT}(none detected){RESET}")

    die = _run_die(path)
    if die:
        print()
        print(f"{ARTERY}{BOLD}  Detect-It-Easy{RESET}")
        print(f"  {ASH}{die[:800]}{RESET}")

    imports = _pe_imports(path)
    if imports:
        print()
        print(f"{ARTERY}{BOLD}  interesting imports{RESET}")
        interesting = [i for i in imports if any(x in i.lower() for x in (
            "crypt", "reg", "http", "winhttp", "winsock", "socket",
            "gettime", "queryperform", "createtoolhelp",
        ))]
        for i in interesting[:20]:
            print(f"  {ARTERY}▓{RESET} {BONE}{i}{RESET}")

    print()
    print(f"{ARTERY}{BOLD}  licensing scheme hints{RESET}")
    scheme = _scan_strings_for_scheme(data)
    if scheme:
        for cat, samples in scheme.items():
            print(f"  {ARTERY}▓{RESET} {SCARLET}{cat}{RESET}")
            for s in samples:
                print(f"      {ASH}{s[:80]}{RESET}")
    else:
        print(f"  {CLOT}(no obvious scheme markers){RESET}")

    result = {
        "file": str(p),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "packers": packers,
        "imports": imports[:200],
        "scheme_hints": scheme,
        "die_raw": die,
    }
    out = OUTPUT_DIR / "crack" / f"classify_{p.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky crack classify <binary>")
        return 2
    return cmd_classify(args[0])


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
