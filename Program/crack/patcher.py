# language: Python, file: Program/crack/patcher.py, target: Red Sky crack — patcher
# Byte-patch conditional jumps. Uses capstone for candidate detection, patches
# JZ -> JNZ or NOPs the check.

import hashlib
import sys
from pathlib import Path
from typing import List, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


JCC_SHORT = {
    0x74: "je", 0x75: "jne",
    0x72: "jb", 0x73: "jae",
    0x76: "jbe", 0x77: "ja",
    0x7C: "jl", 0x7D: "jge",
    0x7E: "jle", 0x7F: "jg",
    0x70: "jo", 0x71: "jno",
    0x78: "js", 0x79: "jns",
}

INVERT = {
    0x74: 0x75, 0x75: 0x74,
    0x72: 0x73, 0x73: 0x72,
    0x76: 0x77, 0x77: 0x76,
    0x7C: 0x7D, 0x7D: 0x7C,
    0x7E: 0x7F, 0x7F: 0x7E,
}


def _find_pe_text(data: bytes) -> Tuple[int, int]:
    if data[:2] != b"MZ":
        return (0, len(data))
    try:
        import pefile
        pe = pefile.PE(data=bytes(data), fast_load=True)
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00")
            if name in (b".text", b"CODE"):
                ret = (s.PointerToRawData, s.SizeOfRawData)
                pe.close()
                return ret
        pe.close()
    except Exception:
        pass
    return (0, len(data))


def _find_branches(data: bytes, text_off: int, text_size: int) -> List[dict]:
    candidates = []
    end = min(text_off + text_size, len(data))

    i = text_off
    while i < end - 8:
        if data[i] in (0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x80, 0x81, 0x83, 0x84, 0x85, 0xA8, 0xA9):
            for j in range(i + 2, min(i + 32, end - 2)):
                op = data[j]
                if op in JCC_SHORT:
                    candidates.append({
                        "offset": j,
                        "opcode": op,
                        "mnemonic": JCC_SHORT[op],
                        "target": j + 2 + (data[j + 1] if data[j + 1] < 0x80 else data[j + 1] - 256),
                    })
                    break
        i += 1
    return candidates


def cmd_patch(path: str, out_file: str = "", offset: int = -1, mode: str = "invert") -> int:
    p = Path(path)
    if not p.exists():
        print_err(f"file not found: {path}")
        return 1

    data = bytearray(p.read_bytes())
    text_off, text_size = _find_pe_text(data)

    print_info(f"patching {p.name}")
    print_kv("text section", f"0x{text_off:x} ({text_size} bytes)")
    print()

    if offset >= 0:
        if offset >= len(data):
            print_err(f"offset {offset} out of range")
            return 1
        op = data[offset]
        if op in INVERT and mode == "invert":
            new = INVERT[op]
            data[offset] = new
            print_ok(f"0x{offset:x}: {JCC_SHORT[op]} -> {JCC_SHORT[new]}")
        elif mode == "nop":
            data[offset:offset + 6] = b"\x90" * 6
            print_ok(f"0x{offset:x}: NOPed 6 bytes")
        else:
            print_err(f"cannot patch byte 0x{op:02x} in mode {mode}")
            return 1
    else:
        cands = _find_branches(data, text_off, text_size)
        print_info(f"found {len(cands)} candidate branches")
        for c in cands[:20]:
            print(f"  {ARTERY}▓{RESET} 0x{c['offset']:x}  {BONE}{c['mnemonic']:<6}{RESET} -> 0x{c['target']:x}")

        if not cands:
            print_warn("no candidates — try a specific --offset")
            return 1

        c = cands[0]
        if mode == "invert" and c["opcode"] in INVERT:
            old_mn = JCC_SHORT[c["opcode"]]
            new_op = INVERT[c["opcode"]]
            data[c["offset"]] = new_op
            print()
            print_ok(f"patched 0x{c['offset']:x}: {old_mn} -> {JCC_SHORT[new_op]}")

    out = Path(out_file) if out_file else p.with_stem(p.stem + "_patched")
    out.write_bytes(bytes(data))
    print()
    print_kv("saved", out)
    print_kv("sha256 before", hashlib.sha256(p.read_bytes()).hexdigest()[:32] + "…")
    print_kv("sha256 after ", hashlib.sha256(out.read_bytes()).hexdigest()[:32] + "…")
    return 0


def run_cli(args: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky crack patch", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--offset", type=lambda x: int(x, 0), default=-1)
    p.add_argument("--out", default="")
    p.add_argument("--mode", choices=["invert", "nop"], default="invert")
    p.add_argument("target", nargs="?", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky crack patch <binary> [--offset 0x...] [--mode invert|nop] [--out file]")
        return 2

    if ns.help:
        print_info("redsky crack patch <binary> [--offset 0x...] [--mode invert|nop] [--out file]")
        return 0

    if not ns.target:
        print_err("target binary required")
        return 2

    return cmd_patch(ns.target, ns.out, ns.offset, ns.mode)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
