# language: Python, file: Program/fuzzer/mutate.py, target: Red Sky fuzzer — mutation engine + wrappers
# Protocol/format agnostic mutation fuzzer. Two modes:
#   mutate  -- take a seed corpus, apply mutations, write to an output dir
#   run     -- spawn the target with each mutated input, watch for crashes
# Plus wrappers for external fuzzers if installed:
#   afl     -- launch AFL++ against a binary with the seed corpus
#   hfuzz   -- launch honggfuzz
#   boofuzz -- generate a boofuzz scaffold against a network protocol
# Mutation strategies: bit flips, byte swaps, arithmetic, boundary values,
# interesting integers, dictionary token insertion, block replication.

import argparse
import json
import os
import random
import shutil
import signal
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


FZ_DIR = OUTPUT_DIR / "fuzzer"
FZ_DIR.mkdir(parents=True, exist_ok=True)


INTERESTING_8 = [0x00, 0x01, 0x7F, 0x80, 0xFF]
INTERESTING_16 = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF]
INTERESTING_32 = [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

DEFAULT_DICT = [
    b"../", b"../../", b"..\\", b"../../..",
    b"%s", b"%n", b"%x", b"%p",
    b"<script>", b"</script>",
    b"' OR 1=1--", b"\"; DROP TABLE",
    b"\x00", b"\xff" * 16,
    b"A" * 256, b"A" * 4096,
    b"GET / HTTP/1.1\r\n",
    b"POST /", b"Host: ", b"Content-Length: ",
]


def _flip_bits(data: bytearray, n: int) -> bytearray:
    for _ in range(n):
        if not data:
            break
        i = random.randrange(len(data))
        data[i] ^= 1 << random.randrange(8)
    return data


def _swap_bytes(data: bytearray, n: int) -> bytearray:
    for _ in range(n):
        if len(data) < 2:
            break
        i, j = random.randrange(len(data)), random.randrange(len(data))
        data[i], data[j] = data[j], data[i]
    return data


def _arith(data: bytearray, n: int) -> bytearray:
    for _ in range(n):
        if not data:
            break
        i = random.randrange(len(data))
        delta = random.choice([-35, -1, 1, 35])
        data[i] = (data[i] + delta) & 0xFF
    return data


def _interesting(data: bytearray, n: int) -> bytearray:
    for _ in range(n):
        if len(data) < 1:
            break
        i = random.randrange(len(data))
        data[i] = random.choice(INTERESTING_8)
    return data


def _insert_dict(data: bytearray, n: int, dict_words: List[bytes]) -> bytearray:
    for _ in range(n):
        word = random.choice(dict_words)
        i = random.randrange(len(data) + 1)
        data[i:i] = word
    return data


def _delete_block(data: bytearray, n: int) -> bytearray:
    for _ in range(n):
        if not data:
            break
        i = random.randrange(len(data))
        j = min(len(data), i + random.randrange(1, 32))
        del data[i:j]
    return data


def _duplicate_block(data: bytearray, n: int) -> bytearray:
    for _ in range(n):
        if not data:
            break
        i = random.randrange(len(data))
        j = min(len(data), i + random.randrange(1, 32))
        data[i:i] = data[i:j]
    return data


def _havoc(data: bytearray, dict_words: List[bytes], rounds: int = 20) -> bytearray:
    for _ in range(rounds):
        op = random.choice([
            lambda d: _flip_bits(d, 2),
            lambda d: _swap_bytes(d, 2),
            lambda d: _arith(d, 2),
            lambda d: _interesting(d, 2),
            lambda d: _insert_dict(d, 1, dict_words),
            lambda d: _delete_block(d, 1),
            lambda d: _duplicate_block(d, 1),
        ])
        data = op(data)
    return data


STRATEGIES = {
    "flip":      lambda d, w: _flip_bits(d, 4),
    "swap":      lambda d, w: _swap_bytes(d, 4),
    "arith":     lambda d, w: _arith(d, 4),
    "interesting": lambda d, w: _interesting(d, 4),
    "dict":      lambda d, w: _insert_dict(d, 2, w),
    "delete":    lambda d, w: _delete_block(d, 2),
    "duplicate": lambda d, w: _duplicate_block(d, 2),
    "havoc":     lambda d, w: _havoc(d, w, 20),
}


def cmd_mutate(seed_dir: str, out_dir: str, count: int, strategy: str,
               out_file: str) -> int:
    seed = Path(seed_dir).expanduser() if seed_dir else FZ_DIR / "seeds"
    if not seed.exists():
        print_err("seed dir not found: " + str(seed))
        return 1
    target = Path(out_dir) if out_dir else FZ_DIR / ("corpus_" + str(int(time.time())))
    target.mkdir(parents=True, exist_ok=True)

    seeds = [p for p in seed.rglob("*") if p.is_file()]
    if not seeds:
        print_err("no seed files in " + str(seed))
        return 1

    strategies = list(STRATEGIES.keys()) if strategy == "all" else [strategy]
    print_info("mutation fuzzer")
    print_kv("seed dir", str(seed))
    print_kv("seed files", str(len(seeds)))
    print_kv("count", str(count))
    print_kv("strategy", ",".join(strategies))
    print_kv("output", str(target))
    print()

    written = 0
    t0 = time.time()
    for i in range(count):
        s_path = random.choice(seeds)
        data = bytearray(s_path.read_bytes())
        strat = random.choice(strategies)
        try:
            mutated = STRATEGIES[strat](data, DEFAULT_DICT)
        except Exception as e:
            print_warn("mutation failed: " + str(e))
            continue
        out_name = "fz_" + str(i).zfill(6) + "_" + strat + "_" + s_path.name
        (target / out_name).write_bytes(bytes(mutated))
        written += 1
        if (i + 1) % 500 == 0:
            print("  " + ASH + str(i+1) + "/" + str(count) + RESET, end="\r")

    print()
    print_kv("written", str(written))
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))

    out = Path(out_file) if out_file else FZ_DIR / ("mutate_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"seeds": [str(s) for s in seeds], "written": written,
                               "count": count, "strategies": strategies}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_run(target_cmd: str, corpus_dir: str, timeout_ms: int, out_file: str) -> int:
    if not target_cmd:
        print_err("--target required")
        return 2
    corpus = Path(corpus_dir).expanduser() if corpus_dir else FZ_DIR / "corpus"
    if not corpus.exists():
        print_err("corpus dir not found: " + str(corpus))
        return 1

    inputs = [p for p in corpus.rglob("*") if p.is_file()]
    print_info("running target on corpus")
    print_kv("target", target_cmd)
    print_kv("inputs", str(len(inputs)))
    print_kv("timeout", str(timeout_ms) + "ms")
    print()

    # target_cmd is expected to accept a file path via {input}
    template = target_cmd if "{input}" in target_cmd else target_cmd + " {input}"
    crashes = []
    t0 = time.time()
    for i, inp in enumerate(inputs, 1):
        cmd = template.replace("{input}", str(inp))
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               timeout=timeout_ms / 1000.0)
            if r.returncode < 0:
                # killed by signal -> crash
                crashes.append({"input": str(inp), "rc": r.returncode,
                                "signal": -r.returncode})
                print("  " + SCARLET + "▓ CRASH " + RESET + str(inp)
                      + "  signal=" + str(-r.returncode))
        except subprocess.TimeoutExpired:
            crashes.append({"input": str(inp), "rc": 124, "timeout": True})
            print("  " + ARTERY + "░ TIMEOUT " + RESET + str(inp))
        except Exception as e:
            pass
        if i % 50 == 0:
            print("  " + ASH + str(i) + "/" + str(len(inputs)) + RESET, end="\r")

    print()
    print_kv("elapsed", "{:.1f}s".format(time.time() - t0))
    print_kv("crashes", str(len(crashes)))

    out = Path(out_file) if out_file else FZ_DIR / ("run_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"target": target_cmd, "crashes": crashes,
                               "total": len(inputs)}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_afl(binary: str, seed_dir: str, timeout: int) -> int:
    if not binary:
        print_err("--binary required")
        return 2
    if not shutil.which("afl-fuzz"):
        print_err("afl-fuzz not installed")
        return 2
    seeds = Path(seed_dir).expanduser() if seed_dir else FZ_DIR / "seeds"
    out_dir = FZ_DIR / ("afl_out_" + str(int(time.time())))
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["afl-fuzz", "-i", str(seeds), "-o", str(out_dir), "-V", str(timeout),
           "--", str(binary), "@@"]
    print_info("AFL++ launch")
    print_kv("cmd", " ".join(cmd))
    print_info("CTRL+C to stop")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    print_kv("output", str(out_dir))
    return 0


def cmd_hfuzz(binary: str, seed_dir: str, timeout: int) -> int:
    if not shutil.which("honggfuzz"):
        print_err("honggfuzz not installed")
        return 2
    seeds = Path(seed_dir).expanduser() if seed_dir else FZ_DIR / "seeds"
    cmd = ["honggfuzz", "-i", str(seeds), "--run_time", str(timeout),
           "--", str(binary), "___FILE___"]
    print_info("honggfuzz launch")
    print_kv("cmd", " ".join(cmd))
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print()
    return 0


BOOFUZZ_TEMPLATE = """# language: Python, file: boofuzz_scaffold.py, target: Red Sky fuzzer — boofuzz scaffold
# Generated scaffold. Adjust the request definition for your protocol.
# pip install boofuzz
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=SocketConnection("{host}", {port}, proto="tcp"),
        ),
    )

    s_initialize("hello")
    s_string("HELLO", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("world")
    s_static("\\r\\n")

    session.connect(s_get("hello"))
    session.fuzz()


if __name__ == "__main__":
    main()
"""


def cmd_boofuzz(host: str, port: int, out_file: str) -> int:
    host = host or "127.0.0.1"
    port = port or 9999
    code = BOOFUZZ_TEMPLATE.format(host=host, port=port)
    out = Path(out_file) if out_file else FZ_DIR / "boofuzz_scaffold.py"
    out.write_text(code)
    print_ok("wrote " + str(out))
    print_kv("target", host + ":" + str(port))
    print_info("edit the s_initialize() block to match your protocol, then: python " + str(out))
    return 0


def cmd_dict(wordlist: str, out_file: str) -> int:
    """Build a dictionary file for AFL (key=value form) from a wordlist."""
    words = DEFAULT_DICT
    if wordlist:
        p = Path(wordlist).expanduser()
        if p.exists():
            words = [l.strip().encode() for l in p.read_text().splitlines() if l.strip()]
    lines = []
    for i, w in enumerate(words):
        lines.append('tok' + str(i).zfill(4) + '="' + ''.join('\\x{:02x}'.format(b) for b in w) + '"')
    out = Path(out_file) if out_file else FZ_DIR / "afl.dict"
    out.write_text("\n".join(lines) + "\n")
    print_ok("wrote " + str(out))
    print_kv("tokens", str(len(lines)))
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky fuzzer mutate", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="mutate",
                   choices=["mutate", "run", "afl", "hfuzz", "boofuzz", "dict"])
    p.add_argument("--seed", default="")
    p.add_argument("--out-dir", default="")
    p.add_argument("--count", type=int, default=1000)
    p.add_argument("--strategy", default="all", choices=list(STRATEGIES.keys()) + ["all"])
    p.add_argument("--target", default="")
    p.add_argument("--corpus", default="")
    p.add_argument("--timeout-ms", type=int, default=2000)
    p.add_argument("--binary", default="")
    p.add_argument("--host", default="")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--wordlist", default="")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky fuzzer mutate <mutate|run|afl|hfuzz|boofuzz|dict> [opts]")
        return 2

    if ns.help:
        print_info("mutate --seed dir/ --count 1000 [--strategy all|havoc] [--out-dir dir/]")
        print_info("run --target 'prog {input}' --corpus dir/ [--timeout-ms 2000]")
        print_info("afl --binary /path/to/target --seed dir/ [--timeout 600]")
        print_info("hfuzz --binary /path/to/target --seed dir/")
        print_info("boofuzz --host 127.0.0.1 --port 9999")
        print_info("dict [--wordlist file]")
        return 0

    if ns.action == "mutate":
        return cmd_mutate(ns.seed, ns.out_dir, ns.count, ns.strategy, ns.out)
    if ns.action == "run":
        return cmd_run(ns.target, ns.corpus, ns.timeout_ms, ns.out)
    if ns.action == "afl":
        return cmd_afl(ns.binary, ns.seed, ns.timeout)
    if ns.action == "hfuzz":
        return cmd_hfuzz(ns.binary, ns.seed, ns.timeout)
    if ns.action == "boofuzz":
        return cmd_boofuzz(ns.host, ns.port, ns.out)
    if ns.action == "dict":
        return cmd_dict(ns.wordlist, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
