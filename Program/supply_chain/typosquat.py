# language: Python, file: Program/supply_chain/typosquat.py, target: Red Sky supply_chain — typosquat generator
# Generates typosquat candidates for a given package name across all classic
# techniques: omission, duplication, transposition, keyboard adjacency,
# homoglyphs, separators, plurals, scope swaps, and affixes.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Set

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SC_DIR = OUTPUT_DIR / "supply_chain"

KEYBOARD = {
    "q": "was",  "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yijh", "i": "uokj", "o": "ipkl", "p": "ol",
    "a": "qszx", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

HOMOGLYPHS = {
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
    "t": "7", "g": "9", "b": "6", "l": "1", "z": "2",
}


def _split(name):
    if name.startswith("@") and "/" in name:
        s, p = name[1:].split("/", 1)
        return s, p
    return None, name


def _join(scope, pkg):
    return f"@{scope}/{pkg}" if scope else pkg


def gen_omission(name):
    out = set()
    for i in range(len(name)):
        if name[i].isalnum():
            out.add(name[:i] + name[i+1:])
    return out


def gen_duplication(name):
    out = set()
    for i in range(len(name)):
        if name[i].isalnum():
            out.add(name[:i] + name[i] * 2 + name[i+1:])
    return out


def gen_transposition(name):
    out = set()
    for i in range(len(name) - 1):
        if name[i] != name[i+1]:
            out.add(name[:i] + name[i+1] + name[i] + name[i+2:])
    return out


def gen_keyboard(name):
    out = set()
    for i, c in enumerate(name):
        for k in KEYBOARD.get(c.lower(), ""):
            out.add(name[:i] + k + name[i+1:])
    return out


def gen_homoglyph(name):
    out = set()
    for i, c in enumerate(name):
        for h in HOMOGLYPHS.get(c.lower(), ""):
            if h != c:
                out.add(name[:i] + h + name[i+1:])
    return out


def gen_separators(name):
    out = set()
    for i, c in enumerate(name):
        if c == "-":
            out.add(name[:i] + "_" + name[i+1:])
            out.add(name[:i] + name[i+1:])
        if c == "_":
            out.add(name[:i] + "-" + name[i+1:])
            out.add(name[:i] + name[i+1:])
        if c == ".":
            out.add(name[:i] + "-" + name[i+1:])
    for i in range(1, len(name)):
        out.add(name[:i] + "-" + name[i:])
        out.add(name[:i] + "_" + name[i:])
    return out


def gen_plural(name):
    return {name[:-1]} if name.endswith("s") else {name + "s"}


def gen_scope_swap(name):
    scope, pkg = _split(name)
    out = set()
    if scope:
        out.add(pkg)
        out.add(f"{scope}-{pkg}")
        for alt in ("official", "core", "sdk", "api", "js", "node", "org"):
            out.add(f"@{alt}/{pkg}")
    else:
        for sc in ("official", "core", "sdk", "api", "js", "node", "org", name):
            out.add(f"@{sc}/{name}")
    return out


def gen_affixes(name):
    out = set()
    for prefix in ("js", "node", "lib", "py", "get", "react", "vue", "ng"):
        out.add(f"{prefix}-{name}")
    for suffix in ("-js", "-node", "-cli", "-core", "-lib", "-sdk"):
        out.add(f"{name}{suffix}")
    return out


GENERATORS = {
    "omission":      gen_omission,
    "duplication":   gen_duplication,
    "transposition": gen_transposition,
    "keyboard":      gen_keyboard,
    "homoglyph":     gen_homoglyph,
    "separators":    gen_separators,
    "plural":        gen_plural,
    "scope-swap":    gen_scope_swap,
    "affixes":       gen_affixes,
}


def generate(name):
    out = {}
    scope, pkg = _split(name)
    for gen_name, fn in GENERATORS.items():
        if gen_name in ("scope-swap", "affixes"):
            cands = fn(name)
        else:
            cands = {_join(scope, c) for c in fn(pkg)}
        cands = {c for c in cands if c and c != name}
        if cands:
            out[gen_name] = sorted(cands)
    return out


def cmd_gen(name, registry="npm", out_file=""):
    SC_DIR.mkdir(parents=True, exist_ok=True)
    print_info(f"generating typosquat candidates for '{name}' ({registry})")

    candidates = generate(name)
    total = sum(len(v) for v in candidates.values())

    print_kv("total", total)
    print()
    for cat, lst in candidates.items():
        print(f"{ARTERY}{BOLD}-- {cat} ({len(lst)}){RESET}")
        for c in lst[:25]:
            print(f"  {ARTERY}*{RESET} {BONE}{c}{RESET}")
        if len(lst) > 25:
            print(f"  {ASH}... +{len(lst)-25} more{RESET}")
        print()

    out = Path(out_file) if out_file else SC_DIR / f"typosquat_{name.replace('/', '_')}_{int(time.time())}.json"
    out.write_text(json.dumps({"base": name, "registry": registry, "candidates": candidates}, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky supply_chain typosquat", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("name", nargs="?", default="")
    p.add_argument("--registry", default="npm", choices=["npm", "pypi", "gem", "cargo", "go"])
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky supply_chain typosquat <package-name> [--registry npm|pypi|gem|cargo|go]")
        return 2

    if ns.help:
        print_info("redsky supply_chain typosquat lodash --registry npm")
        print_info("  generates omission, duplication, transposition, keyboard-neighbour,")
        print_info("  homoglyph, separator, plural, scope-swap, and affix variants")
        return 0

    if not ns.name:
        print_err("provide a package name")
        return 2

    return cmd_gen(ns.name, ns.registry, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
