# language: Python, file: Program/ai/adversarial.py, target: Red Sky AI — adversarial inputs
# Adversarial-input toolkit for LLMs. Two halves:
#
#   1. Attack-class catalog.  Reference notes on each family of adversarial
#      input against a language model — gradient-based (FGSM/PGD style white-
#      box), transfer-based suffixes (GCG), token-boundary rewrites, unicode
#      homoglyphs, invisible padding, markdown/HTML smuggling. Tells the
#      operator which class applies given what access they have.
#
#   2. Generators.  Given a string, emit variants: homoglyph substitution,
#      zero-width padding, leetspeak, token-boundary spacing, case flips,
#      emoji separators. These are the "free" transformations — no model
#      access required, just text in / text out.

import json
import random
import sys
import time
import unicodedata
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


ADV_DIR = OUTPUT_DIR / "ai" / "adversarial"


# ── attack classes ──────────────────────────────────────────────────────────

CLASSES: Dict[str, Dict] = {
    "whitebox_gradient": {
        "title": "White-box gradient attacks (FGSM / PGD / HotFlip)",
        "needs": "Full model weights + gradient access (local model, no API gate).",
        "idea": "Perturb the input embedding along the gradient of the loss with respect to the input, so the model mis-classifies or mis-generates. In discrete token space, HotFlip swaps tokens by first-order approximation.",
        "notes": [
            "FGSM: x' = x + eps * sign(grad_x L(x, y)) — one step, cheap, works for continuous inputs.",
            "PGD: iterate FGSM with projection back into the eps-ball — stronger, more compute.",
            "HotFlip: replace token t_i with t_j that maximizes the first-order loss delta; works in the discrete space.",
            "For generation targets: use a target sequence y* and minimize cross-entropy to y* from the perturbed prompt.",
        ],
    },
    "blackbox_suffix": {
        "title": "Black-box adversarial suffix (GCG, AutoPrompt, transfer)",
        "needs": "Query access to the target model (API or local inference).",
        "idea": "Optimize a suffix string that, appended to a harmful prompt, drives the model to comply. GCG uses token-level gradient approximations from a surrogate. Transfer: suffixes found on open models (Vicuna, Llama) often transfer to closed models of the same family.",
        "notes": [
            "GCG: iterate over candidate token swaps; keep swaps that reduce the loss of the target prefix.",
            "Suffixes are gibberish to humans ('! ! ! ! ! ... describing.\\ + similarlyNow write oppositeley') — that's expected.",
            "Transferability: suffixes found on Llama-2 7B transfer to Vicuna, Mistral, and (weaker) to GPT-class models.",
            "AutoDAN: instead of gibberish, optimize a readable suffix — lower ASR, higher stealth.",
        ],
    },
    "token_boundary": {
        "title": "Token-boundary attacks",
        "needs": "Understanding of the target tokenizer (public for open models).",
        "idea": "Insert characters that change how the model's tokenizer splits the input, so a filter (which sees the surface string) and the model (which sees tokens) disagree. E.g. 'hacking' vs 'hack ing' vs 'hack\\u200bing' tokenize differently.",
        "notes": [
            "Space splitting: 'how to hack' → 'how to hac k' (linebreak in middle).",
            "Zero-width joiners between letters force re-tokenization without changing the visible text.",
            "Combining characters change the token but not the grapheme — filter regex misses.",
            "Combining with the encoded-payloads category from prompt_inject gives strong filter-evasion.",
        ],
    },
    "homoglyph": {
        "title": "Unicode homoglyphs (confusable characters)",
        "needs": "Nothing — pure string transform.",
        "idea": "Replace Latin letters with visually identical Cyrillic / Greek / mathematical alphanumeric characters. Filters matching ASCII miss; models trained on mixed data often still read the word.",
        "notes": [
            "a → а (Cyrillic a, U+0430)",
            "e → е (Cyrillic e, U+0435)",
            "o → о (Cyrillic o, U+043E)",
            "p → р (Cyrillic er, U+0440)",
            "c → с (Cyrillic es, U+0441)",
            "x → х (Cyrillic ha, U+0445)",
        ],
    },
    "invisible_padding": {
        "title": "Invisible padding",
        "needs": "Nothing — pure string transform.",
        "idea": "Insert zero-width characters (U+200B-U+200D, U+2060-U+2064, U+FEFF) between letters. Filters that count words or match words break; models often normalize away the padding and read the word normally.",
        "notes": [
            "U+200B ZERO WIDTH SPACE — most common.",
            "U+200C ZERO WIDTH NON-JOINER.",
            "U+200D ZERO WIDTH JOINER — can change tokenizer behavior if the tokenizer has ZWJ rules.",
            "U+FEFF ZERO WIDTH NO-BREAK SPACE — also BOM.",
            "Pad one char per letter, or every N chars — both have been effective against different filters.",
        ],
    },
    "markdown_html": {
        "title": "Markdown / HTML smuggling",
        "needs": "Target pipeline that renders markdown or HTML before passing to the model.",
        "idea": "Embed instructions inside HTML comments, markdown reference links, alt text, or CSS-hidden elements. A human reading the rendered page never sees the injection; the model reading the raw text does.",
        "notes": [
            "<!-- {instruction} -->",
            "[link]: {instruction} 'tooltip'",
            "![alt: {instruction}](x.png)",
            "<span style='display:none'>{instruction}</span>",
            "<div aria-label='{instruction}'>visible</div>",
            "Base64 in data-* attributes.",
        ],
    },
}


# ── homoglyph maps ──────────────────────────────────────────────────────────

HOMOGLYPHS = {
    "a": "а",  # Cyrillic a
    "e": "е",  # Cyrillic e
    "o": "о",  # Cyrillic o
    "p": "р",  # Cyrillic er
    "c": "с",  # Cyrillic es
    "x": "х",  # Cyrillic ha
    "y": "у",  # Cyrillic u
    "i": "і",  # Cyrillic i (Ukrainian)
    "s": "ѕ",  # Cyrillic dze
    "h": "һ",  # Cyrillic shha
}

ZERO_WIDTHS = ["\u200b", "\u200c", "\u200d", "\u2060", "\u2061", "\u2062", "\u2063"]


# ── generators ──────────────────────────────────────────────────────────────

def gen_homoglyph(text: str, p: float = 0.5) -> str:
    out = []
    for ch in text:
        if ch.lower() in HOMOGLYPHS and random.random() < p:
            rep = HOMOGLYPHS[ch.lower()]
            out.append(rep.upper() if ch.isupper() else rep)
        else:
            out.append(ch)
    return "".join(out)


def gen_zero_width(text: str, every: int = 1, which: str = "200b") -> str:
    cw = chr(int(which, 16))
    out = []
    for i, ch in enumerate(text):
        out.append(ch)
        if every > 0 and (i + 1) % every == 0:
            out.append(cw)
    return "".join(out)


def gen_leet(text: str) -> str:
    table = str.maketrans({
        "a": "4", "A": "4", "e": "3", "E": "3", "i": "1", "I": "1",
        "o": "0", "O": "0", "s": "5", "S": "5", "t": "7", "T": "7",
    })
    return text.translate(table)


def gen_token_split(text: str, every: int = 3, sep: str = " ") -> str:
    parts = []
    for i in range(0, len(text), every):
        parts.append(text[i:i+every])
    return sep.join(parts)


def gen_case_flip(text: str) -> str:
    return "".join(c.lower() if c.isupper() else c.upper() for c in text)


def gen_emoji_sep(text: str, sep: str = "🫥") -> str:
    return sep.join(list(text))


def gen_combining(text: str) -> str:
    """Insert combining acute (U+0301) after each letter — changes token, not grapheme."""
    out = []
    for ch in text:
        out.append(ch)
        if ch.isalpha():
            out.append("\u0301")
    return "".join(out)


GENERATORS = {
    "homoglyph": gen_homoglyph,
    "zero_width": gen_zero_width,
    "leet": gen_leet,
    "token_split": gen_token_split,
    "case_flip": gen_case_flip,
    "emoji_sep": gen_emoji_sep,
    "combining": gen_combining,
}


# ── commands ────────────────────────────────────────────────────────────────

def cmd_classes() -> int:
    print_info("adversarial input — attack classes")
    print()
    for key, c in CLASSES.items():
        print("  " + SCARLET + key.ljust(18) + RESET + " " + BONE + c["title"] + RESET)
        print("      " + ASH + "needs: " + c["needs"] + RESET)
    print()
    print_info("run:  redsky ai adversarial class <name>")
    print_info("      redsky ai adversarial gen --in TEXT [--tech homoglyph] [--out FILE]")
    return 0


def cmd_class(name: str) -> int:
    if name not in CLASSES:
        print_err("unknown class: " + name)
        print_info("available: " + ", ".join(CLASSES.keys()))
        return 1
    c = CLASSES[name]
    print(SCARLET + BOLD + "== " + c["title"] + " ==" + RESET)
    print()
    print(ARTERY + "needs:" + RESET + " " + c["needs"])
    print(ARTERY + "idea:" + RESET + "  " + c["idea"])
    print()
    print(ARTERY + "notes:" + RESET)
    for n in c["notes"]:
        print("  - " + n)
    print()
    return 0


def cmd_gen(text: str, tech: str, out: str) -> int:
    if not text:
        print_err("--in required (or pipe via stdin)")
        return 1
    if tech not in GENERATORS:
        print_err("unknown technique: " + tech)
        print_info("available: " + ", ".join(GENERATORS.keys()))
        return 1
    gen = GENERATORS[tech]
    result = gen(text)

    print_info("adversarial variant")
    print_kv("technique", tech)
    print_kv("in_bytes", len(text.encode()))
    print_kv("out_bytes", len(result.encode()))
    print()
    print(BONE + "in: " + RESET + text)
    print(BONE + "out:" + RESET + result)
    print()

    if out:
        Path(out).write_text(result)
        print_ok("written: " + out)
    return 0


def cmd_all(text: str, out_dir: str) -> int:
    if not text:
        print_err("--in required")
        return 1
    d = Path(out_dir) if out_dir else ADV_DIR / ("variants_" + time.strftime("%Y%m%d_%H%M%S"))
    d.mkdir(parents=True, exist_ok=True)
    for tech, gen in GENERATORS.items():
        try:
            result = gen(text)
        except Exception as e:
            print_warn(tech + ": " + str(e))
            continue
        (d / (tech + ".txt")).write_text(result)
        print_ok(tech + " -> " + str(d / (tech + ".txt")))
    print()
    print_kv("dir", d)
    print_kv("techniques", len(GENERATORS))
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "classes"
    rest = args[1:] if args else []

    if sub in ("-h", "--help"):
        print_info("redsky ai adversarial <sub-command>")
        print_info("")
        print_info("  classes                          list attack classes with notes")
        print_info("  class <name>                     show one attack-class reference")
        print_info("  gen --in TEXT --tech NAME [--out FILE]")
        print_info("      produce one adversarial variant")
        print_info("  all --in TEXT [--out DIR]")
        print_info("      produce every variant of the input text")
        print_info("")
        print_info("generators: " + ", ".join(GENERATORS.keys()))
        return 0

    if sub in ("classes", "list"):
        return cmd_classes()

    if sub == "class":
        if not rest:
            print_err("usage: redsky ai adversarial class <name>")
            return 2
        return cmd_class(rest[0])

    if sub == "gen":
        p = argparse.ArgumentParser(prog="redsky ai adversarial gen", add_help=False)
        p.add_argument("--in", dest="text", default="")
        p.add_argument("--tech", default="homoglyph")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ai adversarial gen --in TEXT --tech NAME [--out FILE]")
            return 2
        return cmd_gen(ns.text, ns.tech, ns.out)

    if sub == "all":
        p = argparse.ArgumentParser(prog="redsky ai adversarial all", add_help=False)
        p.add_argument("--in", dest="text", default="")
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky ai adversarial all --in TEXT [--out DIR]")
            return 2
        return cmd_all(ns.text, ns.out)

    print_err("unknown adversarial sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
