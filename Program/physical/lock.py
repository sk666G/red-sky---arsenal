# language: Python, file: Program/physical/lock.py, target: Red Sky physical — lock bypass catalog
# Not a live attack tool — this is a reference card. Prints (or writes to a
# printable PDF-ready text file) the standard bypass catalog for the common
# pin-tumbler / wafer / disc-detainer / tubular / high-security cylinders:
#   attack type, applicable lock class, tools needed, time estimate, notes.
# Also generates cut-sheet key blank dimensions for keying-by-hand.

import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


PH_DIR = OUTPUT_DIR / "physical"
REF_DIR = PH_DIR / "reference"
REF_DIR.mkdir(parents=True, exist_ok=True)


# ── bypass catalog ──
# keys: name, applies_to (list), difficulty (1-5), time, tools, notes
CATALOG: List[Dict] = [
    {
        "name": "Raking",
        "applies_to": ["pin tumbler (cheap)", "wafer"],
        "difficulty": 1,
        "time": "seconds to minutes",
        "tools": ["rake pick", "tension wrench"],
        "notes": "Randomized pick strokes while light tension. Bypasses Kwikset, Schlage consumer lines fast."
    },
    {
        "name": "Single-pin picking (SPP)",
        "applies_to": ["pin tumbler", "high-security (with the right pick)"],
        "difficulty": 3,
        "time": "1-15 min",
        "tools": ["hook picks", "tension wrench", "light"],
        "notes": "Binds each pin. Security pins (spool/serrated) need feather tension."
    },
    {
        "name": "Bumping",
        "applies_to": ["pin tumbler (unrestricted keyway)"],
        "difficulty": 2,
        "time": "seconds",
        "tools": ["bump key (matching keyway)", "bump hammer"],
        "notes": "Needs the right profile. Defeated by security pins and restricted keyways."
    },
    {
        "name": "Shimming",
        "applies_to": ["padlocks (spring latch)", "some deadbolts"],
        "difficulty": 1,
        "time": "seconds",
        "tools": ["shim stock / feeler gauge"],
        "notes": "Slides between shackle and body to trip the latch. Defeated by ball-bearing (anti-shim) latches."
    },
    {
        "name": "Comb picking",
        "applies_to": ["pin tumbler"],
        "difficulty": 2,
        "time": "seconds to minutes",
        "tools": ["comb pick"],
        "notes": "Pushes all pins above the shear line at once. Works best on locks with stacked key pins + driver pins."
    },
    {
        "name": "Overlifting",
        "applies_to": ["pin tumbler"],
        "difficulty": 2,
        "time": "seconds",
        "tools": ["pick or key blank"],
        "notes": "Push every pin above the shear line. Some locks will open when all pins sit on the top of the plug."
    },
    {
        "name": "Decoder / tryout keys",
        "applies_to": ["wafer", "disc detainer", "tubular"],
        "difficulty": 3,
        "time": "1-30 min",
        "tools": ["decoder set"],
        "notes": "Reads the binding order without opening. Automobile and vending machines are common targets."
    },
    {
        "name": "Disc detainer picks",
        "applies_to": ["disc detainer (Kryptonite, Abus, bike locks)"],
        "difficulty": 4,
        "time": "5-60 min",
        "tools": ["disc detainer pick (Sparrows, custom)"],
        "notes": "Rotate each disc to the gate position. Cheap Chinese picks work; quality locks need a tensioned front disc."
    },
    {
        "name": "Tubular lock pick",
        "applies_to": ["tubular (vending, old handcuffs)"],
        "difficulty": 3,
        "time": "1-10 min",
        "tools": ["tubular pick set", "tension wrench"],
        "notes": "Each pin (usually 6-8) pins at a different depth. Self-impressioning pick is the fastest."
    },
    {
        "name": "Under-door tool",
        "applies_to": ["lever handle interior doors", "some hotel doors"],
        "difficulty": 1,
        "time": "seconds",
        "tools": ["under-door tool"],
        "notes": "Slides under the door and pulls the lever handle from the other side."
    },
    {
        "name": "Loiding / carding",
        "applies_to": ["spring-latch doors"],
        "difficulty": 1,
        "time": "seconds",
        "tools": ["credit card / loiding card"],
        "notes": "Push the spring latch back. Defeated by deadlatches and strike plates."
    },
    {
        "name": "Padlock bypass (shackle shim)",
        "applies_to": ["padlocks"],
        "difficulty": 1,
        "time": "seconds",
        "tools": ["shim / beer can strip"],
        "notes": "Wrap the shackle to catch the bolt. Not applicable to ball-bearing latches."
    },
    {
        "name": "Brute force / drill",
        "applies_to": ["any"],
        "difficulty": 2,
        "time": "minutes",
        "tools": ["drill", "carbide bit", "tension wrench"],
        "notes": "Drill the shear line or the pin stacks. Loud, destructive, last resort."
    },
    {
        "name": "Snapping",
        "applies_to": ["cheap padlocks", "some euro cylinders"],
        "difficulty": 3,
        "time": "seconds",
        "tools": ["snap tool / pipe wrench"],
        "notes": "Break the cylinder in half and use a screwdriver in the back half to actuate the cam."
    },
]


# ── key blank dimensions for common cylinders ──
# blank code, name, manufacturer, cut depths (inch, master reference), spacing
KEY_BLANKS: List[Dict] = [
    {
        "code": "KW1 / KW10",
        "name": "Kwikset",
        "manufacturer": "Kwikset",
        "pins": 5,
        "spacing_in": 0.15625,
        "depths_in": [0.320, 0.297, 0.273, 0.250, 0.227, 0.203, 0.180],
        "blank_stock": "0.019\" x 0.090\" brass",
    },
    {
        "code": "SC1",
        "name": "Schlage",
        "manufacturer": "Schlage",
        "pins": 5,
        "spacing_in": 0.15625,
        "depths_in": [0.334, 0.313, 0.293, 0.272, 0.252, 0.231, 0.210],
        "blank_stock": "0.019\" x 0.090\" brass",
    },
    {
        "code": "SC4",
        "name": "Schlage (6-pin)",
        "manufacturer": "Schlage",
        "pins": 6,
        "spacing_in": 0.15625,
        "depths_in": [0.334, 0.313, 0.293, 0.272, 0.252, 0.231, 0.210],
        "blank_stock": "0.019\" x 0.090\" brass",
    },
    {
        "code": "Y1",
        "name": "Yale",
        "manufacturer": "Yale",
        "pins": 5,
        "spacing_in": 0.15625,
        "depths_in": [0.320, 0.297, 0.273, 0.250, 0.227, 0.203, 0.180],
        "blank_stock": "0.019\" x 0.090\" brass",
    },
    {
        "code": "M1",
        "name": "Master Lock",
        "manufacturer": "Master Lock",
        "pins": 4,
        "spacing_in": 0.15625,
        "depths_in": [0.320, 0.297, 0.273, 0.250, 0.227, 0.203, 0.180],
        "blank_stock": "0.019\" x 0.090\" brass",
    },
    {
        "code": "DE6",
        "name": "American Lock (6-pin)",
        "manufacturer": "American Lock",
        "pins": 6,
        "spacing_in": 0.15625,
        "depths_in": [0.320, 0.297, 0.273, 0.250, 0.227, 0.203, 0.180],
        "blank_stock": "0.019\" x 0.090\" brass",
    },
]


def cmd_catalog(name_filter: str = "", difficulty_max: int = 0, out_file: str = "") -> int:
    print_info("lock bypass catalog")
    print()
    rows = CATALOG
    if name_filter:
        f = name_filter.lower()
        rows = [r for r in rows if f in r["name"].lower() or any(f in a.lower() for a in r["applies_to"])]
    if difficulty_max:
        rows = [r for r in rows if r["difficulty"] <= difficulty_max]

    for r in rows:
        stars = SCARLET + ("★" * r["difficulty"]) + ASH + ("☆" * (5 - r["difficulty"])) + RESET
        print(BONE + r["name"] + RESET + "  " + stars)
        print("  " + ASH + "applies: " + RESET + ARTERY + ", ".join(r["applies_to"]) + RESET)
        print("  " + ASH + "time:    " + RESET + r["time"])
        print("  " + ASH + "tools:   " + RESET + ", ".join(r["tools"]))
        print("  " + CLOT + r["notes"] + RESET)
        print()

    if out_file:
        out = Path(out_file)
    else:
        out = REF_DIR / ("lock_catalog_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(rows, indent=2))
    print_kv("saved", out)
    return 0


def cmd_blanks(code_filter: str = "", out_file: str = "") -> int:
    print_info("key blank reference")
    print()
    rows = KEY_BLANKS
    if code_filter:
        f = code_filter.lower()
        rows = [r for r in rows if f in r["code"].lower() or f in r["name"].lower()]

    for b in rows:
        print(BONE + b["code"] + RESET + "  " + ARTERY + b["name"] + RESET)
        print("  " + ASH + "mfr:      " + RESET + b["manufacturer"])
        print("  " + ASH + "pins:     " + RESET + str(b["pins"]))
        print("  " + ASH + "spacing:  " + RESET + str(b["spacing_in"]) + "\"")
        print("  " + ASH + "depths:   " + RESET + ", ".join(str(d) for d in b["depths_in"]) + " in")
        print("  " + ASH + "stock:    " + RESET + b["blank_stock"])
        print()

    if out_file:
        out = Path(out_file)
    else:
        out = REF_DIR / ("key_blanks_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(rows, indent=2))
    print_kv("saved", out)
    return 0


def cmd_cut_sheet(code: str, cuts: str) -> int:
    """Given a blank code and a cut sequence (e.g. "3-5-2-1-4"), print the cut
    depths as inches and a rough filing order. cuts are 1-indexed into the
    depths_in array (1 = shallowest)."""
    blank = next((b for b in KEY_BLANKS if code.lower() in b["code"].lower()), None)
    if not blank:
        print_err("unknown blank code: " + code)
        print_info("available: " + ", ".join(b["code"] for b in KEY_BLANKS))
        return 2

    try:
        seq = [int(x) for x in cuts.replace(",", "-").split("-") if x.strip()]
    except ValueError:
        print_err("cuts must be a dash-separated list of integers, e.g. 3-5-2-1-4")
        return 2

    if len(seq) != blank["pins"]:
        print_warn("blank takes " + str(blank["pins"]) + " pins, got " + str(len(seq)))

    depths = blank["depths_in"]
    print_info("cut sheet for " + blank["code"] + " (" + blank["name"] + ")")
    print_kv("sequence", "-".join(str(s) for s in seq))
    print()
    for i, s in enumerate(seq, 1):
        if s < 1 or s > len(depths):
            print("  " + ASH + "pin " + str(i) + ": cut #" + str(s) + " (out of range)" + RESET)
            continue
        d = depths[s - 1]
        print("  " + ARTERY + "pin " + str(i) + RESET + " cut #" + str(s) + "  ->  "
              + BONE + "{:.4f}\"".format(d) + RESET)
    print()
    print_info("cut deepest toward the shoulder — the shoulder stops travel; depths are from shoulder face")
    print_info("validate against a working key with a caliper before cutting the real blank")

    out = REF_DIR / ("cut_sheet_" + blank["code"].replace(" ", "_") + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "blank": blank,
        "sequence": seq,
        "depths_in": [depths[s - 1] if 1 <= s <= len(depths) else None for s in seq],
    }, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky physical lock", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="catalog",
                   choices=["catalog", "blanks", "cut-sheet"])
    p.add_argument("--filter", default="")
    p.add_argument("--max-difficulty", type=int, default=0)
    p.add_argument("--code", default="")
    p.add_argument("--cuts", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky physical lock <catalog|blanks|cut-sheet> [opts]")
        return 2

    if ns.help:
        print_info("catalog [--filter NAME] [--max-difficulty 1-5]   -- bypass techniques")
        print_info("blanks  [--filter KW1]                          -- key blank dimensions")
        print_info("cut-sheet --code KW1 --cuts 3-5-2-1-4            -- depths for a given bitting")
        return 0

    if ns.action == "catalog":
        return cmd_catalog(ns.filter, ns.max_difficulty, ns.out)
    if ns.action == "blanks":
        return cmd_blanks(ns.filter, ns.out)
    if ns.action == "cut-sheet":
        if not ns.code or not ns.cuts:
            print_err("--code and --cuts required")
            return 2
        return cmd_cut_sheet(ns.code, ns.cuts)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
