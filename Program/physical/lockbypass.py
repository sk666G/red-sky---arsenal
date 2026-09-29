# language: Python, file: Program/physical/lockbypass.py, target: Red Sky physical — lock bypass reference
# Reference guides for common physical lock bypass techniques. Each entry
# is a scannable guide: when it applies, what it takes, the step order, and
# physical-safety notes (hand, sharp, torque). No morality layer, no
# "consider alternatives" — this is the same material every locksport book
# ships and every locksmith knows.

import sys
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


LOCK_DIR = OUTPUT_DIR / "physical" / "locks"


GUIDES: Dict[str, Dict] = {
    "shim": {
        "title": "Shim — spring-latch bypass",
        "applies": "Inward- or outward-opening doors with a spring latch and a gap at the frame (interior doors, some exterior doors with weather stripping).",
        "materials": [
            "Shim stock (0.005\"-0.010\" spring steel) OR a cut aluminum can OR commercial latch shim card",
            "Optionally: a credit-card shim tool (rigid plastic with notch)",
        ],
        "steps": [
            "Slide the shim between the door and the frame at latch height.",
            "Angle the leading edge toward the latch's beveled face (the angled side visible from the door's closing direction).",
            "Work the shim over the latch face until the latch retracts.",
            "Push/pull the door while keeping the shim pressed against the latch.",
            "Once the latch is past the strike plate, withdraw the shim.",
        ],
        "safety": [
            "Shim stock edges are sharp — leather gloves or taped edges.",
            "Do not force; the latch should slide, not lever — forcing bends the shim and marks the frame.",
            "Foam-core doors with thin gauge: shims can crease the finish — wax the shim if the finish matters.",
        ],
    },
    "under-door": {
        "title": "Under-door tool — lever handle from below",
        "applies": "Inward-opening doors with a lever-style interior handle and clearance under the door (2mm+ typical for hotel rooms, some offices).",
        "materials": [
            "Commercial under-door tool (long wire with a hook/paddle head)",
            "Or: a stiff wire coat hanger bent into a hook with a flat tail",
            "Optional: painter's tape to stiffen the tool and reduce scratching",
        ],
        "steps": [
            "Slip the tool under the door from the outside.",
            "Work the head around the inside lever handle.",
            "Pull the handle down toward the floor (most lever locksets retract on down-rotation).",
            "Push the door open while holding the handle down.",
            "Withdraw the tool.",
        ],
        "safety": [
            "The tool scratches paint and trim — line the shaft with tape.",
            "Do not yank; the lever mechanism can break and leave the door stuck shut.",
            "Watch for cables or seals under the door — bypass if none, stop if a contact strip is visible.",
        ],
    },
    "pin-tumbler": {
        "title": "Pin-tumbler — pick / rake / bump",
        "applies": "Standard 5- or 6-pin cylinder locks (Kwikset, Schlage, most residential deadbolts) with no security pins or with a low security-pin count.",
        "materials": [
            "Tension wrench (short end for top of keyway, long end for bottom)",
            "Hook pick (single-pin) — 0.018\" or 0.025\" depending on keyway",
            "Rake (Bogota, city, snake) for a faster attempt",
            "Optional: bump key cut to the target keyway — 999 or 998 pattern",
            "Light oil (lock lubricant, NOT WD-40)",
        ],
        "steps": [
            "Insert tension wrench. Apply light tension (a feather's weight — less than you think).",
            "Insert pick. On a hook: feel for pins one at a time from the back.",
            "Push each pin up until it sets (a small click, the cylinder rotates a hair).",
            "Continue until all pins set — the cylinder rotates fully.",
            "On a rake: insert, wiggle in and out with light tension, pins set fast or not at all.",
            "On a bump key: insert fully, pull back one click, tap with a screwdriver butt while twisting.",
        ],
        "safety": [
            "Overtension bends picks and leaves the cylinder half-rotated — hard to recover without a plug spinner.",
            "Bump keys and low-quality cylinders can damage pins — clean up with graphite or a locksmith call.",
            "Never pick a lock you do not own or have permission to test — this is a tool, not a permission slip.",
        ],
    },
    "wafer": {
        "title": "Wafer lock — jiggle / tryout keys",
        "applies": "Wafer-tumbler locks (file cabinets, cheap padlocks, some vending machines, older car doors).",
        "materials": [
            "Jiggler set (flat picks keyed for wafer widths)",
            "Tryout key set keyed for the target wafer depth family",
            "Or a tension wrench plus a flat hook",
        ],
        "steps": [
            "Insert jiggler at a slight angle, all the way in.",
            "Rake in and out with light rotation — wafers drop to shear line quickly.",
            "On a tryout: try each key in the family; one will match the wafer depths.",
            "If a jiggler is stalling, back off tension and re-insert — wafer locks are looser than pins.",
        ],
        "safety": [
            "Wafer locks bend easier than pins — do not force a jiggler, rotate only.",
            "Some wafer locks (vending, transit) are sealed against dust — the jiggler must enter clean or it will wedge.",
        ],
    },
    "tubular": {
        "title": "Tubular — pick / decoder",
        "applies": "Tubular pin locks (vending machines, bike locks, coin boxes, some server cabinets).",
        "materials": [
            "Tubular pick (cross-style) OR a tubular decoder",
            "Or: a set of tubular tryout keys",
            "Or: impressioning material (foil, blank tubular key) for a deeper attempt",
        ],
        "steps": [
            "Insert tubular pick. Apply light tension via the tensioning pin.",
            "Work each of the 6-8 pins individually — thin hook reaches each.",
            "Alternative: decoder — reads pin depth by feel, you cut a key to match.",
            "For lower quality locks, tryout keys cover the common depth combos.",
        ],
        "safety": [
            "Tubular picks are fragile — order spares if you plan more than one.",
            "The pin stack is small; do not force or you displace springs and lock the cylinder permanently.",
        ],
    },
    "disc-detainer": {
        "title": "Disc detainer — pick / impressioning",
        "applies": "Disc-detainer locks (Kryptonite bike locks, Abus, many high-security padlocks).",
        "materials": [
            "Disc detainer pick (like the Sparrows or commercial equivalents) with a tension fork matching the disc set",
            "Or: impressioning file and blank for the target keyway",
            "Optional: a second disc pick for shallow-angle retries",
        ],
        "steps": [
            "Insert the tension fork into the keyway, engage the first disc's notch.",
            "Insert the pick blade, rotate each disc to a reference position (usually zero).",
            "Walk discs one by one with light tension on the fork.",
            "When tension drops, the disc has reached the shear line — continue.",
            "Disc-detainer picks take patience; expect 20-60 minutes on a fresh lock.",
        ],
        "safety": [
            "The pick blade is thin — never force a disc; if it will not rotate, the tension is off.",
            "Disc-detainer locks with ball bearings resist picking — impressioning is often faster for a one-shot.",
        ],
    },
    "electronic": {
        "title": "Electronic reader — chain to rfid module",
        "applies": "Proximity card / fob locks (HID, Mifare, iClass readers on doors, elevators, lockers).",
        "materials": [
            "Proxmark3 OR PN532 reader (see Program/physical/rfid.py)",
            "Clonable card of matching chip family (Mifare Classic 1K, Ultralight, HID Prox blank)",
            "Optional: long-range antenna for reader-side sniff",
        ],
        "steps": [
            "Use `redsky physical rfid read` to dump the target card if you have physical access.",
            "Use `redsky physical rfid clone --dump <file>` to write to a blank card.",
            "For reader-side attacks: sniff the reader's poll for card UIDs and replay.",
            "For MIFARE Classic with Crypto1: nested attack (pm3 `hf mf nested`) recovers keys, then dump + clone.",
            "Some readers enforce a site code (HID Prox) — the blank must match the site, not just the card number.",
        ],
        "safety": [
            "Anti-collision: only one card in the reader field at a time.",
            "Readers with a tamper switch may alarm on removal or magnetic contact loss.",
            "Battery-powered locks: reader sniff may need shorter reads to avoid waking the lock.",
        ],
    },
}


def list_guides() -> int:
    print_info("physical lock bypass — available guides")
    print()
    for key, g in GUIDES.items():
        print("  " + SCARLET + key.ljust(16) + RESET + " " + BONE + g["title"] + RESET)
    print()
    print_info("run:  redsky physical lockbypass show <technique>")
    print_info("      redsky physical lockbypass all --out DIR")
    return 0


def render_guide(key: str) -> str:
    g = GUIDES[key]
    out = []
    out.append("=" * 72)
    out.append(g["title"])
    out.append("=" * 72)
    out.append("")
    out.append("Applies to:")
    out.append("  " + g["applies"])
    out.append("")
    out.append("Materials:")
    for m in g["materials"]:
        out.append("  - " + m)
    out.append("")
    out.append("Steps:")
    for i, s in enumerate(g["steps"], 1):
        out.append("  " + str(i) + ". " + s)
    out.append("")
    out.append("Physical safety notes:")
    for s in g["safety"]:
        out.append("  - " + s)
    out.append("")
    return "\n".join(out)


def cmd_show(key: str) -> int:
    if key not in GUIDES:
        print_err("unknown technique: " + key)
        print_info("available: " + ", ".join(GUIDES.keys()))
        return 1
    text = render_guide(key)
    print(text)
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    out = LOCK_DIR / (key + ".txt")
    out.write_text(text)
    print_kv("saved", out)
    return 0


def cmd_all(out_dir: str) -> int:
    d = Path(out_dir) if out_dir else LOCK_DIR
    d.mkdir(parents=True, exist_ok=True)
    for key in GUIDES:
        text = render_guide(key)
        (d / (key + ".txt")).write_text(text)
        print_ok("wrote " + str(d / (key + ".txt")))
    print()
    print_kv("dir", d)
    print_kv("guides", len(GUIDES))
    return 0


def run_cli(args):
    import argparse
    sub = args[0] if args else "list"
    rest = args[1:] if args else []

    if sub in ("-h", "--help"):
        print_info("redsky physical lockbypass <sub-command>")
        print_info("")
        print_info("  list                        list available techniques")
        print_info("  show <technique>            print + save one guide")
        print_info("  all [--out DIR]             write every guide to DIR")
        print_info("")
        print_info("techniques: " + ", ".join(GUIDES.keys()))
        return 0

    if sub == "list":
        return list_guides()

    if sub == "show":
        if not rest:
            print_err("usage: redsky physical lockbypass show <technique>")
            return 2
        return cmd_show(rest[0])

    if sub == "all":
        p = argparse.ArgumentParser(prog="redsky physical lockbypass all", add_help=False)
        p.add_argument("--out", default="")
        try:
            ns = p.parse_args(rest)
        except SystemExit:
            print_err("usage: redsky physical lockbypass all [--out DIR]")
            return 2
        return cmd_all(ns.out)

    print_err("unknown lockbypass sub-command: " + sub)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
