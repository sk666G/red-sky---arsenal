# language: Python, file: Program/lock_bypass/workflow.py, target: Red Sky lock_bypass — reference + cutting + impressioning
# This is the interactive companion to physical/lock.py. Where that module is
# a static catalog, this one is the operator's worksheet:
#   picklist    -- generate a prioritized attack order for a given lock type
#   depth       -- print the depth progression for picking a pin-tumbler
#   keygen      -- generate a "tryout key" set for common wafer/disc locks
#   bump        -- print bump-key bitting for a given target bitting
#   impression  -- step-by-step worksheet for impressioning a lock
#   decode      -- decode a visible bitting from a photo measurement (helper)
# Everything is a worksheet or reference. No live lock interaction.

import argparse
import itertools
import json
import random
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


LB_DIR = OUTPUT_DIR / "lock_bypass"
LB_DIR.mkdir(parents=True, exist_ok=True)


# Prioritized attack order per lock type. Lower index = try first.
ATTACK_ORDERS: Dict[str, List[str]] = {
    "pin_tumbler_cheap": [
        "raking (3-5 rake strokes with light tension)",
        "single-pin picking (SPP) from the back",
        "comb pick if all pins are standard",
        "bump key",
        "shimming (if applicable)",
        "destructive entry (drill at shear)",
    ],
    "pin_tumbler_medium": [
        "single-pin picking with a hook",
        "raking to set any spool pins",
        "top-of-keyway tension (TOK)",
        "overlifting",
        "impressioning with a key blank",
        "drill at pin 1 (destructive)",
    ],
    "pin_tumbler_high_security": [
        "identify the high-security feature (sidebar / pin-in-pin / magnetic)",
        "impressioning if a key blank is available",
        "rare-earth bypass only if the pick exists",
        "decoder if a lockpicking decoder set is available",
        "destructive entry (last resort, loud)",
    ],
    "wafer": [
        "tryout key set (wafer locks have shallow bitting)",
        "jiggler or wafer rake",
        "comb pick",
        "decode to key if the lock is exposed",
        "destructive entry",
    ],
    "disc_detainer": [
        "disc-detainer pick (front disc tensioned)",
        "impressioning against the fence",
        "tryout keys for cheap bicycle locks",
        "destructive entry (cut shackle)",
    ],
    "tubular": [
        "self-impressioning tubular pick",
        "manually decoded tryout",
        "destructive entry (drill at 90 degrees from each pin)",
    ],
    "padlock": [
        "shim the shackle",
        "raking / SPP as pin-tumbler",
        "bump key",
        "destructive (cut shackle, angle grinder)",
    ],
    "smart_lock": [
        "identify the reader (RFID/NFC/BLE)",
        "physical key override if present",
        "relay attack on BLE if the model is known-vulnerable",
        "firmware downgrade via UART/JTAG if accessible",
        "destructive entry",
    ],
}


def cmd_picklist(lock_type: str, out_file: str) -> int:
    key = (lock_type or "").strip().lower().replace(" ", "_")
    if not key:
        print_info("lock types available")
        for k in ATTACK_ORDERS:
            print("  " + ARTERY + "* " + RESET + k)
        return 0
    if key not in ATTACK_ORDERS:
        print_err("unknown lock type: " + key)
        print_info("available: " + ", ".join(ATTACK_ORDERS.keys()))
        return 2

    print_info("attack order: " + key)
    print()
    for i, step in enumerate(ATTACK_ORDERS[key], 1):
        print("  " + SCARLET + str(i) + ". " + RESET + step)

    out = Path(out_file) if out_file else LB_DIR / ("picklist_" + key + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"lock_type": key, "steps": ATTACK_ORDERS[key]}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_depth(pins: int, out_file: str) -> int:
    pins = pins or 5
    print_info("pin depth progression")
    print_kv("pins", str(pins))
    print()

    # Standard pin picking order — start from the back pin, work forward
    # because back pins usually bind first after tension is set.
    order = list(range(pins, 0, -1))
    for i, p in enumerate(order, 1):
        print("  " + SCARLET + "step " + str(i) + RESET + "  pin " + BONE + str(p) + RESET)

    print()
    print_info("tension first. Light tension. Start at pin " + str(order[0]) + ".")
    print_info("each pin should give a small 'click' when it sets on the shear line.")
    print_info("if a pin feels springy, it's a security pin — reset and try again.")

    out = Path(out_file) if out_file else LB_DIR / ("depth_" + str(pins) + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"pins": pins, "order": order}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_keygen(lock_type: str, depth: int, out_file: str) -> int:
    """Tryout key set: for wafer locks, all combinations of depth 1..N.
    For tubular locks, all 8 positions at the same depth."""
    depth = depth or 4
    lock_type = (lock_type or "wafer").lower()

    print_info("tryout key set")
    print_kv("lock", lock_type)
    print_kv("depth levels", str(depth))

    # generate the depth sequences
    if lock_type == "wafer":
        pins = 5
    elif lock_type == "tubular":
        pins = 8
    else:
        pins = 5

    combos = list(itertools.product(range(1, depth+1), repeat=pins))
    # tubular locks usually have all pins at the same depth, so only N keys
    if lock_type == "tubular":
        combos = [(d,) * pins for d in range(1, depth+1)]

    print_kv("candidate keys", str(len(combos)))
    print()
    for c in combos[:20]:
        print("  " + SCARLET + "* " + RESET + "-".join(str(x) for x in c))
    if len(combos) > 20:
        print("  " + ASH + "... +" + str(len(combos) - 20) + " more" + RESET)

    out = Path(out_file) if out_file else LB_DIR / ("keygen_" + lock_type + "_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"lock": lock_type, "depth": depth, "combos": combos}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_bump(target_bitting: str, out_file: str) -> int:
    """Given the target bitting (space-separated depths 1..N, shallow=1),
    print the bump-key bitting. The rule for a standard pin-tumbler is:
    each cut is one position shallower than the target, so all pins sit on
    the top of the plug when bumped."""
    if not target_bitting:
        print_err("--bitting required, e.g. '3 5 2 1 4'")
        return 2
    try:
        depths = [int(x) for x in target_bitting.replace(",", " ").split()]
    except ValueError:
        print_err("bitting must be space- or comma-separated integers")
        return 2

    # bump key: each depth shifted up by 1 (shallower)
    bump = [max(1, d - 1) for d in depths]

    print_info("bump key bitting")
    print_kv("target", " ".join(str(d) for d in depths))
    print_kv("bump key", " ".join(str(d) for d in bump))
    print()
    print_info("cut the bump key to the 'bump key' depths above")
    print_info("insert fully, pull back one pin, apply torque, strike the back of the key")

    out = Path(out_file) if out_file else LB_DIR / ("bump_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"target": depths, "bump_key": bump}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_impression(out_file: str) -> int:
    steps = [
        "obtain a key blank that matches the keyway (file down the shoulder to remove bitting)",
        "insert the blank fully into the lock",
        "apply medium torque in the opening direction",
        "rock the blank up and down 10-20 times",
        "remove the blank — look for shiny marks on the top edge of the blank",
        "file each mark with a round file (2-3 strokes), re-insert, re-torque",
        "repeat until the blank turns — usually 3-8 iterations",
        "trim the key and test on a second lock of the same keying",
    ]

    print_info("impressioning worksheet")
    print()
    for i, s in enumerate(steps, 1):
        print("  " + SCARLET + str(i) + ". " + RESET + s)

    out = Path(out_file) if out_file else LB_DIR / ("impressioning_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"steps": steps}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_decode(measurements: str, out_file: str) -> int:
    """Helper for decoding a visible lock's bitting from a photo measurement.
    Expects 'x1 y1 x2 y2 ...' pairs in millimetres from the shoulder.
    Maps each measurement to the closest depth in a common pin-tumbler range."""
    if not measurements:
        print_err("--measurements 'x1 y1 x2 y2 ...' in mm")
        return 2
    try:
        vals = [float(x) for x in measurements.replace(",", " ").split()]
    except ValueError:
        print_err("measurements must be numbers")
        return 2
    if len(vals) % 2 != 0:
        print_err("measurements must be pairs (x y)")
        return 2

    # reference depths for a common pin-tumbler range (mm from shoulder)
    # this is a rough reference; real values vary by manufacturer
    REF = {
        "1": 4.20, "2": 4.60, "3": 5.00, "4": 5.40,
        "5": 5.80, "6": 6.20, "7": 6.60,
    }

    decoded = []
    for i in range(0, len(vals), 2):
        x, y = vals[i], vals[i+1]
        # find closest depth
        best = min(REF.items(), key=lambda kv: abs(kv[1] - x))
        decoded.append({"pair": i//2 + 1, "x": x, "y": y, "depth": int(best[0])})

    print_info("bitting decode")
    for d in decoded:
        print("  " + ARTERY + "pin " + str(d["pair"]) + RESET + "  x=" + str(d["x"])
              + "  -> depth " + BONE + str(d["depth"]) + RESET)

    out = Path(out_file) if out_file else LB_DIR / ("decode_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(decoded, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky lock_bypass workflow", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["picklist", "depth", "keygen", "bump", "impression", "decode", "help"])
    p.add_argument("lock_type", nargs="?", default="")
    p.add_argument("--pins", type=int, default=5)
    p.add_argument("--depth", type=int, default=4)
    p.add_argument("--bitting", default="")
    p.add_argument("--measurements", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky lock_bypass workflow <picklist|depth|keygen|bump|impression|decode> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("picklist [lock_type]                    -- attack order; no arg = list types")
        print_info("depth [--pins 5]                        -- pin picking order")
        print_info("keygen [--lock-type wafer] [--depth 4]  -- tryout key set")
        print_info("bump --bitting '3 5 2 1 4'              -- bump-key bitting")
        print_info("impression                              -- impressioning worksheet")
        print_info("decode --measurements '4.2 0 4.6 0 ...' -- decode visible bitting")
        return 0

    if ns.action == "picklist":
        return cmd_picklist(ns.lock_type, ns.out)
    if ns.action == "depth":
        return cmd_depth(ns.pins, ns.out)
    if ns.action == "keygen":
        return cmd_keygen(ns.lock_type, ns.depth, ns.out)
    if ns.action == "bump":
        return cmd_bump(ns.bitting, ns.out)
    if ns.action == "impression":
        return cmd_impression(ns.out)
    if ns.action == "decode":
        return cmd_decode(ns.measurements, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
