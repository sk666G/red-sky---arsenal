# language: Python, file: Program/bluetooth/services.py, target: Red Sky bluetooth — GATT service dump
# Enumerate GATT services and characteristics for a BLE device. Uses bleak
# for the modern path, gatttool for the legacy fallback.

import asyncio
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


BT_DIR = OUTPUT_DIR / "bluetooth"


def _bleak_available() -> bool:
    try:
        import bleak  # noqa: F401
        return True
    except ImportError:
        return False


async def _bleak_dump(address: str, timeout: float) -> Dict:
    from bleak import BleakClient
    result = {"address": address, "services": [], "error": ""}
    try:
        async with BleakClient(address, timeout=timeout) as client:
            if not client.is_connected:
                result["error"] = "connect failed"
                return result
            for service in client.services:
                entry = {
                    "uuid": str(service.uuid),
                    "description": service.description,
                    "characteristics": [],
                }
                for char in service.characteristics:
                    c = {
                        "uuid": str(char.uuid),
                        "description": char.description,
                        "properties": list(char.properties),
                        "handle": char.handle,
                    }
                    try:
                        val = await client.read_gatt_char(char)
                        c["value_hex"] = val.hex()
                        c["value_len"] = len(val)
                    except Exception:
                        c["value_hex"] = ""
                        c["value_len"] = 0
                    entry["characteristics"].append(c)
                result["services"].append(entry)
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def _gatttool_dump(address: str, timeout: int) -> Dict:
    """Fallback path. gatttool is deprecated but still ships on many boxes."""
    result = {"address": address, "services": [], "error": ""}
    if not shutil.which("gatttool"):
        result["error"] = "gatttool not installed"
        return result

    try:
        r = subprocess.run(
            ["gatttool", "-b", address, "--primary"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        result["error"] = str(e)[:200]
        return result

    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "attr":
            result["services"].append({
                "handle_range": f"{parts[1]}-{parts[2]}",
                "uuid": parts[3] if len(parts) > 3 else "",
                "characteristics": [],
            })

    try:
        r2 = subprocess.run(
            ["gatttool", "-b", address, "--characteristics"],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in r2.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "handle:":
                result["services"].append({
                    "handle": parts[1],
                    "properties": parts[2],
                    "uuid": parts[3] if len(parts) > 3 else "",
                    "characteristics": [],
                })
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return result


def cmd_dump(address: str, timeout: float = 15.0, legacy: bool = False) -> int:
    BT_DIR.mkdir(parents=True, exist_ok=True)

    if legacy or not _bleak_available():
        if not _bleak_available():
            print(f"  {ASH}using gatttool (bleak not installed){RESET}")
        else:
            print(f"  {ASH}using gatttool (forced with --legacy){RESET}")
        result = _gatttool_dump(address, int(timeout))
    else:
        print(f"  {ASH}using bleak{RESET}")
        try:
            result = asyncio.run(_bleak_dump(address, timeout))
        except Exception as e:
            print_warn(f"bleak dump failed: {e} — falling back to gatttool")
            result = _gatttool_dump(address, int(timeout))

    if result.get("error") and not result.get("services"):
        print_err(f"dump failed: {result['error']}")
        return 1

    print()
    print_ok(f"{address}: {len(result['services'])} service(s)")
    print()

    for svc in result["services"]:
        uuid = svc.get("uuid", "?")
        desc = svc.get("description", "")
        handle = svc.get("handle_range", svc.get("handle", ""))
        print(f"  {ARTERY}{BOLD}▓ {uuid}{RESET}  {ASH}{desc}{RESET}  {CLOT}{handle}{RESET}")
        for c in svc.get("characteristics", []):
            props = ",".join(c.get("properties", [])) if isinstance(c.get("properties"), list) else str(c.get("properties", ""))
            cv = c.get("uuid", "?")
            vlen = c.get("value_len", 0)
            print(f"    {ARTERY}▶{RESET} {BONE}{cv}{RESET}  {ASH}[{props}]{RESET}  "
                  f"{CLOT}{vlen} bytes{RESET}")
            if c.get("value_hex"):
                vh = c["value_hex"]
                shown = vh if len(vh) <= 40 else vh[:40] + "…"
                print(f"        {CLOT}{shown}{RESET}")

    out = BT_DIR / f"gatt_{address.replace(':', '')}_{int(time.time())}.json"
    out.write_text(json.dumps(result, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky bluetooth services <MAC> [--timeout N] [--legacy]")
        return 2
    address = args[0]
    timeout = 15.0
    if "--timeout" in args:
        i = args.index("--timeout")
        if i + 1 < len(args):
            timeout = float(args[i + 1])
    return cmd_dump(address, timeout, legacy="--legacy" in args)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
