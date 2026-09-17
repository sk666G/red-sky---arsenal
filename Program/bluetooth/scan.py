# language: Python, file: Program/bluetooth/scan.py, target: Red Sky bluetooth — BLE scan
# Primary: bleak (async BLE). Fallback: hcitool lescan for classic discovery.

import asyncio
import json
import os
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


def _ensure_hci_up():
    """If hci0 is DOWN, try to bring it up. Needs root."""
    if not shutil.which("hciconfig"):
        return
    try:
        r = subprocess.run(["hciconfig"], capture_output=True, text=True, timeout=5)
        if "DOWN" in r.stdout and os.geteuid() == 0:
            subprocess.run(["hciconfig", "hci0", "up"], timeout=5)
            time.sleep(1)
    except Exception:
        pass


async def _bleak_scan(duration: float) -> List[Dict]:
    from bleak import BleakScanner
    seen: Dict[str, Dict] = {}

    def _cb(device, adv):
        addr = device.address
        seen[addr] = {
            "address": addr,
            "name": device.name or adv.local_name or "",
            "rssi": adv.rssi,
            "tx_power": adv.tx_power,
            "manufacturer_data": {str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()},
            "service_uuids": adv.service_uuids or [],
            "service_data": {str(k): v.hex() for k, v in (adv.service_data or {}).items()},
            "last_seen": time.time(),
        }

    scanner = BleakScanner(detection_callback=_cb)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()
    return list(seen.values())


def _bleak_available() -> bool:
    try:
        import bleak  # noqa: F401
        return True
    except ImportError:
        return False


def _hcitool_scan(duration: int) -> List[Dict]:
    """Fallback — hcitool lescan for LE discovery only. Slower, less data."""
    if not shutil.which("hcitool"):
        return []
    seen: Dict[str, Dict] = {}
    try:
        proc = subprocess.Popen(["hcitool", "lescan", "--duplicates"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1)
    except (subprocess.SubprocessError, FileNotFoundError):
        return []
    t0 = time.time()
    for line in proc.stdout:
        line = line.rstrip()
        parts = line.split(None, 1)
        if len(parts) == 2 and ":" in parts[0] and len(parts[0]) == 17:
            addr, name = parts[0], parts[1].strip()
            if addr not in seen:
                seen[addr] = {"address": addr, "name": name, "rssi": None,
                              "manufacturer_data": {}, "service_uuids": [],
                              "service_data": {}, "last_seen": time.time()}
        if time.time() - t0 > duration:
            break
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
    return list(seen.values())


def cmd_scan(duration: int = 10) -> int:
    _ensure_hci_up()
    BT_DIR.mkdir(parents=True, exist_ok=True)

    print_info(f"BLE scan for {duration}s")
    print()

    if _bleak_available():
        print(f"  {ASH}using bleak (async BLE){RESET}")
        try:
            devices = asyncio.run(_bleak_scan(duration))
        except Exception as e:
            print_warn(f"bleak scan failed: {e} — falling back to hcitool")
            devices = _hcitool_scan(duration)
    else:
        print(f"  {ASH}using hcitool (bleak not installed){RESET}")
        devices = _hcitool_scan(duration)

    if not devices:
        print_warn("no devices found")
        print_info("is hci0 up? sudo hciconfig hci0 up")
        return 1

    print()
    print_ok(f"{len(devices)} device(s)")
    print()
    print(f"{ARTERY}{BOLD}  ADDRESS              RSSI  NAME                              SERVICES{RESET}")
    for d in sorted(devices, key=lambda x: -(x.get("rssi") or -200)):
        rssi = f"{d['rssi']:>4}" if d.get("rssi") is not None else "  ? "
        name = (d.get("name") or "(unknown)")[:32]
        svcs = len(d.get("service_uuids", []))
        mfg = len(d.get("manufacturer_data", {}))
        extra = f"{svcs} svc, {mfg} mfg"
        print(f"  {ARTERY}▓{RESET} {BONE}{d['address']}{RESET}  {SCARLET}{rssi}{RESET}  "
              f"{BONE}{name:<32}{RESET} {ASH}{extra}{RESET}")

    out = BT_DIR / f"scan_{int(time.time())}.json"
    out.write_text(json.dumps(devices, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args) -> int:
    if not args:
        print_err("usage: redsky bluetooth scan [--duration N]")
        return 2
    dur = 10
    if "--duration" in args:
        i = args.index("--duration")
        if i + 1 < len(args):
            dur = int(args[i + 1])
    return cmd_scan(dur)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
