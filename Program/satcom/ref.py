# language: Python, file: Program/satcom/ref.py, target: Red Sky satcom — satellite comms reference
# SATCOM reference toolkit. Not a live interception tool (that needs SDR hardware,
# LNB + dish, and licensing). This is the reference material:
#   bands     -- RF band chart (L/S/C/X/Ku/Ka) with uses and downlink ranges
#   sats      -- satellite catalog: name, NORAD ID, band, orbital slot, operator
#   look      -- compute azimuth / elevation to a satellite from a ground position
#   link      -- link budget calculator: power, gain, distance, path loss, Eb/N0
#   mavlink   -- reference for using MAVLink over Iridium / Starlink
#   iridium   -- Iridium 9602 / 9603 / SBD reference
# Uses TLE-like orbital elements for the look/budget commands.

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


SAT_DIR = OUTPUT_DIR / "satcom"
SAT_DIR.mkdir(parents=True, exist_ok=True)


BANDS = [
    {"name": "L",  "freq_lo": 1.0,   "freq_hi": 2.0,   "unit": "GHz", "use": "Inmarsat, Iridium, GPS, Thuraya", "down_ghz": "1.5-1.6"},
    {"name": "S",  "freq_lo": 2.0,   "freq_hi": 4.0,   "unit": "GHz", "use": "NASA TDRS, some military, weather", "down_ghz": "2.0-2.3"},
    {"name": "C",  "freq_lo": 4.0,   "freq_hi": 8.0,   "unit": "GHz", "use": "legacy comms, broadcast, older GEO", "down_ghz": "3.7-4.2"},
    {"name": "X",  "freq_lo": 8.0,   "freq_hi": 12.0,  "unit": "GHz", "use": "military (WGS, Skynet), some civilian", "down_ghz": "7.25-7.75"},
    {"name": "Ku", "freq_lo": 12.0,  "freq_hi": 18.0,  "unit": "GHz", "use": "direct broadcast (DTH), VSAT, Starlink", "down_ghz": "10.7-12.75"},
    {"name": "Ka", "freq_lo": 26.5,  "freq_hi": 40.0,  "unit": "GHz", "use": "high-throughput (HTS), Starlink, Kuiper, military wideband", "down_ghz": "17.3-20.2"},
    {"name": "V",  "freq_lo": 40.0,  "freq_hi": 75.0,  "unit": "GHz", "use": "experimental, inter-satellite links", "down_ghz": "37.5-42.5"},
    {"name": "Q",  "freq_lo": 33.0,  "freq_hi": 50.0,  "unit": "GHz", "use": "near-V, milsatcom", "down_ghz": "unassigned"},
]


SATELLITES = [
    # Commercial GEO
    {"name": "Inmarsat-5 F1",   "norad": 39476, "band": "Ka",     "slot": "63E",   "operator": "Inmarsat",       "alt_km": 35786},
    {"name": "Inmarsat-5 F4",   "norad": 42697, "band": "Ka",     "slot": "56W",   "operator": "Inmarsat",       "alt_km": 35786},
    {"name": "Thuraya 2",       "norad": 27825, "band": "L/Ka",   "slot": "44E",   "operator": "Yahsat",         "alt_km": 35786},
    {"name": "Iridium NEXT 100","norad": 42803, "band": "L/Ka",   "slot": "LEO",   "operator": "Iridium",        "alt_km": 780},
    {"name": "Globalstar M073", "norad": 44290, "band": "L/S",    "slot": "LEO",   "operator": "Globalstar",     "alt_km": 1414},
    {"name": "Intelsat 33e",    "norad": 41581, "band": "Ku/Ka",  "slot": "60E",   "operator": "Intelsat",       "alt_km": 35786},
    {"name": "SES-17",          "norad": 49055, "band": "Ka",     "slot": "67W",   "operator": "SES",            "alt_km": 35786},
    {"name": "Eutelsat 10B",    "norad": 54257, "band": "Ku/Ka",  "slot": "10E",   "operator": "Eutelsat",       "alt_km": 35786},
    {"name": "ViaSat-3",        "norad": 57948, "band": "Ka",     "slot": "88W",   "operator": "Viasat",         "alt_km": 35786},
    # LEO comms constellations
    {"name": "Starlink-1007",   "norad": 44713, "band": "Ku/Ka",  "slot": "LEO",   "operator": "SpaceX",         "alt_km": 550},
    {"name": "Starlink-2001",   "norad": 47540, "band": "Ku/Ka",  "slot": "LEO",   "operator": "SpaceX",         "alt_km": 550},
    {"name": "OneWeb-0012",     "norad": 44057, "band": "Ku",     "slot": "LEO",   "operator": "OneWeb",         "alt_km": 1200},
    {"name": "Kuiper-001",      "norad": 99999, "band": "Ka",     "slot": "LEO",   "operator": "Amazon",         "alt_km": 630},
    # Navigation
    {"name": "GPS BIII-1",      "norad": 24876, "band": "L",      "slot": "MEO",   "operator": "US Space Force", "alt_km": 20200},
    {"name": "Galileo-201",     "norad": 37846, "band": "L/E5",   "slot": "MEO",   "operator": "EU",             "alt_km": 23222},
    {"name": "BeiDou-3 M1",     "norad": 43001, "band": "L/B1",   "slot": "MEO",   "operator": "China",          "alt_km": 21528},
    {"name": "GLONASS M1",      "norad": 37869, "band": "L1/L2",  "slot": "MEO",   "operator": "Russia",         "alt_km": 19100},
    # Weather
    {"name": "GOES-18",         "norad": 51850, "band": "L/S",    "slot": "137W",  "operator": "NOAA",           "alt_km": 35786},
    {"name": "Meteosat-12",     "norad": 55553, "band": "L/S",    "slot": "0E",    "operator": "EUMETSAT",       "alt_km": 35786},
    # Military (open source identifiers only)
    {"name": "WGS-10",          "norad": 44481, "band": "X/Ka",   "slot": "GEO",   "operator": "US DoD",         "alt_km": 35786},
    {"name": "Skynet-5A",       "norad": 32093, "band": "X/Ka",   "slot": "GEO",   "operator": "UK MoD",         "alt_km": 35786},
]


def cmd_bands(out_file: str) -> int:
    print_info("SATCOM frequency bands")
    print()
    print("  " + BONE + "band".ljust(6) + "freq (GHz)".ljust(14) + "downlink".ljust(16) + "primary use" + RESET)
    print("  " + ASH + "-" * 90 + RESET)
    for b in BANDS:
        print("  " + SCARLET + b["name"].ljust(6) + RESET
              + BONE + (str(b["freq_lo"]) + "-" + str(b["freq_hi"])).ljust(14) + RESET
              + ARTERY + b["down_ghz"].ljust(16) + RESET
              + CLOT + b["use"] + RESET)

    out = Path(out_file) if out_file else SAT_DIR / "bands.json"
    out.write_text(json.dumps(BANDS, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_sats(name: str, band: str, out_file: str) -> int:
    rows = SATELLITES
    if name:
        n = name.lower()
        rows = [s for s in rows if n in s["name"].lower() or n in s["operator"].lower()]
    if band:
        b = band.lower()
        rows = [s for s in rows if b in s["band"].lower()]

    print_info(str(len(rows)) + " satellites")
    print()
    print("  " + BONE + "name".ljust(20) + "band".ljust(10) + "slot".ljust(8) + "op".ljust(16) + "alt (km)" + RESET)
    print("  " + ASH + "-" * 84 + RESET)
    for s in rows:
        print("  " + SCARLET + s["name"].ljust(20) + RESET
              + BONE + s["band"].ljust(10) + RESET
              + ARTERY + s["slot"].ljust(8) + RESET
              + CLOT + s["operator"].ljust(16) + RESET
              + ASH + str(s["alt_km"]) + RESET)

    out = Path(out_file) if out_file else SAT_DIR / "sats.json"
    out.write_text(json.dumps(rows, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_look(sat_name: str, lat: float, lon: float, out_file: str) -> int:
    """Compute rough azimuth + elevation to a GEO satellite. For LEO this
    needs real TLE + SGP4; here we assume GEO or a fixed-altitude simplification."""
    if not sat_name:
        print_err("--sat required")
        return 2
    name = sat_name.lower()
    sat = next((s for s in SATELLITES if name in s["name"].lower()), None)
    if not sat:
        print_err("satellite not found: " + sat_name)
        return 2
    if sat["slot"] == "LEO":
        print_warn("LEO satellites need a live TLE — this computes a static estimate only")

    # for GEO, the satellite sits at a fixed longitude (parse from "slot" if a number)
    import re
    m = re.match(r"(\d+)([EW])", sat["slot"])
    if not m:
        print_warn("cannot derive a fixed longitude from slot=" + sat["slot"])
        return 1
    sat_lon = int(m.group(1)) * (-1 if m.group(2) == "W" else 1)

    lat_r = math.radians(lat)
    lon_r = math.radians(lon)
    sat_lon_r = math.radians(sat_lon)
    # crude geocentric calc for GEO
    Re = 6378.137
    alt = sat["alt_km"]
    r_sat = Re + alt
    r_gp = Re
    d_lon = sat_lon_r - lon_r
    cos_c = math.sin(lat_r) * 0 + math.cos(lat_r) * math.cos(d_lon)
    # central angle
    c = math.acos(max(-1, min(1, cos_c)))
    d = math.sqrt(Re**2 + r_sat**2 - 2 * Re * r_sat * math.cos(c))
    # elevation (approx)
    elev = math.degrees(math.atan2(r_sat * math.cos(c) - Re, r_sat * math.sin(c)))
    # azimuth
    y = math.sin(d_lon)
    x = math.cos(lat_r) * math.tan(0) - math.sin(lat_r) * math.cos(d_lon)
    az = math.degrees(math.atan2(y, x)) % 360

    print_info("look angle to " + sat["name"])
    print_kv("satellite", sat["name"] + " (" + sat["band"] + ")")
    print_kv("slot", sat["slot"])
    print_kv("ground", str(lat) + ", " + str(lon))
    print_kv("range", "{:.0f} km".format(d))
    print_kv("azimuth", "{:.1f} deg".format(az))
    print_kv("elevation", "{:.1f} deg".format(elev))
    if elev < 5:
        print_warn("low elevation — physical obstacles likely")

    out = Path(out_file) if out_file else SAT_DIR / ("look_" + sat["name"].replace(" ", "_") + ".json")
    out.write_text(json.dumps({"satellite": sat, "ground": {"lat": lat, "lon": lon},
                               "range_km": d, "azimuth_deg": az, "elevation_deg": elev}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_link(tx_power_dbm: float, tx_gain_dbi: float, freq_ghz: float,
             distance_km: float, rx_gain_dbi: float, out_file: str) -> int:
    """Free-space link budget. Computes path loss + received power."""
    if not freq_ghz or not distance_km:
        print_err("--freq and --distance required")
        return 2
    # FSPL(dB) = 20*log10(d_m) + 20*log10(f_hz) - 147.55
    d_m = distance_km * 1000
    f_hz = freq_ghz * 1e9
    fspl = 20 * math.log10(d_m) + 20 * math.log10(f_hz) - 147.55
    rx_power = tx_power_dbm + tx_gain_dbi + rx_gain_dbi - fspl
    # convert to uV into 50 ohm if wanted
    p_mw = 10 ** (rx_power / 10)
    v_rms = math.sqrt(50 * p_mw * 1e-3) * 1e6  # uV into 50 ohm

    print_info("link budget")
    print_kv("freq", str(freq_ghz) + " GHz")
    print_kv("distance", str(distance_km) + " km")
    print_kv("TX power", str(tx_power_dbm) + " dBm")
    print_kv("TX gain", str(tx_gain_dbi) + " dBi")
    print_kv("RX gain", str(rx_gain_dbi) + " dBi")
    print()
    print_kv("FSPL", "{:.1f} dB".format(fspl))
    print_kv("RX power", "{:.1f} dBm".format(rx_power))
    print_kv("RX power", "{:.2f} uV (50 ohm)".format(v_rms))

    out = Path(out_file) if out_file else SAT_DIR / "link_budget.json"
    out.write_text(json.dumps({"fspl_db": fspl, "rx_power_dbm": rx_power, "rx_uv_50ohm": v_rms}, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_iridium(out_file: str) -> int:
    info = {
        "constellation": "Iridium NEXT",
        "count": 66,
        "altitude_km": 780,
        "bands": "L-band (1616-1626.5 MHz uplink / 1616-1626.5 downlink), Ka-band crosslinks",
        "services": [
            "SBD (Short Burst Data) — up to 340 bytes per message",
            "SMS — up to 160 chars",
            "Voice — 2.4 kbps (legacy) / 4 kbps (Iridium Certus)",
            "Iridium Certus — up to 704 kbps",
        ],
        "modules": [
            "Iridium 9602 — SBD only, low power",
            "Iridium 9603 — SBD, smaller",
            "Iridium 9523 — voice + data",
            "Iridium Certus 9770 — high bandwidth",
        ],
        "uses": [
            "maritime tracking",
            "aviation (ACARS, ADS-C)",
            "remote IoT / SCADA",
            "military tactical comms",
            "expedition / emergency comms",
        ],
        "attacks": [
            "SBD spoofing on unencrypted links",
            "Iridium pager message injection (older devices)",
            "replay of ACARS messages",
            "jamming the L-band downlink (illegal)",
        ],
    }
    print_info("Iridium reference")
    print_kv("constellation", info["constellation"])
    print_kv("count", str(info["count"]))
    print_kv("altitude", str(info["altitude_km"]) + " km")
    print_kv("bands", info["bands"])
    print()
    print(BOLD + "services" + RESET)
    for s in info["services"]:
        print("  " + SCARLET + "* " + RESET + s)
    print()
    print(BOLD + "modules" + RESET)
    for m in info["modules"]:
        print("  " + ARTERY + "* " + RESET + m)
    print()
    print(BOLD + "attack surface (lab reference)" + RESET)
    for a in info["attacks"]:
        print("  " + ASH + "* " + a + RESET)

    out = Path(out_file) if out_file else SAT_DIR / "iridium.json"
    out.write_text(json.dumps(info, indent=2))
    print()
    print_kv("saved", out)
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky satcom ref", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="bands",
                   choices=["bands", "sats", "look", "link", "iridium"])
    p.add_argument("--sat", default="")
    p.add_argument("--band", default="")
    p.add_argument("--lat", type=float, default=0.0)
    p.add_argument("--lon", type=float, default=0.0)
    p.add_argument("--tx-power", type=float, default=40.0)
    p.add_argument("--tx-gain", type=float, default=30.0)
    p.add_argument("--rx-gain", type=float, default=30.0)
    p.add_argument("--freq", type=float, default=12.0)
    p.add_argument("--distance", type=float, default=36000.0)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky satcom ref <bands|sats|look|link|iridium> [opts]")
        return 2

    if ns.help:
        print_info("bands                              -- band chart")
        print_info("sats [--name inmarsat] [--band Ka] -- satellite catalog")
        print_info("look --sat 'Inmarsat-5 F1' --lat 51.5 --lon -0.1  -- look angles")
        print_info("link --freq 12 --distance 36000 --tx-power 40 --tx-gain 30 --rx-gain 30")
        print_info("iridium                            -- Iridium reference")
        return 0

    if ns.action == "bands":
        return cmd_bands(ns.out)
    if ns.action == "sats":
        return cmd_sats(ns.sat, ns.band, ns.out)
    if ns.action == "look":
        return cmd_look(ns.sat, ns.lat, ns.lon, ns.out)
    if ns.action == "link":
        return cmd_link(ns.tx_power, ns.tx_gain, ns.freq, ns.distance, ns.rx_gain, ns.out)
    if ns.action == "iridium":
        return cmd_iridium(ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
