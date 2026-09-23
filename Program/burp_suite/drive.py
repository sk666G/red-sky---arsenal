# language: Python, file: Program/burp_suite/drive.py, target: Red Sky burp_suite — headless Burp driver
# Wraps Burp Suite (Community + Pro):
#   find    -- locate the burp jar / launcher on this host
#   launch  -- start Burp in headless mode with a project file + no GUI
#   ext     -- generate a starter Burp extension (Java or Python/Jython)
#   api     -- speak to the Burp REST API (Pro only) for scope + scan control
#   proxy   -- configure a Chrome/Chromium to route through Burp via --proxy-server
# Does not include Burp itself.

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


BS_DIR = OUTPUT_DIR / "burp_suite"
BS_DIR.mkdir(parents=True, exist_ok=True)


BURP_SEARCH_PATHS = [
    "~/BurpSuiteCommunity/burpsuite_community.jar",
    "~/BurpSuitePro/burpsuite_pro.jar",
    "/opt/BurpSuiteCommunity/burpsuite_community.jar",
    "/opt/BurpSuitePro/burpsuite_pro.jar",
    "/usr/share/burpsuite/burpsuite.jar",
    "/usr/local/bin/burpsuite",
    "/usr/bin/burpsuite",
]


def cmd_find(out_file: str) -> int:
    print_info("locating Burp Suite")
    found = []
    for p in BURP_SEARCH_PATHS:
        path = Path(p).expanduser()
        if path.exists():
            kind = "pro" if "pro" in path.name.lower() else "community"
            found.append({"path": str(path), "kind": kind})
            print("  " + SCARLET + "▓ " + RESET + BONE + kind.ljust(10) + RESET + str(path))
    # also check PATH
    for name in ("burpsuite", "burpsuite_pro", "burpsuite_community"):
        p = shutil.which(name)
        if p:
            found.append({"path": p, "kind": "pro" if "pro" in name else "community"})
            print("  " + SCARLET + "▓ " + RESET + BONE + "path".ljust(10) + RESET + p)
    if not found:
        print_warn("no Burp Suite found")
        print_info("download: https://portswigger.net/burp/releases")

    out = Path(out_file) if out_file else BS_DIR / ("find_" + str(int(time.time())) + ".json")
    out.write_text(json.dumps(found, indent=2))
    print()
    print_kv("saved", out)
    return 0


def cmd_launch(jar: str, project: str, headless: bool, config: str) -> int:
    if not jar:
        # try to auto-detect
        for p in BURP_SEARCH_PATHS:
            path = Path(p).expanduser()
            if path.exists():
                jar = str(path)
                break
    if not jar:
        print_err("no Burp jar located — pass --jar")
        return 2
    if not Path(jar).exists():
        print_err("jar not found: " + jar)
        return 2

    project = project or str(BS_DIR / ("project_" + str(int(time.time())) + ".burp"))
    cmd = ["java"]
    if headless:
        cmd += ["-Djava.awt.headless=true"]
    cmd += ["-jar", jar, "--project-file", project]
    if config:
        cmd += ["--config-file", config]
    if headless:
        # Burp headless needs a special flag (Pro only)
        cmd += ["--unpause-spider-and-scanner"] if os.path.exists("/tmp/fake") else []

    print_info("Burp launch")
    print_kv("jar", jar)
    print_kv("project", project)
    print_kv("headless", "yes" if headless else "no")
    print_kv("cmd", " ".join(cmd))
    print()
    print_warn("headless mode is a Pro-only feature. Community will still try to open a window.")

    try:
        subprocess.Popen(cmd)
        print_ok("launched")
    except FileNotFoundError:
        print_err("java not found — install a JRE")
        return 1
    return 0


def cmd_ext(name: str, lang: str, out_dir: str) -> int:
    name = name or "RedSkyExtension"
    lang = (lang or "java").lower()
    target = Path(out_dir) if out_dir else BS_DIR / ("ext_" + name)
    target.mkdir(parents=True, exist_ok=True)

    if lang == "java":
        (target / (name + ".java")).write_text(
            "// Burp extension scaffold — Java\n"
            "// Build with the Burp Extender API:\n"
            "//   javac -cp burp.jar " + name + ".java\n"
            "// Load the .class in Burp: Extender -> Extensions -> Add\n\n"
            "import burp.*;\n\n"
            "public class " + name + " implements BurpExtension {\n"
            "    public void initialize(MontoyaApi api) {\n"
            "        api.extension().setName(\"" + name + "\");\n\n"
            "        api.http().registerHttpHandler(new HttpHandler() {\n"
            "            @Override\n"
            "            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent r) {\n"
            "                api.logging().logToOutput(\"[req] \" + r.method() + \" \" + r.url());\n"
            "                return RequestToBeSentAction.continueWith(r);\n"
            "            }\n\n"
            "            @Override\n"
            "            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r) {\n"
            "                return ResponseReceivedAction.continueWith(r);\n"
            "            }\n"
            "        });\n\n"
            "        api.logging().logToOutput(\"" + name + " loaded\");\n"
            "    }\n"
            "}\n"
        )
        (target / "build.sh").write_text(
            "#!/bin/bash\n"
            "# download burp.jar from https://portswigger.net/burp/extender/api/burp-extender-api.jar\n"
            "javac -cp burp-extender-api.jar:. " + name + ".java\n"
        )
        print_ok("wrote " + str(target / (name + ".java")))
    elif lang in ("python", "jython"):
        (target / (name + ".py")).write_text(
            "# Burp extension scaffold — Jython (load via Extender -> Python)\n"
            "from burp import IBurpExtender, IHttpListener\n\n"
            "class BurpExtender(IBurpExtender, IHttpListener):\n"
            "    def registerExtenderCallbacks(self, callbacks):\n"
            "        self._callbacks = callbacks\n"
            "        self._helpers = callbacks.getHelpers()\n"
            "        callbacks.setExtensionName('" + name + "')\n"
            "        callbacks.registerHttpListener(self)\n"
            "        print('" + name + " loaded')\n\n"
            "    def processHttpMessage(self, tool, is_request, content):\n"
            "        if is_request:\n"
            "            req = self._helpers.analyzeRequest(content)\n"
            "            print('[req]', req.getMethod(), req.getUrl())\n"
        )
        print_ok("wrote " + str(target / (name + ".py")))
    else:
        print_err("unknown lang: " + lang + " (java|python)")
        return 2

    print_kv("dir", str(target))
    print_kv("lang", lang)
    return 0


def cmd_api(host: str, port: int, key: str, action: str, url: str, out_file: str) -> int:
    """Burp Pro REST API client."""
    base = "http://" + (host or "127.0.0.1") + ":" + str(port or 1337)
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key

    try:
        import requests
    except ImportError:
        print_err("requests not installed")
        return 2

    endpoints = {
        "status":   ("GET",  "/v0.1/status"),
        "scope":    ("GET",  "/v0.1/target/scope"),
        "scope_add":("POST", "/v0.1/target/scope"),
        "scan":     ("POST", "/v0.1/scan"),
        "scans":    ("GET",  "/v0.1/scan"),
        "config":   ("GET",  "/v0.1/configuration"),
    }
    if action not in endpoints:
        print_err("unknown action: " + action)
        print_info("available: " + ", ".join(endpoints.keys()))
        return 2
    method, path = endpoints[action]
    full = base + path

    print_info("Burp REST API")
    print_kv("method", method)
    print_kv("url", full)
    body = None
    if action == "scope_add" and url:
        body = {"url": url}
    elif action == "scan" and url:
        body = {"urls": [url]}
    if body:
        print_kv("body", json.dumps(body))

    try:
        if method == "GET":
            r = requests.get(full, headers=headers, timeout=15)
        else:
            r = requests.post(full, headers=headers, json=body, timeout=15)
        print_kv("status", str(r.status_code))
        print(r.text[:1000])
    except Exception as e:
        print_err("request failed: " + str(e))
        return 1

    out = Path(out_file) if out_file else BS_DIR / ("api_" + action + "_" + str(int(time.time())) + ".json")
    out.write_text(r.text)
    print()
    print_kv("saved", out)
    return 0


def cmd_proxy(browser: str, port: int, url: str, no_verify: bool) -> int:
    exes = {
        "chrome":   ["google-chrome", "google-chrome-stable"],
        "chromium": ["chromium", "chromium-browser"],
        "edge":     ["microsoft-edge"],
        "brave":    ["brave-browser"],
        "firefox":  ["firefox"],
    }
    cands = exes.get(browser.lower(), [browser])
    exe = None
    for c in cands:
        exe = shutil.which(c)
        if exe:
            break
    if not exe:
        print_err("browser not found: " + browser)
        return 2

    profile = BS_DIR / ("browser_profile_" + str(int(time.time())))
    profile.mkdir(parents=True, exist_ok=True)

    cmd = [
        exe,
        "--user-data-dir=" + str(profile),
        "--proxy-server=http://127.0.0.1:" + str(port or 8080),
        "--proxy-bypass-list=<-loopback>",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if no_verify:
        cmd.append("--ignore-certificate-errors")
    if url:
        cmd.append(url)

    print_info("browser via Burp")
    print_kv("exe", exe)
    print_kv("proxy", "http://127.0.0.1:" + str(port or 8080))
    print_kv("profile", str(profile))
    print_kv("cmd", " ".join(cmd))
    print()
    print_info("in Burp: Proxy -> Options -> make sure the listener is on 127.0.0.1:" + str(port or 8080))
    print_info("install Burp's CA cert: http://burp in this browser, download cert, trust it")

    try:
        subprocess.Popen(cmd)
        print_ok("launched")
    except Exception as e:
        print_err("launch failed: " + str(e))
        return 1
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky burp_suite drive", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["find", "launch", "ext", "api", "proxy", "help"])
    p.add_argument("--jar", default="")
    p.add_argument("--project", default="")
    p.add_argument("--config", default="")
    p.add_argument("--headless", action="store_true")
    p.add_argument("--name", default="RedSkyExtension")
    p.add_argument("--lang", default="java", choices=["java", "python"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=1337)
    p.add_argument("--key", default="")
    p.add_argument("--url", default="")
    p.add_argument("--browser", default="chrome")
    p.add_argument("--proxy-port", type=int, default=8080)
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky burp_suite drive <find|launch|ext|api|proxy> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("find                        -- locate Burp installs on this host")
        print_info("launch [--jar X] [--project Y] [--headless]")
        print_info("ext [--name X] [--lang java|python]  -- Burp extension scaffold")
        print_info("api --action status|scope|scan|scans  -- Burp Pro REST")
        print_info("proxy [--browser chrome] [--port 8080] [--url https://target]")
        return 0

    if ns.action == "find":
        return cmd_find(ns.out)
    if ns.action == "launch":
        return cmd_launch(ns.jar, ns.project, ns.headless, ns.config)
    if ns.action == "ext":
        return cmd_ext(ns.name, ns.lang, ns.out)
    if ns.action == "api":
        return cmd_api(ns.host, ns.port, ns.key, ns.action, ns.url, ns.out)
    if ns.action == "proxy":
        return cmd_proxy(ns.browser, ns.proxy_port, ns.url, ns.no_verify)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
