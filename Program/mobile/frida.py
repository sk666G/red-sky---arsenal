# language: Python, file: Program/mobile/frida.py, target: Red Sky mobile — Frida hook scaffolding
# Wraps frida-tools. Generates hook scripts for common targets:
#   - ssl unpinning (Android + iOS)
#   - root/jailbreak detection bypass
#   - crypto key dump (AES/CommonCrypto/Java crypto)
#   - network request dump (OkHttp / NSURLSession)
#   - shared prefs dump
# Attach by process name or PID.

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


MOB_DIR = OUTPUT_DIR / "mobile"
HOOKS_DIR = MOB_DIR / "frida_hooks"


HOOK_SSL_UNPIN_ANDROID = r"""
// Android SSL unpinning — TrustManager, X509TrustManager, OkHttp, Conscrypt
Java.perform(function () {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.rs.TrustAll',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });

    var TrustManagers = [TrustManager.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    SSLContext_init.implementation = function (km, tm, sr) {
        SSLContext_init.call(this, km, TrustManagers, sr);
        console.log('[+] SSLContext.init patched');
    };

    // OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
            console.log('[+] OkHttp CertificatePinner.check bypassed');
            return;
        };
    } catch (e) {}

    // TrustManagerImpl (Android's default)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function () {
            console.log('[+] Conscrypt verifyChain bypassed');
            return arguments[0];
        };
    } catch (e) {}

    // HostnameVerifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        // Replace verifier returns from OkHttp
        var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
            return true;
        };
    } catch (e) {}

    console.log('[+] SSL unpin hooks installed (Android)');
});
"""


HOOK_SSL_UNPIN_IOS = r"""
// iOS SSL unpinning — SecTrustEvaluate, SSL_set_verify, NSURLSession
if (ObjC.available) {
    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
    if (SecTrustEvaluate) {
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
            Memory.writeU32(result, 1);  // kSecTrustResultProceed
            console.log('[+] SecTrustEvaluate forced to Proceed');
            return 0;
        }, 'int', ['pointer', 'pointer']));
    }

    var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, err) {
            return 1;
        }, 'int', ['pointer', 'pointer']));
    }

    // NSURLSession delegate
    try {
        var delegate = ObjC.classes.NSURLSession;
        var orig = delegate['- URLSession:didReceiveChallenge:completionHandler:'];
        if (orig) {
            Interceptor.attach(orig.implementation, {
                onEnter: function (args) {
                    var completion = new ObjC.Block(args[4]);
                    var origImpl = completion.implementation;
                    completion.implementation = function (disposition, credential) {
                        origImpl(0, credential);  // NSURLSessionAuthChallengeUseCredential
                        console.log('[+] NSURLSession challenge accepted');
                    };
                }
            });
        }
    } catch (e) {}

    console.log('[+] SSL unpin hooks installed (iOS)');
}
"""


HOOK_ROOT_BYPASS = r"""
// Root / jailbreak / debugger detection bypass
Java.perform(function () {
    var common = [
        'java.io.File',
        'java.lang.Runtime',
        'android.app.ActivityManager',
        'android.os.Build'
    ];

    // File.exists() -> false for known root paths
    var File = Java.use('java.io.File');
    var _exists = File.exists;
    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        if (p.indexOf('su') >= 0 || p.indexOf('magisk') >= 0 || p.indexOf('supersu') >= 0 ||
            p.indexOf('busybox') >= 0 || p.indexOf('xposed') >= 0 || p.indexOf('frida') >= 0) {
            console.log('[+] File.exists(' + p + ') -> false');
            return false;
        }
        return _exists.call(this);
    };

    // Runtime.exec -> filter "su"
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd.indexOf('su') >= 0) {
                console.log('[+] Runtime.exec(su) blocked');
                return null;
            }
            return this.exec(cmd);
        };
    } catch (e) {}

    console.log('[+] root-detection bypass installed');
});
"""


HOOK_CRYPTO_DUMP = r"""
// Crypto key + plaintext dump — Java Cipher, MessageDigest, Mac, CommonCrypto
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (data) {
        var out = this.doFinal(data);
        console.log('[Cipher.doFinal] alg=' + this.getAlgorithm() + ' in=' + bytesToHex(data) + ' out=' + bytesToHex(out));
        return out;
    };

    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function (data) {
        var out = this.digest(data);
        console.log('[MessageDigest] alg=' + this.getAlgorithm() + ' in=' + bytesToHex(data) + ' out=' + bytesToHex(out));
        return out;
    };

    try {
        var Mac = Java.use('javax.crypto.Mac');
        Mac.doFinal.overload('[B').implementation = function (data) {
            var out = this.doFinal(data);
            console.log('[Mac.doFinal] alg=' + this.getAlgorithm() + ' out=' + bytesToHex(out));
            return out;
        };
    } catch (e) {}

    console.log('[+] crypto dump hooks installed');
});

function bytesToHex(b) {
    if (!b) return '';
    var s = '';
    for (var i = 0; i < b.length; i++) {
        var h = (b[i] & 0xff).toString(16);
        if (h.length === 1) h = '0' + h;
        s += h;
    }
    return s;
}
"""


HOOK_NETWORK_DUMP = r"""
// Network request dump — OkHttp + common HTTP libs
Java.perform(function () {
    try {
        var Request = Java.use('okhttp3.Request');
        Request.toString.implementation = function () {
            var s = this.toString();
            console.log('[OkHttp Request] ' + s);
            return s;
        };
    } catch (e) {}

    try {
        var Response = Java.use('okhttp3.Response');
        Response.toString.implementation = function () {
            var s = this.toString();
            console.log('[OkHttp Response] ' + s);
            return s;
        };
    } catch (e) {}

    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            console.log('[URL.openConnection] ' + this.toString());
            return this.openConnection();
        };
    } catch (e) {}

    console.log('[+] network dump hooks installed');
});
"""


HOOK_PREFS_DUMP = r"""
// SharedPreferences dump
Java.perform(function () {
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferencesImpl.getString.implementation = function (key, def) {
        var v = this.getString(key, def);
        console.log('[prefs.getString] ' + key + ' = ' + v);
        return v;
    };
    SharedPreferencesImpl.getInt.implementation = function (key, def) {
        var v = this.getInt(key, def);
        console.log('[prefs.getInt] ' + key + ' = ' + v);
        return v;
    };
    SharedPreferencesImpl.getBoolean.implementation = function (key, def) {
        var v = this.getBoolean(key, def);
        console.log('[prefs.getBool] ' + key + ' = ' + v);
        return v;
    };
    console.log('[+] shared prefs dump hooks installed');
});
"""


HOOKS = {
    "ssl-android":    HOOK_SSL_UNPIN_ANDROID,
    "ssl-ios":        HOOK_SSL_UNPIN_IOS,
    "root-bypass":    HOOK_ROOT_BYPASS,
    "crypto-dump":    HOOK_CRYPTO_DUMP,
    "network-dump":   HOOK_NETWORK_DUMP,
    "prefs-dump":     HOOK_PREFS_DUMP,
}


def _check_frida() -> bool:
    import shutil
    for t in ("frida", "frida-ps"):
        if not shutil.which(t):
            print_warn(t + " not on PATH — pip install frida-tools")
            return False
    print_ok("frida on PATH")
    return True


def cmd_list() -> int:
    print_info(str(len(HOOKS)) + " hook scripts available")
    print()
    for name, _ in HOOKS.items():
        print("  " + ARTERY + "*" + RESET + " " + BONE + name + RESET)
    print()
    print_info("run: redsky mobile frida gen <hook-name>")
    print_info("     redsky mobile frida attach <process> --hook <hook-name>")
    print_info("     redsky mobile frida devices")
    print_info("     redsky mobile frida ps [--host 192.168.x.x]")
    return 0


def cmd_gen(hook: str, out_path: str = "") -> int:
    if hook not in HOOKS:
        print_err("unknown hook: " + hook)
        print_info("available: " + ", ".join(HOOKS.keys()))
        return 2
    HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(out_path) if out_path else HOOKS_DIR / (hook + ".js")
    out.write_text(HOOKS[hook], encoding="utf-8")
    print_ok("wrote " + str(out))
    return 0


def cmd_attach(process: str, hook: str, host: str, spawn: bool) -> int:
    if not _check_frida():
        return 2
    if hook not in HOOKS:
        print_err("unknown hook: " + hook)
        return 2

    HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    script_path = HOOKS_DIR / (hook + ".js")
    if not script_path.exists():
        script_path.write_text(HOOKS[hook], encoding="utf-8")

    cmd = ["frida"]
    if host:
        cmd += ["-H", host]
    if spawn:
        cmd += ["-f", process]
    else:
        cmd += ["-n", process]
    cmd += ["-l", str(script_path), "--runtime=v8"]

    print_info("running: " + " ".join(cmd))
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print_info("detached")
    return 0


def cmd_devices() -> int:
    if not _check_frida():
        return 2
    subprocess.run(["frida-ls-devices"])
    return 0


def cmd_ps(host: str) -> int:
    if not _check_frida():
        return 2
    cmd = ["frida-ps"]
    if host:
        cmd += ["-H", host]
    subprocess.run(cmd)
    return 0


def run_cli(args):
    import argparse
    p = argparse.ArgumentParser(prog="redsky mobile frida", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "gen", "attach", "devices", "ps"])
    p.add_argument("target", nargs="?", default="")
    p.add_argument("--hook", default="")
    p.add_argument("--host", default="")
    p.add_argument("--out", default="")
    p.add_argument("--spawn", action="store_true", help="spawn the app instead of attaching")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky mobile frida <list|gen|attach|devices|ps>")
        return 2

    if ns.help:
        print_info("redsky mobile frida list")
        print_info("redsky mobile frida gen ssl-android")
        print_info("redsky mobile frida attach com.target.app --hook ssl-android [--spawn] [--host 192.168.1.20]")
        print_info("redsky mobile frida devices")
        print_info("redsky mobile frida ps --host 192.168.1.20")
        return 0

    if ns.action == "list":
        return cmd_list()
    if ns.action == "gen":
        hook = ns.hook or ns.target
        if not hook:
            print_err("give a hook name: redsky mobile frida gen ssl-android")
            return 2
        return cmd_gen(hook, ns.out)
    if ns.action == "attach":
        if not ns.target or not ns.hook:
            print_err("need <process> and --hook <name>")
            return 2
        return cmd_attach(ns.target, ns.hook, ns.host, ns.spawn)
    if ns.action == "devices":
        return cmd_devices()
    if ns.action == "ps":
        return cmd_ps(ns.host)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
