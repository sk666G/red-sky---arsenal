# language: Python, file: setup.py, target: Red Sky installer
# Verifies Python, installs requirements, creates missing folders.
import sys
import subprocess
import platform
from pathlib import Path

MIN_PY = (3, 11)

RED = "\033[38;2;255;36;0m"
BLOOD = "\033[38;2;120;0;0m"
BONE = "\033[38;2;230;220;210m"
ASH = "\033[38;2;120;120;120m"
RESET = "\033[0m"


def banner():
    print(f"""{BLOOD}
    ██▀███  ▓█████ ▓█████▄      ██████  ██ ▄█▀▓██   ██▓
    ▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌   ▒██    ▒  ██▄█▒  ▒██  ██▒
    ▓██ ░▄█ ▒▒███   ░██   █▌   ░ ▓██▄   ▓███▄░   ▒██ ██░
    ▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌     ▒   ██▒▓██ █▄   ░ ▐██▓░
    ░██▓ ▒██▒░▒████▒░▒████▓    ▒██████▒▒▒██▒ █▄  ░ ██▒▓░
    ░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒    ▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒   ██▒▒▒
      ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒    ░ ░▒  ░ ░░ ░▒ ▒░ ▓██ ░▒░
      ░░   ░    ░    ░ ░  ░    ░  ░  ░  ░ ░░ ░  ▒ ▒ ░░
       ░        ░  ░   ░             ░  ░  ░    ░ ░
                     ░                          ░ ░
    {RESET}""")
    print(f"{RED}    setup.py — installer{RESET}\n")


def check_python():
    if sys.version_info < MIN_PY:
        print(f"{RED}[!] Python {MIN_PY[0]}.{MIN_PY[1]}+ required. "
              f"You have {sys.version_info.major}.{sys.version_info.minor}.{RESET}")
        sys.exit(1)
    print(f"{BONE}[+] Python {sys.version_info.major}.{sys.version_info.minor} — OK{RESET}")


def check_pip():
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"],
                       check=True, capture_output=True)
        print(f"{BONE}[+] pip — OK{RESET}")
    except subprocess.CalledProcessError:
        print(f"{RED}[!] pip is missing.{RESET}")
        sys.exit(1)


def install_requirements():
    req = Path(__file__).parent / "requirements.txt"
    if not req.exists():
        print(f"{RED}[!] requirements.txt not found.{RESET}")
        sys.exit(1)
    print(f"{ASH}[*] installing dependencies from requirements.txt ...{RESET}")
    cmd = [sys.executable, "-m", "pip", "install", "-r", str(req)]
    if "--user" in sys.argv:
        cmd.append("--user")
    if platform.system() == "Linux":
        cmd.append("--break-system-packages")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"{RED}[!] pip install failed.{RESET}")
        sys.exit(1)
    print(f"{BONE}[+] dependencies installed.{RESET}")


def make_folders():
    here = Path(__file__).parent
    folders = [
        "Data", "Plugins", "Program", "docs", "lab", "Output",
        "Program/theme", "Program/utils", "Program/recon",
        "Program/ipgrab", "Program/cctv", "Program/web",
        "Program/phish", "Program/creds", "Program/payload",
        "Program/evade", "Program/crack", "Program/botnet",
        "Program/c2", "Program/panel", "Program/geoip",
        "Program/ddos", "Program/csint", "Program/wifi",
        "Program/bluetooth", "Program/rfid", "Program/usb",
        "Program/social", "Program/osint_face", "Program/mail_trace",
        "Program/ad_attack", "Program/cloud_pwn", "Program/container_escape",
        "Program/supply_chain", "Program/firmware", "Program/satcom",
        "Program/ics_scada", "Program/av_bypass", "Program/shellcode",
        "Program/proxy_chain", "Program/anti_forensics", "Program/vm_detect",
        "Program/drone", "Program/keygen_factory", "Program/fuzzer",
        "Program/burp_suite", "Program/wireless_jam", "Program/fiber_tap",
        "Program/lock_bypass", "Program/memory_forensics",
    ]
    for name in folders:
        (here / name).mkdir(parents=True, exist_ok=True)
    print(f"{BONE}[+] folder tree — OK{RESET}")


def main():
    banner()
    check_python()
    check_pip()
    install_requirements()
    make_folders()
    print(f"\n{RED}[*] setup complete. run: python3 redsky.py{RESET}\n")


if __name__ == "__main__":
    main()
