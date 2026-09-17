# language: Python, file: Program/utils/paths.py, target: Red Sky paths
# Canonical locations for every file the arsenal touches.

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DATA_DIR    = REPO_ROOT / "Data"
OUTPUT_DIR  = REPO_ROOT / "Output"
PLUGINS_DIR = REPO_ROOT / "Plugins"
PROGRAM_DIR = REPO_ROOT / "Program"
DOCS_DIR    = REPO_ROOT / "docs"
LAB_DIR     = REPO_ROOT / "lab"

CONFIG_FILE     = DATA_DIR / "config.json"
USERAGENTS_FILE = DATA_DIR / "useragents.json"
CREDS_FILE      = DATA_DIR / "default_creds.json"
SECRETS_FILE    = DATA_DIR / "secrets.json"

LOOT_DIR = OUTPUT_DIR / "loot"
REPORT_DIR = OUTPUT_DIR / "reports"
SCREENSHOT_DIR = OUTPUT_DIR / "screenshots"
KEYLOG_DIR = OUTPUT_DIR / "keylogs"
DUMP_DIR = OUTPUT_DIR / "dumps"


def ensure_dirs():
    """Create every folder Red Sky writes to. Idempotent."""
    for p in (
        DATA_DIR, OUTPUT_DIR, PLUGINS_DIR, PROGRAM_DIR, DOCS_DIR, LAB_DIR,
        LOOT_DIR, REPORT_DIR, SCREENSHOT_DIR, KEYLOG_DIR, DUMP_DIR,
    ):
        p.mkdir(parents=True, exist_ok=True)
