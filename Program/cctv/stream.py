# language: Python, file: Program/cctv/stream.py, target: Red Sky cctv — stream
# Pull RTSP via ffmpeg. Local preview, or save to Output/cctv/.

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import load_config, print_ok, print_err, print_info, print_warn, print_kv, print_bullet
from Program.utils.paths import OUTPUT_DIR


def _ffmpeg_ok() -> bool:
    return shutil.which("ffmpeg") is not None


def _ffplay_ok() -> bool:
    return shutil.which("ffplay") is not None


def _probe(url: str) -> dict:
    """ffprobe the stream to see if it's alive."""
    if not shutil.which("ffprobe"):
        return {}
    try:
        r = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json",
             "-show_streams", "-show_format", "-rtsp_transport", "tcp", url],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            return json.loads(r.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return {}


def cmd_probe(url: str) -> int:
    print_info(f"probing {url}")
    info = _probe(url)
    if not info:
        print_err("no response (ffprobe failed)")
        return 1

    fmt = info.get("format", {})
    print_kv("format", fmt.get("format_long_name", "?"))
    print_kv("duration", fmt.get("duration", "live"))
    for i, s in enumerate(info.get("streams", [])):
        codec = s.get("codec_name", "?")
        w = s.get("width", "?")
        h = s.get("height", "?")
        fps = s.get("r_frame_rate", "?")
        print(f"  {ARTERY}▓{RESET} stream {i}: {BONE}{codec}{RESET} {w}x{h} @ {fps}")
    return 0


def cmd_view(url: str, seconds: int = 0) -> int:
    if not _ffplay_ok():
        print_err("ffplay not found — install ffmpeg: sudo apt install ffmpeg")
        return 1

    print_info(f"opening stream window (CTRL+C to stop)")
    cmd = ["ffplay", "-rtsp_transport", "tcp", "-window_title", "Red Sky // CCTV", "-autoexit"]
    if seconds > 0:
        cmd += ["-t", str(seconds)]
    cmd += [url]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    return 0


def cmd_capture(url: str, seconds: int = 30, output: str = "") -> int:
    if not _ffmpeg_ok():
        print_err("ffmpeg not found — install: sudo apt install ffmpeg")
        return 1

    out = Path(output) if output else OUTPUT_DIR / "cctv" / f"capture_{int(time.time())}.mp4"
    out.parent.mkdir(parents=True, exist_ok=True)

    print_info(f"recording {seconds}s -> {out}")
    cmd = [
        "ffmpeg", "-y", "-rtsp_transport", "tcp",
        "-i", url, "-t", str(seconds), "-c", "copy", str(out),
    ]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print_err(f"ffmpeg failed: {e}")
        return 1
    print_ok(f"saved {out}")
    return 0


def run_cli(args: List[str]) -> int:
    if not args:
        print_err("usage: redsky cctv stream <probe|view|capture> <rtsp_url> [seconds]")
        return 2

    action = args[0].lower()
    if action == "probe":
        if len(args) < 2:
            print_err("probe needs a URL")
            return 2
        return cmd_probe(args[1])
    if action == "view":
        if len(args) < 2:
            print_err("view needs a URL")
            return 2
        return cmd_view(args[1], int(args[2]) if len(args) > 2 else 0)
    if action == "capture":
        if len(args) < 2:
            print_err("capture needs a URL")
            return 2
        secs = int(args[2]) if len(args) > 2 else 30
        out = args[3] if len(args) > 3 else ""
        return cmd_capture(args[1], secs, out)

    # bare URL → probe
    return cmd_probe(action)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
