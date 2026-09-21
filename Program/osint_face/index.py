# language: Python, file: Program/osint_face/index.py, target: Red Sky osint_face — face index
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import DATA_DIR, OUTPUT_DIR
from .embedder import embed_image, _load_app


DB_FILE = DATA_DIR / "face_index.sqlite"
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff"}


def _open():
    db = sqlite3.connect(str(DB_FILE))
    db.execute("""
        CREATE TABLE IF NOT EXISTS faces (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            path        TEXT NOT NULL,
            bbox        TEXT,
            det_score   REAL,
            embedding   BLOB NOT NULL,
            added       INTEGER NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS idx_path ON faces(path)")
    db.commit()
    return db


def _pack(vec):
    import struct
    return struct.pack(f"<{len(vec)}f", *vec)


def _unpack(blob):
    import struct
    n = len(blob) // 4
    return list(struct.unpack(f"<{n}f", blob))


def _cosine(a, b):
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def cmd_build(directory, recursive=True):
    root = Path(directory).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print_err(f"directory not found: {root}")
        return 1
    if _load_app() is None:
        return 1
    files = []
    pattern = "**/*" if recursive else "*"
    for p in root.glob(pattern):
        if p.is_file() and p.suffix.lower() in IMAGE_EXT:
            files.append(p)
    if not files:
        print_warn(f"no image files found under {root}")
        return 1
    print_info(f"building face index from {len(files)} image(s)")
    print_kv("root", root)
    print_kv("db", DB_FILE)
    print()
    db = _open()
    added_faces = 0
    added_imgs = 0
    errors = 0
    t0 = time.time()
    for i, f in enumerate(files, 1):
        if i % 20 == 0:
            dt = time.time() - t0
            rate = i / dt if dt > 0 else 0
            print(f"  {ARTERY}▓{RESET} {i}/{len(files)} — {added_faces} faces, {rate:.1f} img/s")
        faces = embed_image(str(f))
        if not faces:
            errors += 1
            continue
        now = int(time.time())
        for face in faces:
            db.execute(
                "INSERT INTO faces (path, bbox, det_score, embedding, added) VALUES (?,?,?,?,?)",
                (str(f), json.dumps(face["bbox"]), face["det_score"],
                 _pack(face["embedding"]), now)
            )
            added_faces += 1
        added_imgs += 1
        db.commit()
    db.close()
    dt = time.time() - t0
    print()
    print_ok(f"index complete in {dt:.1f}s")
    print_kv("images processed", f"{added_imgs}/{len(files)}")
    print_kv("faces indexed", added_faces)
    if errors:
        print_kv("images with no faces", errors)
    return 0


def cmd_query(image_path, top_k=10, threshold=0.4):
    p = Path(image_path).expanduser().resolve()
    if not p.exists():
        print_err(f"image not found: {p}")
        return 1
    print_info(f"querying index with {p.name}")
    faces = embed_image(str(p))
    if not faces:
        print_warn("no faces in query image")
        return 1
    if not DB_FILE.exists():
        print_err("no face index — build one first")
        return 1
    db = _open()
    rows = db.execute("SELECT id, path, bbox, det_score, embedding FROM faces").fetchall()
    db.close()
    if not rows:
        print_warn("index is empty")
        return 1
    print_kv("db rows", len(rows))
    print_kv("query faces", len(faces))
    print()
    for qi, qface in enumerate(faces):
        q_emb = qface["embedding"]
        scored = []
        for rid, path, bbox, score, blob in rows:
            emb = _unpack(blob)
            sim = _cosine(q_emb, emb)
            scored.append((sim, path, bbox, score))
        scored.sort(reverse=True, key=lambda x: x[0])
        top = [s for s in scored[:top_k] if s[0] >= threshold]
        print(f"{ARTERY}{BOLD}── query face {qi} (det={qface['det_score']:.3f}){RESET}")
        if not top:
            print(f"  {ASH}no matches above {threshold}{RESET}")
            print()
            continue
        for sim, path, bbox, score in top:
            marker = f"{SCARLET}▓{RESET}" if sim >= 0.6 else (f"{ARTERY}▓{RESET}" if sim >= 0.5 else f"{ASH}▓{RESET}")
            print(f"  {marker} sim={sim:.3f}  {BONE}{path}{RESET}")
        print()
    return 0


def cmd_stats():
    if not DB_FILE.exists():
        print_warn("no face index yet")
        return 0
    db = _open()
    total = db.execute("SELECT COUNT(*) FROM faces").fetchone()[0]
    unique = db.execute("SELECT COUNT(DISTINCT path) FROM faces").fetchone()[0]
    db.close()
    print_kv("db", DB_FILE)
    print_kv("faces", total)
    print_kv("images", unique)
    return 0


def cmd_clear(confirm=False):
    if not confirm:
        print_err("this deletes the whole face index — pass --yes to confirm")
        return 1
    if DB_FILE.exists():
        DB_FILE.unlink()
        print_ok(f"removed {DB_FILE}")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky osint_face <build|query|stats|clear> [args]")
        return 2
    sub = args[0].lower()
    if sub == "build":
        if len(args) < 2:
            print_err("build needs a directory")
            return 2
        return cmd_build(args[1], recursive="--no-recurse" not in args)
    if sub in ("query", "find"):
        if len(args) < 2:
            print_err("query needs an image path")
            return 2
        top = 10
        thresh = 0.4
        if "--top" in args:
            i = args.index("--top")
            if i + 1 < len(args):
                top = int(args[i + 1])
        if "--threshold" in args:
            i = args.index("--threshold")
            if i + 1 < len(args):
                thresh = float(args[i + 1])
        return cmd_query(args[1], top, thresh)
    if sub == "stats":
        return cmd_stats()
    if sub == "clear":
        return cmd_clear(confirm="--yes" in args)
    print_err(f"unknown osint_face sub-command: {sub}")
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
