# language: Python, file: Program/osint_face/embedder.py, target: Red Sky osint_face — face embedder
# Loads InsightFace buffalo_l model (ArcFace backbone) and extracts 512-dim
# face vectors. Auto-downloads the model on first use.

import sys
from pathlib import Path
from typing import Dict, List

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import DATA_DIR


MODEL_ROOT = DATA_DIR / "insightface"
_app = None


def _load_app():
    """Lazy-load the InsightFace FaceAnalysis app. Downloads model on first call."""
    global _app
    if _app is not None:
        return _app
    try:
        from insightface.app import FaceAnalysis
    except ImportError as e:
        print_err(f"insightface missing: {e}")
        print_info("  pip install --break-system-packages insightface onnxruntime")
        return None

    MODEL_ROOT.mkdir(parents=True, exist_ok=True)
    print_info("loading InsightFace buffalo_l (downloads ~300 MB on first run)")
    print_kv("model root", MODEL_ROOT)

    try:
        app = FaceAnalysis(name="buffalo_l", root=str(MODEL_ROOT),
                           providers=["CPUExecutionProvider"])
        app.prepare(ctx_id=-1, det_size=(640, 640))
    except Exception as e:
        print_err(f"model load failed: {e}")
        print_info("check network — insightface downloads model files on first run")
        return None

    _app = app
    print_ok("model ready")
    return app


def embed_image(image_path):
    """Return list of {bbox, embedding, det_score, kps} for every face in the image."""
    app = _load_app()
    if app is None:
        return []

    import cv2
    p = Path(image_path).expanduser()
    if not p.exists():
        print_err(f"image not found: {p}")
        return []

    img = cv2.imread(str(p))
    if img is None:
        print_err(f"cannot decode image: {p}")
        return []

    try:
        faces = app.get(img)
    except Exception as e:
        print_err(f"face detect failed: {e}")
        return []

    out = []
    for f in faces:
        out.append({
            "bbox": [float(x) for x in f.bbox],
            "embedding": [float(x) for x in f.embedding],
            "det_score": float(f.det_score),
            "kps": [[float(x), float(y)] for x, y in f.kps] if f.kps is not None else [],
        })
    return out


def cmd_embed(image_path):
    print_info(f"extracting faces from {image_path}")
    faces = embed_image(image_path)
    if not faces:
        print_warn("no faces detected")
        return 1
    print_ok(f"{len(faces)} face(s)")
    for i, f in enumerate(faces):
        x1, y1, x2, y2 = f["bbox"]
        print(f"  {ARTERY}▓{RESET} face {i}: {int(x2-x1)}x{int(y2-y1)}  "
              f"det={f['det_score']:.3f}  emb_norm={sum(x*x for x in f['embedding']) ** 0.5:.3f}")
    return 0


def run_cli(args):
    if not args:
        print_err("usage: redsky osint_face embed <image>")
        return 2
    return cmd_embed(args[0])


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
