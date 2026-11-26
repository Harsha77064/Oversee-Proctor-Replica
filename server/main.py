"""Oversee server: REST API + WebSocket signaling + the built web app, on one port."""
from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response

from .api import HttpError, api, error_reply
from .auth import purge_expired_sessions
from .config import config
from .mailer import email_enabled
from .services import sweep_expired_attempts
from .signaling import signal_endpoint

CSP = ";".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "media-src 'self' blob:",
    "connect-src 'self' ws: wss:",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-DNS-Prefetch-Control": "off",
    "X-Download-Options": "noopen",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Permitted-Cross-Domain-Policies": "none",
    "X-XSS-Protection": "0",
    "Permissions-Policy": "camera=(self), microphone=(self), fullscreen=(self), geolocation=()",
}
if config.production:
    SECURITY_HEADERS["Strict-Transport-Security"] = "max-age=15552000"


async def _sweeper() -> None:
    """Auto-submits timed-out exams and clears expired sessions every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        try:
            sweep_expired_attempts()
            purge_expired_sessions()
        except Exception as err:
            print("[sweep]", repr(err))


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    host = "localhost" if config.host == "0.0.0.0" else config.host
    print(f"Oversee server listening on http://{host}:{config.port}")
    print(f"  data directory: {config.data_dir}")
    print(f"  email invitations: {'on' if email_enabled() else 'off (set SMTP_* to enable)'}")
    print(f"  TURN relay: {'on' if config.ice.turn else 'off (set TURN_URLS to enable)'}", flush=True)
    task = asyncio.create_task(_sweeper())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if request.url.path.startswith("/api") and "cache-control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(HttpError)
async def http_error(request: Request, err: HttpError):
    return error_reply(request, err)


app.include_router(api, prefix="/api")
app.add_api_websocket_route("/signal", signal_endpoint)

# ---------------------------------------------------------------- the built front end (npm run build)
DIST = config.dist_dir.resolve()
INDEX = DIST / "index.html"


def _static_file(path: str) -> Path | None:
    if any(part.startswith(".") for part in path.split("/") if part):
        return None  # never serve dotfiles
    candidate = (DIST / path).resolve()
    if candidate != DIST and DIST not in candidate.parents:
        return None
    return candidate if candidate.is_file() else None


@app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
async def frontend(path: str):
    if not INDEX.exists():
        if path == "":
            return PlainTextResponse("Oversee API is running. Start the web app with `npm run dev`, or run `npm run build` first.")
        return PlainTextResponse(f"Cannot GET /{path}", status_code=404)
    file = _static_file(path)
    if file:
        assets = (DIST / "assets") in file.parents
        cache = "public, max-age=31536000, immutable" if assets else "public, max-age=0"
        return FileResponse(file, headers={"Cache-Control": cache})
    return FileResponse(INDEX, headers={"Cache-Control": "no-cache"})


@app.api_route("/{path:path}", methods=["POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def other_methods(request: Request, path: str):
    return Response(f"Cannot {request.method} /{path}", status_code=404, media_type="text/plain")
