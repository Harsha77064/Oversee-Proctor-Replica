"""Checks that a running Oversee server is working, area by area. Read-only: it never
creates or changes data, so it is safe to run against your real server.

  python -m server.check                                  (server at http://localhost:3001)
  python -m server.check http://localhost:3000 --email you@example.com
  python -m server.check https://exams.example.com --email you@example.com --password '...'

Without --password you are asked for it (or set OVERSEE_PASSWORD). Without --email
only the public checks run. Each sign-in counts towards the login limit (10 per 15 min).
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys

import httpx

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
results = {"pass": 0, "fail": 0}


def report(ok: bool | None, area: str, what: str, detail: str = "") -> None:
    if ok is None:
        tag = f"{YELLOW}SKIP{RESET}"
    elif ok:
        tag, results["pass"] = f"{GREEN}PASS{RESET}", results["pass"] + 1
    else:
        tag, results["fail"] = f"{RED}FAIL{RESET}", results["fail"] + 1
    print(f"  {tag}  {area:<14} {what}" + (f"  {DIM}{detail}{RESET}" if detail else ""))


def check(area: str, what: str, fn) -> object:
    try:
        ok, detail, value = fn()
    except httpx.HTTPError as err:
        report(False, area, what, f"request failed: {err}")
        return None
    except Exception as err:  # unexpected response shape
        report(False, area, what, f"{type(err).__name__}: {err}")
        return None
    report(ok, area, what, detail)
    return value


def err_text(r: httpx.Response) -> str:
    try:
        return f"HTTP {r.status_code}: {r.json().get('error', '')}"
    except ValueError:
        return f"HTTP {r.status_code}"


async def check_websocket(base: str, cookie: str | None) -> tuple[bool, str]:
    from websockets.asyncio.client import connect
    from websockets.exceptions import InvalidStatus

    url = base.replace("https://", "wss://").replace("http://", "ws://") + "/signal"
    headers = {"Origin": base}
    if cookie is None:
        try:
            async with connect(url, additional_headers=headers, open_timeout=5):
                return False, "connected without signing in"
        except InvalidStatus as err:
            return True, f"rejected (HTTP {err.response.status_code})"
    headers["Cookie"] = cookie
    async with connect(url, additional_headers=headers, open_timeout=5) as ws:
        msg = json.loads(await asyncio.wait_for(ws.recv(), 5))
        peers = json.loads(await asyncio.wait_for(ws.recv(), 5))
        live = len(peers.get("peers", []))
        return msg.get("type") == "welcome", f"connected as {msg.get('role')}, {live} candidate(s) live now"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check that a running Oversee server works.")
    parser.add_argument("url", nargs="?", default="http://localhost:3001", help="server address (default %(default)s)")
    parser.add_argument("--email", default=os.environ.get("OVERSEE_EMAIL"), help="staff account to sign in with")
    parser.add_argument("--password", default=os.environ.get("OVERSEE_PASSWORD"), help="its password (asked if omitted)")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    if os.name == "nt":
        os.system("")  # enable colours in Windows terminals

    print(f"\nChecking {base}\n")
    c = httpx.Client(base_url=base, timeout=15, follow_redirects=False)

    # ---- public endpoints
    def health():
        r = c.get("/api/health")
        return r.status_code == 200 and r.json().get("ok") is True, f"server time {r.json().get('time')}", r

    if check("server", "GET /api/health", health) is None:
        print(f"\n{RED}Cannot reach the server at {base}. Is it running?{RESET}  (npm run dev  or  python -m server)\n")
        return 1

    def setup_status():
        r = c.get("/api/setup/status")
        d = r.json()
        note = "first-time setup NOT done yet: open the site to create the admin" if d["needsSetup"] else "setup done"
        return r.status_code == 200, f"{note}; email invitations {'on' if d['emailEnabled'] else 'off'}", d

    check("setup", "GET /api/setup/status", setup_status)

    def headers():
        r = c.get("/api/health")
        h = r.headers
        ok = "frame-ancestors 'none'" in h.get("content-security-policy", "") and h.get("x-content-type-options") == "nosniff" and h.get("cache-control") == "no-store"
        return ok, "CSP, nosniff, no-store", None

    check("security", "security headers on API responses", headers)
    check("security", "staff data needs sign-in (401)", lambda: (c.get("/api/data").status_code == 401, "", None))
    check("security", "unknown API path is a JSON 404", lambda: (c.get("/api/does-not-exist").json() == {"error": "Not found."}, "", None))
    check("candidate", "POST /api/candidate/lookup rejects a bad link (404)",
          lambda: (c.post("/api/candidate/lookup", json={"token": "x" * 30}).status_code == 404, "", None))

    def frontend():
        r = c.get("/")
        if "text/html" in r.headers.get("content-type", ""):
            return True, "web app is served", None
        return None, "not built here (fine in dev: the app is on the Vite port, e.g. :5173)", None

    try:
        ok, detail, _ = frontend()
        report(ok, "website", "GET / serves the React app", detail)
    except httpx.HTTPError as err:
        report(False, "website", "GET / serves the React app", str(err))

    ws_ok, ws_detail = asyncio.run(check_websocket(base, None))
    report(ws_ok, "live video", "/signal WebSocket refuses anonymous users", ws_detail)

    if not args.email:
        print(f"\n  {YELLOW}Signed-in checks skipped.{RESET} Add --email you@example.com to run them.")
        return summary()

    password = args.password or getpass.getpass(f"\n  Password for {args.email}: ")
    print()

    # ---- signed-in endpoints
    r = c.post("/api/auth/login", json={"email": args.email, "password": password})
    report(r.status_code == 200, "auth", "POST /api/auth/login", "" if r.status_code == 200 else err_text(r))
    if r.status_code != 200:
        return summary()
    role = r.json()["user"]["role"]

    check("auth", "GET /api/auth/me", lambda: ((x := c.get("/api/auth/me")).status_code == 200, f"signed in as {x.json()['user']['name']} ({role})", None))

    def data():
        r = c.get("/api/data")
        d = r.json()
        counts = ", ".join(f"{len(d[k])} {k}" for k in ("candidates", "questionBanks", "exams", "results", "feedback", "auditLogs"))
        return r.status_code == 200, counts, d

    d = check("data", "GET /api/data", data) or {}

    if role == "admin":
        check("users", "GET /api/users", lambda: ((x := c.get("/api/users")).status_code == 200, f"{len(x.json()['users'])} staff account(s)", None))
        exams = d.get("exams") or []
        if exams:
            ex = exams[0]
            check("invites", f"GET /api/exams/{ex['id']}/invites",
                  lambda: ((x := c.get(f"/api/exams/{ex['id']}/invites")).status_code == 200, f"{len(x.json()['invites'])} candidate(s) on \"{ex['title']}\"", None))
        else:
            report(None, "invites", "GET /api/exams/<id>/invites", "no exams yet")
    else:
        check("users", "GET /api/users is admin-only for proctors (403)", lambda: (c.get("/api/users").status_code == 403, "", None))

    check("recordings", "GET /api/recordings", lambda: ((x := c.get("/api/recordings")).status_code == 200, f"{len(x.json()['recordings'])} recording(s)", None))

    def ice():
        r = c.get("/api/ice")
        servers = r.json()["iceServers"]
        turn = any("username" in s for s in servers)
        return r.status_code == 200, f"STUN {'+ TURN' if turn else 'only (no TURN relay configured)'}", None

    check("live video", "GET /api/ice", ice)

    cookie = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
    try:
        ws_ok, ws_detail = asyncio.run(check_websocket(base, cookie))
    except Exception as err:
        ws_ok, ws_detail = False, f"{type(err).__name__}: {err}"
    report(ws_ok, "live video", "/signal WebSocket accepts signed-in staff", ws_detail)

    check("auth", "POST /api/auth/logout", lambda: (c.post("/api/auth/logout").status_code == 200 and c.get("/api/auth/me").status_code == 401, "signed out again", None))
    return summary()


def summary() -> int:
    total_fail = results["fail"]
    colour = RED if total_fail else GREEN
    print(f"\n{colour}{results['pass']} passed, {total_fail} failed{RESET}\n")
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
