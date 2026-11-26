"""Live-proctoring WebSocket (/signal): authentication, relaying rules and server-side logging."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from conftest import client


def ws_url(base: str) -> str:
    return base.replace("http://", "ws://") + "/signal"


def open_ws(base: str, cookie: str = "", origin: str | None = None):
    headers = {"Origin": origin or base}
    if cookie:
        headers["Cookie"] = cookie
    return connect(ws_url(base), additional_headers=headers, open_timeout=5)


async def recv_until(ws, pred, timeout: float = 5.0) -> dict:
    """Next message matching pred (skips the rest, e.g. data-changed notices)."""
    async def loop():
        while True:
            msg = json.loads(await ws.recv())
            if pred(msg):
                return msg
    return await asyncio.wait_for(loop(), timeout)


def signed_in_candidate(base: str, admin, name: str):
    """Creates a candidate with a live exam and returns (http client, candidate id, invite id)."""
    email = f"{name.lower().replace(' ', '.')}@example.com"
    cid = admin.post("/api/candidates", json={"name": name, "email": email}).json()["id"]
    ex = admin.post("/api/exams", json={"title": f"WS exam for {name}", "bankId": "QB-101",
                                        "startTime": datetime.now(timezone.utc).isoformat(), "duration": 30, "passMark": 50}).json()["id"]
    admin.post(f"/api/candidates/{cid}/assign", json={"examId": ex})
    admin.patch(f"/api/exams/{ex}", json={"status": "Live"})
    inv = admin.post(f"/api/exams/{ex}/invites", json={"candidateIds": [cid]}).json()["invites"][0]
    token = parse_qs(urlsplit(inv["link"]).query)["t"][0]
    c = client(base)
    assert c.post("/api/candidate/login", json={"token": token, "code": inv["code"]}).status_code == 200
    return c, cid, inv["inviteId"]


def test_rejects_unauthenticated_and_cross_origin(base_url, admin):
    async def run():
        with pytest.raises(InvalidStatus):
            async with open_ws(base_url):
                pass
        staff_cookie = f"ov_staff={admin.cookies.get('ov_staff')}"
        with pytest.raises(InvalidStatus):
            async with open_ws(base_url, staff_cookie, origin="https://evil.example"):
                pass
    asyncio.run(run())


def test_live_session_relay_and_logging(base_url, admin):
    cand, cid, _ = signed_in_candidate(base_url, admin, "Wendy Socket")
    staff_cookie = f"ov_staff={admin.cookies.get('ov_staff')}"
    cand_cookie = f"ov_cand={cand.cookies.get('ov_cand')}"

    async def run():
        async with open_ws(base_url, staff_cookie) as staff:
            welcome = await recv_until(staff, lambda m: m["type"] == "welcome")
            assert welcome["role"] == "staff"
            await recv_until(staff, lambda m: m["type"] == "peers")

            async with open_ws(base_url, cand_cookie) as cws:
                me = await recv_until(cws, lambda m: m["type"] == "welcome")
                assert me["role"] == "candidate"
                joined = await recv_until(staff, lambda m: m["type"] == "peer-joined")
                # Identity comes from the database, not from anything the browser sent.
                assert joined["info"]["name"] == "Wendy Socket" and joined["info"]["candidateId"] == cid
                assert joined["info"]["phase"] == "system-check"
                peer = joined["id"]

                # Integrity event -> relayed to staff and written to the audit log; unknown types become Normal.
                await cws.send(json.dumps({"type": "to-admins", "payload": {"kind": "event", "type": "Warning", "event": "Switched tabs"}}))
                ev = await recv_until(staff, lambda m: m["type"] == "relay" and m["payload"].get("kind") == "event")
                assert ev["from"] == peer and ev["payload"] == {"kind": "event", "type": "Warning", "event": "Switched tabs", "autoFlagged": False}
                await cws.send(json.dumps({"type": "to-admins", "payload": {"kind": "event", "type": "Bogus", "event": "Odd"}}))
                ev = await recv_until(staff, lambda m: m["type"] == "relay" and m["payload"].get("kind") == "event")
                assert ev["payload"]["type"] == "Normal"

                # Candidates may only send WebRTC answers/ICE to staff: an "offer" is dropped.
                await cws.send(json.dumps({"type": "relay", "to": welcome["id"], "payload": {"kind": "offer", "sdp": "x"}}))
                await cws.send(json.dumps({"type": "relay", "to": welcome["id"], "payload": {"kind": "answer", "sdp": "y"}}))
                rel = await recv_until(staff, lambda m: m["type"] == "relay" and m["payload"].get("kind") in ("offer", "answer"))
                assert rel["payload"] == {"kind": "answer", "sdp": "y"}

                # Progress numbers are sanitised.
                await cws.send(json.dumps({"type": "to-admins", "payload": {"kind": "progress", "progress": {"answered": "3", "total": 6, "current": None, "secondsLeft": "x"}}}))
                pr = await recv_until(staff, lambda m: m["type"] == "relay" and m["payload"].get("kind") == "progress")
                assert pr["payload"]["progress"] == {"answered": 3, "total": 6, "current": 0, "secondsLeft": 0}

                # Proctor warning reaches the candidate and counts as a warning.
                await staff.send(json.dumps({"type": "relay", "to": peer, "payload": {"kind": "command", "action": "warn", "text": "Eyes on screen"}}))
                cmd = await recv_until(cws, lambda m: m["type"] == "relay")
                assert cmd["payload"] == {"kind": "command", "action": "warn", "text": "Eyes on screen"}

            left = await recv_until(staff, lambda m: m["type"] == "peer-left")
            assert left["id"] == peer

    asyncio.run(run())
    data = admin.get("/api/data", params={"only": "candidates,auditLogs"}).json()
    me = next(c for c in data["candidates"] if c["id"] == cid)
    assert me["warnings"] == 2, "candidate warning + proctor warning"
    events = [l["event"] for l in data["auditLogs"] if l["candidateId"] == cid]
    for expected in ("Joined live proctoring session", "Switched tabs", "Proctor warning: Eyes on screen", "Left the live session"):
        assert expected in events, expected


def test_revoking_invite_ends_live_session(base_url, admin):
    cand, _, invite_id = signed_in_candidate(base_url, admin, "Rex Revoked")
    cand_cookie = f"ov_cand={cand.cookies.get('ov_cand')}"

    async def run():
        async with open_ws(base_url, cand_cookie) as cws:
            await recv_until(cws, lambda m: m["type"] == "welcome")
            assert admin.post(f"/api/invites/{invite_id}/revoke").status_code == 200
            cmd = await recv_until(cws, lambda m: m["type"] == "relay")
            assert cmd["payload"]["action"] == "terminate"
            with pytest.raises(ConnectionClosed) as closed:
                await asyncio.wait_for(cws.recv(), 5)
            assert closed.value.rcvd.code == 4001
        # The revoked session can no longer connect.
        with pytest.raises(InvalidStatus):
            async with open_ws(base_url, cand_cookie):
                pass

    asyncio.run(run())
