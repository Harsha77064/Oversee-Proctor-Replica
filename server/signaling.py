"""Oversee signaling server (WebSocket at /signal).

Browsers exchange WebRTC connection details (offers, answers, ICE candidates)
and proctoring messages through this authenticated WebSocket relay. Camera
video flows directly between browsers (or through TURN); never through here.

Identity comes only from session cookies: staff (admin/proctor) or a
candidate's invite session. Candidate details are read from the database,
never trusted from the browser.

  client -> server  { type: 'relay', to, payload }       staff <-> candidate only
  client -> server  { type: 'to-admins', payload }       candidate -> every staff member
  server -> client  { type: 'welcome', id } / { type: 'peers', peers } / { type: 'peer-joined' | 'peer-left', ... }
  server -> staff   { type: 'data-changed', collections } after API writes
"""
from __future__ import annotations

import asyncio
import itertools
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

from . import db
from .auth import candidate_from_cookies, parse_cookie_header, staff_from_cookies
from .jsutil import dumps, js_number, js_string, truthy
from .services import finish_attempt, get_attempt_by_invite, record_proctor_event, touch_candidate

MAX_MESSAGE_BYTES = 128 * 1024  # enforced by uvicorn's ws_max_size (see __main__.py)
FLOOD_BUDGET = 300  # messages per 10 seconds
_CLOSE = object()


@dataclass
class Client:
    ws: WebSocket
    role: str  # 'staff' | 'candidate'
    info: dict
    user: dict | None = None
    ctx: dict | None = None
    ip: str = ""
    outbox: asyncio.Queue = field(default_factory=asyncio.Queue)


clients: dict[str, Client] = {}
_seq = itertools.count(1)


def _send(client: Client, msg: dict) -> None:
    """Queues a message; each client's writer task sends them in order."""
    client.outbox.put_nowait(dumps(msg))


def _staff() -> list[tuple[str, Client]]:
    return [(i, c) for i, c in list(clients.items()) if c.role == "staff"]


def _candidates() -> list[tuple[str, Client]]:
    return [(i, c) for i, c in list(clients.items()) if c.role == "candidate"]


def is_candidate_online(candidate_id: str) -> bool:
    return any(c.ctx["candidate_id"] == candidate_id for _, c in _candidates())


def notify_staff(collections: list[str]) -> None:
    for _, c in _staff():
        _send(c, {"type": "data-changed", "collections": list(collections)})


def _close_later(client: Client, code: int, reason: str, delay: float) -> None:
    loop = asyncio.get_running_loop()
    loop.call_later(delay, lambda: client.outbox.put_nowait((_CLOSE, code, reason)))


def disconnect_invite(invite_id: str, reason: str = "Your exam session has ended.") -> None:
    for _, c in _candidates():
        if c.ctx["invite_id"] == invite_id:
            _send(c, {"type": "relay", "from": "server", "payload": {"kind": "command", "action": "terminate", "text": reason}})
            _close_later(c, 4001, "ended", 0.2)


def disconnect_user(user_id: str) -> None:
    """Session revocation: kick staff whose account was deactivated."""
    for _, c in _staff():
        if c.user["id"] == user_id:
            c.outbox.put_nowait((_CLOSE, 4003, "signed out"))


def _candidate_info(ctx: dict) -> dict:
    attempt = get_attempt_by_invite(ctx["invite_id"])
    if not attempt:
        phase = "system-check"
    elif attempt["status"] == "InProgress":
        phase = "in-exam"
    elif attempt["status"] == "Submitted":
        phase = "submitted"
    else:
        phase = "terminated"
    return {
        "candidateId": ctx["candidate_id"],
        "name": ctx["name"],
        "department": ctx["department"],
        "examId": ctx["exam_id"],
        "examTitle": ctx["exam_title"],
        "phase": phase,
    }


def _same_origin(ws: WebSocket) -> bool:
    origin = ws.headers.get("origin")
    if not origin:
        return True  # non-browser clients cannot carry the user's cookies
    try:
        return urlsplit(origin).netloc == ws.headers.get("host")
    except ValueError:
        return False


async def _writer(client: Client) -> None:
    while True:
        item = await client.outbox.get()
        try:
            if isinstance(item, tuple) and item[0] is _CLOSE:
                if client.ws.application_state == WebSocketState.CONNECTED:
                    await client.ws.close(code=item[1], reason=item[2])
                return
            if client.ws.application_state != WebSocketState.CONNECTED:
                return
            await client.ws.send_text(item)
        except Exception:  # connection already gone
            return


async def signal_endpoint(ws: WebSocket) -> None:
    cookies = parse_cookie_header(ws.headers.get("cookie", ""))
    user = staff_from_cookies(cookies)
    ctx = None if user else candidate_from_cookies(cookies)
    if not _same_origin(ws) or (not user and not ctx):
        await ws.close(code=4401)  # rejected before the handshake completes (HTTP 403)
        return
    await ws.accept()

    client_id = f"p{next(_seq)}"
    forwarded = ws.headers.get("x-forwarded-for", "")
    ip = (forwarded or (ws.client.host if ws.client else "")).split(",")[0].strip()

    if user:
        client = Client(ws=ws, role="staff", user=user, info={"name": user["name"], "role": user["role"]})
    else:
        client = Client(ws=ws, role="candidate", ctx=ctx, info=_candidate_info(ctx), ip=ip)
    clients[client_id] = client
    writer = asyncio.create_task(_writer(client))

    if user:
        _send(client, {"type": "welcome", "id": client_id, "role": "staff"})
        _send(client, {"type": "peers", "peers": [{"id": pid, "info": c.info} for pid, c in _candidates()]})
    else:
        touch_candidate(ctx["candidate_id"])
        db.audit(candidate_id=ctx["candidate_id"], type="Normal", event="Joined live proctoring session", exam_id=ctx["exam_id"], ip=ip)
        _send(client, {"type": "welcome", "id": client_id, "role": "candidate"})
        for _, s in _staff():
            _send(s, {"type": "peer-joined", "id": client_id, "info": client.info})
        notify_staff(["candidates", "auditLogs"])

    budget, window = FLOOD_BUDGET, time.monotonic()
    try:
        while True:
            message = await ws.receive()
            if message["type"] == "websocket.disconnect":
                break
            raw = message.get("text")
            if raw is None and message.get("bytes") is not None:
                raw = message["bytes"].decode("utf-8", "replace")
            if time.monotonic() - window >= 10:
                budget, window = FLOOD_BUDGET, time.monotonic()
            budget -= 1
            if budget < 0:
                continue
            try:
                msg = json.loads(raw or "")
            except ValueError:
                continue
            me = clients.get(client_id)
            if not me or not isinstance(msg, dict):
                continue
            try:
                if me.role == "candidate":
                    _handle_candidate(client_id, me, msg)
                else:
                    _handle_staff(client_id, me, msg)
            except Exception as err:  # never let one bad message drop the connection
                print(f"[signaling] {err!r}")
    except WebSocketDisconnect:
        pass
    finally:
        me = clients.pop(client_id, None)
        writer.cancel()
        if me:
            _on_close(client_id, me)


def _on_close(client_id: str, me: Client) -> None:
    if me.role == "candidate":
        for _, s in _staff():
            _send(s, {"type": "peer-left", "id": client_id})
        attempt = get_attempt_by_invite(me.ctx["invite_id"])
        in_exam = attempt and attempt["status"] == "InProgress"
        db.audit(
            candidate_id=me.ctx["candidate_id"],
            type="Normal",
            event="Disconnected from the live session during the exam" if in_exam else "Left the live session",
            exam_id=me.ctx["exam_id"],
            ip=me.ip,
        )
        touch_candidate(me.ctx["candidate_id"])
        notify_staff(["candidates", "auditLogs"])
    else:
        for _, c in _candidates():
            _send(c, {"type": "admin-left", "id": client_id})


def _num_or_zero(v: Any) -> int | float:
    """`+v || 0` from JavaScript, returned as an int when whole."""
    n = js_number(v)
    if math.isnan(n) or n == 0:
        return 0
    if math.isinf(n):
        return 0  # JSON has no Infinity; JSON.stringify would send null
    return int(n) if n.is_integer() else n


def _handle_candidate(client_id: str, me: Client, msg: dict) -> None:
    payload = msg.get("payload")
    p = payload if isinstance(payload, dict) else {}
    if msg.get("type") == "relay" and isinstance(msg.get("to"), str):
        target = clients.get(msg["to"])
        # Candidates may only answer staff (WebRTC answers and ICE candidates).
        if target and target.role == "staff" and p.get("kind") in ("answer", "ice"):
            _send(target, {"type": "relay", "from": client_id, "payload": payload})
        return
    if msg.get("type") != "to-admins":
        return
    kind = p.get("kind")
    if kind == "event":
        type_ = p.get("type") if p.get("type") in ("Normal", "Warning", "Validation") else "Normal"
        event = (js_string(p.get("event")) if truthy(p.get("event")) else "")[:160]
        if not event:
            return
        result = record_proctor_event(candidate_id=me.ctx["candidate_id"], exam_id=me.ctx["exam_id"], type=type_, event=event, ip=me.ip)
        for _, s in _staff():
            _send(s, {"type": "relay", "from": client_id,
                      "payload": {"kind": "event", "type": type_, "event": event, "autoFlagged": result["autoFlagged"]}})
        notify_staff(["candidates", "auditLogs"])
    elif kind == "progress" and isinstance(p.get("progress"), (dict, list)) and truthy(p.get("progress")):
        pr = p["progress"] if isinstance(p["progress"], dict) else {}
        progress = {k: _num_or_zero(pr.get(k)) for k in ("answered", "total", "current", "secondsLeft")}
        for _, s in _staff():
            _send(s, {"type": "relay", "from": client_id, "payload": {"kind": "progress", "progress": progress}})
    elif kind == "phase":
        # Phase is re-derived from the database so a candidate cannot fake "submitted".
        me.info = _candidate_info(me.ctx)
        for _, s in _staff():
            _send(s, {"type": "relay", "from": client_id, "payload": {"kind": "phase", "phase": me.info["phase"]}})
        if me.info["phase"] != "system-check":
            notify_staff(["results", "auditLogs", "candidates"])


def _handle_staff(client_id: str, me: Client, msg: dict) -> None:
    if msg.get("type") != "relay" or not isinstance(msg.get("to"), str):
        return
    target = clients.get(msg["to"])
    if not target or target.role != "candidate":
        return
    payload = msg.get("payload")
    p = payload if isinstance(payload, dict) else {}
    actor = me.user["name"]
    candidate_id, exam_id, invite_id = target.ctx["candidate_id"], target.ctx["exam_id"], target.ctx["invite_id"]

    if p.get("kind") in ("offer", "ice"):
        _send(target, {"type": "relay", "from": client_id, "payload": p})
        return
    if p.get("kind") != "command":
        return
    text = (js_string(p.get("text")) if truthy(p.get("text")) else "")[:300]
    action = p.get("action")
    if action == "message":
        db.audit(candidate_id=candidate_id, type="Normal", event=f"Proctor message: {text}", exam_id=exam_id, actor=actor)
    elif action == "warn":
        record_proctor_event(candidate_id=candidate_id, exam_id=exam_id, type="Warning", event=f"Proctor warning: {text}", actor=actor)
    elif action == "terminate":
        attempt = get_attempt_by_invite(invite_id)
        if not attempt or attempt["status"] != "InProgress":
            return
        finish_attempt(attempt["id"], status="Terminated", reason=text, actor=actor)
        target.info = _candidate_info(target.ctx)
    else:
        return
    _send(target, {"type": "relay", "from": client_id, "payload": {"kind": "command", "action": action, "text": text}})
    notify_staff(["candidates", "auditLogs", "results"])
