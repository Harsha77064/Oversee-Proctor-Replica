"""HTTP API (/api/...). Staff routes need an admin/proctor session; candidate routes need an
invite session. Every write is validated here, never trusted from the browser."""
from __future__ import annotations

import functools
import hmac
import json
import math
import re
import secrets
import time
import traceback
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, Response
from starlette.datastructures import MutableHeaders
from starlette.requests import ClientDisconnect

from . import db
from .auth import (
    candidate_from_cookies, create_session, destroy_session, hash_password, password_problem,
    revoke_sessions, staff_from_cookies, verify_password,
)
from .config import config
from .ice import ice_servers
from .jsutil import (
    UNDEFINED, date_ms, dumps, get, iso, is_integer, js_length, js_number, js_round,
    js_string, loads, now_ms, parse_date, truthy,
)
from .mailer import (
    MODES as MAIL_MODES, SECURITY as MAIL_SECURITY, MailError, clear_outbox, email_enabled, email_mode,
    env_configured, list_outbox, mail_config, public_mail_config, save_mail_config, send_invite_email,
    send_test_email, valid_from,
)
from .seed import seed_demo
from .services import (
    attempt_questions, finish_attempt, finish_attempts_for_exam, flag_candidate, get_attempt_by_invite,
    list_audit, list_banks, list_candidates, list_exams, list_feedback, list_recordings, list_results,
    end_finished_exams, start_attempt, start_due_exams, touch_candidate,
)
from .signaling import disconnect_invite, disconnect_user, is_candidate_online, notify_staff

JSON_LIMIT = 1024 * 1024  # express.json({ limit: '1mb' })
REC_DIR = config.data_dir / "recordings"


# ---------------------------------------------------------------- errors & responses
class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def bad(msg: str) -> HttpError:
    return HttpError(400, msg)


def not_found(what: str) -> HttpError:
    return HttpError(404, f"{what} not found.")


def _extra(request: Request) -> MutableHeaders:
    """Headers collected while handling the request (cookies, rate-limit info)."""
    if not hasattr(request.state, "reply"):
        request.state.reply = SimpleNamespace(headers=MutableHeaders(raw=[]))
    return request.state.reply.headers


def _res(request: Request) -> SimpleNamespace:
    _extra(request)
    return request.state.reply


def reply(request: Request, data: Any, status: int = 200) -> Response:
    response = Response(content=dumps(data), status_code=status, media_type="application/json")
    for k, v in _extra(request).raw:
        response.raw_headers.append((k, v))
    return response


def error_reply(request: Request, err: Exception) -> Response:
    if isinstance(err, HttpError):
        return reply(request, {"error": err.message}, err.status)
    print("[api]", "".join(traceback.format_exception(err)).rstrip())
    return reply(request, {"error": "Something went wrong on the server. Try again."}, 500)


# ---------------------------------------------------------------- request body
async def parse_body(request: Request) -> None:
    """express.json(): parses application/json bodies (up to 1 MB) into request.state.body.

    Runs for every /api route, before the handler. Other content types (e.g. recording uploads)
    are left unread and the body is {}."""
    request.state.body = {}
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        return
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > JSON_LIMIT:
        raise HttpError(413, "Request is too large.")
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > JSON_LIMIT:
            raise HttpError(413, "Request is too large.")
    request._body = raw  # let request.body() return it later
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return
    if text[0] not in "{[":
        raise bad("Request body is not valid JSON.")
    try:
        request.state.body = json.loads(text)
    except ValueError:
        raise bad("Request body is not valid JSON.") from None


def body_of(request: Request) -> Any:
    return getattr(request.state, "body", {})


# ---------------------------------------------------------------- validation (same rules and messages as before)
def str_(v: Any, label: str, *, max: int = 200, required: bool = True) -> str:
    if isinstance(v, str):
        s = v.strip()
    elif v is None or v is UNDEFINED:
        s = ""
    else:
        s = js_string(v).strip()
    if required and not s:
        raise bad(f"{label} is required.")
    if js_length(s) > max:
        raise bad(f"{label} must be at most {max} characters.")
    return s


def int_(v: Any, label: str, lo: int, hi: int) -> int:
    n = js_number(v)
    if not is_integer(n) or n < lo or n > hi:
        raise bad(f"{label} must be a whole number from {lo} to {hi}.")
    return int(n)


_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def email_(v: Any, label: str = "Email") -> str:
    s = str_(v, label, max=254)
    if not _EMAIL.match(s):
        raise bad(f"{label} is not a valid email address.")
    return s.lower()


def one_of(v: Any, label: str, options: list[str]) -> str:
    if not isinstance(v, str) or v not in options:
        raise bad(f"{label} must be one of: {', '.join(options)}.")
    return v


def iso_date(v: Any, label: str) -> str:
    d = parse_date(v) if truthy(v) else None
    if d is None:
        raise bad(f"{label} is not a valid date and time.")
    return iso(d)


# ---------------------------------------------------------------- request helpers
def ip_of(request: Request) -> str:
    """req.ip: with TRUST_PROXY, the address the (single) reverse proxy saw."""
    peer = request.client.host if request.client else ""
    if config.trust_proxy:
        forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if forwarded:
            return forwarded[-1]
    return peer


def base_url(request: Request) -> str:
    if config.public_url:
        return config.public_url
    proto = request.url.scheme
    if config.trust_proxy and request.headers.get("x-forwarded-proto"):
        proto = request.headers["x-forwarded-proto"].split(",")[0].strip()
    return f"{proto}://{request.headers.get('host', '')}"


class Limiter:
    """express-rate-limit: fixed window per client IP, with RateLimit-* headers."""

    def __init__(self, max_: int, minutes: float):
        self.max = max_
        self.window = minutes * 60
        self.hits: dict[str, tuple[int, float]] = {}

    def check(self, request: Request) -> None:
        now = time.time()
        key = ip_of(request)
        count, reset_at = self.hits.get(key, (0, now + self.window))
        if now >= reset_at:
            count, reset_at = 0, now + self.window
        count += 1
        self.hits[key] = (count, reset_at)
        if len(self.hits) > 10000:  # drop expired entries now and then
            self.hits = {k: v for k, v in self.hits.items() if v[1] > now}
        headers = _extra(request)
        headers["RateLimit-Policy"] = f"{self.max};w={int(self.window)}"
        headers["RateLimit-Limit"] = str(self.max)
        headers["RateLimit-Remaining"] = str(max(0, self.max - count))
        headers["RateLimit-Reset"] = str(max(0, math.ceil(reset_at - now)))
        if count > self.max:
            headers["Retry-After"] = str(max(0, math.ceil(reset_at - now)))
            raise HttpError(429, "Too many attempts. Wait a few minutes and try again.")


def require_staff(request: Request, *roles: str) -> dict:
    user = staff_from_cookies(request.cookies)
    if not user:
        raise HttpError(401, "Please sign in.")
    if roles and user["role"] not in roles:
        raise HttpError(403, "You do not have permission to do that.")
    return user


def any_staff(request: Request) -> dict:
    return require_staff(request, "admin", "proctor")


def admin_only(request: Request) -> dict:
    return require_staff(request, "admin")


def require_candidate(request: Request) -> dict:
    ctx = candidate_from_cookies(request.cookies)
    if not ctx:
        raise HttpError(401, "Your exam session has ended. Open your invitation link again.")
    return ctx


def changed(*collections: str) -> None:
    notify_staff(list(collections))


def update_exam_schedule() -> None:
    """Opens scheduled exams whose start time has come and closes live exams whose time has run
    out (submitting answers in progress). Runs on candidate/staff requests and every 30 s."""
    started = start_due_exams()
    ended = end_finished_exams(config.exam_end_grace_seconds)
    for _exam_id, invite_ids in ended:
        for invite_id in invite_ids:
            disconnect_invite(invite_id, "Time is up. The exam has ended and your answers were submitted.")
    if started or ended:
        changed("exams", "results", "auditLogs", "candidates")


def staff_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=config.staff_session_hours)


def data_payload(only: list[str] | None, user: dict) -> dict:
    def want(k: str) -> bool:
        return only is None or k in only

    out: dict[str, Any] = {}
    if want("candidates"):
        out["candidates"] = list_candidates(is_candidate_online)
    if want("questionBanks"):
        out["questionBanks"] = list_banks(include_answers=user["role"] == "admin")
    if want("exams"):
        out["exams"] = list_exams()
    if want("results"):
        out["results"] = list_results()
    if want("feedback"):
        out["feedback"] = list_feedback()
    if want("auditLogs"):
        out["auditLogs"] = list_audit(1000)
    if want("settings"):
        out["settings"] = db.get_settings()
    return out


# ---------------------------------------------------------------- routes
api = APIRouter(dependencies=[Depends(parse_body)])


def route(path: str, *methods: str):
    """Registers a handler. Errors become JSON replies; GET routes also answer HEAD, like Express."""
    ms = list(methods)
    if "GET" in ms:
        ms.append("HEAD")

    def decorate(fn):
        @functools.wraps(fn)
        async def handler(request: Request, **kwargs):
            try:
                return await fn(request, **kwargs)
            except Exception as err:  # HttpError -> its status; anything else -> 500
                return error_reply(request, err)

        return api.api_route(path, methods=ms, include_in_schema=False)(handler)

    return decorate


def user_count() -> int:
    return db.one("SELECT COUNT(*) AS n FROM users")["n"]


# ---- health / setup
@route("/health", "GET")
async def health(request: Request):
    return reply(request, {"ok": True, "time": db.now()})


@route("/setup/status", "GET")
async def setup_status(request: Request):
    return reply(request, {"needsSetup": user_count() == 0, "emailEnabled": email_enabled()})


_setup_limit = Limiter(10, 60)


@route("/setup", "POST")
async def setup(request: Request):
    _setup_limit.check(request)
    b = body_of(request)
    if user_count() > 0:
        raise HttpError(409, "Setup is already complete. Sign in instead.")
    name = str_(get(b, "name"), "Your name", max=100)
    mail = email_(get(b, "email"))
    problem = password_problem(get(b, "password"))
    if problem:
        raise bad(f"Password: {problem}")
    org_name = str_(get(b, "orgName"), "Organization name", max=120)
    password_hash = await hash_password(b["password"])
    with db.tx():
        if user_count() > 0:
            raise HttpError(409, "Setup is already complete.")
        uid = db.new_id("USR")
        db.run("INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
               uid, name, mail, password_hash, "admin", db.now())
        if truthy(get(b, "loadDemo")):
            seed_demo()
        org = db.get_settings()["organization"]
        db.save_settings("organization", {**org, "name": org_name, "supportEmail": org.get("supportEmail") or mail})
    create_session(_res(request), "staff", uid, staff_expiry())
    return reply(request, {"user": {"id": uid, "name": name, "email": mail, "role": "admin"}})


# ---- staff auth
_login_limit = Limiter(10, 15)
_DUMMY_HASH = "scrypt$AAAAAAAAAAAAAAAAAAAAAA==$" + "A" * 86 + "=="


@route("/auth/login", "POST")
async def login(request: Request):
    _login_limit.check(request)
    b = body_of(request)
    mail = str_(get(b, "email"), "Email", max=254).lower()
    password = get(b, "password") if isinstance(get(b, "password"), str) else ""
    u = db.one("SELECT * FROM users WHERE email = ?", mail)
    # Always run the hash so response time does not reveal which emails exist.
    ok = await verify_password(password, u["password_hash"] if u else _DUMMY_HASH)
    if not u or not ok or not u["active"]:
        raise HttpError(401, "Email or password is incorrect.")
    db.run("UPDATE users SET last_login_at = ? WHERE id = ?", db.now(), u["id"])
    create_session(_res(request), "staff", u["id"], staff_expiry())
    return reply(request, {"user": {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"]}})


@route("/auth/logout", "POST")
async def logout(request: Request):
    destroy_session(request, _res(request), "staff")
    return reply(request, {"ok": True})


@route("/auth/me", "GET")
async def me(request: Request):
    user = staff_from_cookies(request.cookies)
    if not user:
        return reply(request, {"error": "Not signed in."}, 401)
    return reply(request, {"user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]},
                           "emailEnabled": email_enabled(), "emailMode": email_mode()})


@route("/auth/password", "POST")
async def change_password(request: Request):
    user = require_staff(request)
    b = body_of(request)
    u = db.one("SELECT * FROM users WHERE id = ?", user["id"])
    current = get(b, "currentPassword")
    if not await verify_password(js_string(current) if truthy(current) else "", u["password_hash"]):
        raise bad("Current password is incorrect.")
    problem = password_problem(get(b, "newPassword"))
    if problem:
        raise bad(f"New password: {problem}")
    db.run("UPDATE users SET password_hash = ? WHERE id = ?", await hash_password(b["newPassword"]), u["id"])
    revoke_sessions("staff", u["id"])
    create_session(_res(request), "staff", u["id"], staff_expiry())
    return reply(request, {"ok": True})


# ---- data
@route("/data", "GET")
async def data(request: Request):
    user = any_staff(request)
    update_exam_schedule()
    values = request.query_params.getlist("only")
    only = values[0].split(",") if len(values) == 1 and values[0] else None
    return reply(request, data_payload(only, user))


# ---- candidates
DEPARTMENT_MAX = 60


@route("/candidates", "POST")
async def add_candidate(request: Request):
    user = admin_only(request)
    b = body_of(request)
    name = str_(get(b, "name"), "Name", max=100)
    mail = email_(get(b, "email"))
    department = str_(get(b, "department"), "Department", max=DEPARTMENT_MAX, required=False)
    if db.one("SELECT 1 FROM candidates WHERE email = ?", mail):
        raise bad("A candidate with this email already exists.")
    with db.tx():
        cid = db.new_id("CND")
        db.run("INSERT INTO candidates (id, name, email, department, created_at) VALUES (?, ?, ?, ?, ?)", cid, name, mail, department, db.now())
        db.audit(candidate_id=cid, event="Candidate registered by organization", actor=user["name"], ip=ip_of(request))
    changed("candidates", "auditLogs")
    return reply(request, {"id": cid}, 201)


def _revoke_sessions_for_candidate(candidate_id: str) -> None:
    for inv in db.all_("SELECT id FROM invites WHERE candidate_id = ?", candidate_id):
        revoke_sessions("candidate", inv["id"])
        disconnect_invite(inv["id"], "Your account was deactivated by the organization.")


@route("/candidates/{cid}", "PATCH")
async def update_candidate(request: Request, cid: str):
    user = admin_only(request)
    b = body_of(request)
    c = db.one("SELECT * FROM candidates WHERE id = ?", cid)
    if not c:
        raise not_found("Candidate")
    nxt = {
        "name": str_(get(b, "name"), "Name", max=100) if get(b, "name") is not UNDEFINED else c["name"],
        "email": email_(get(b, "email")) if get(b, "email") is not UNDEFINED else c["email"],
        "department": str_(get(b, "department"), "Department", max=DEPARTMENT_MAX, required=False)
        if get(b, "department") is not UNDEFINED else c["department"],
        "status": one_of(get(b, "status"), "Status", ["Active", "Inactive"]) if get(b, "status") is not UNDEFINED else c["status"],
    }
    with db.tx():
        db.run("UPDATE candidates SET name = ?, email = ?, department = ?, status = ? WHERE id = ?",
               nxt["name"], nxt["email"], nxt["department"], nxt["status"], c["id"])
        if nxt["status"] != c["status"]:
            db.audit(candidate_id=c["id"], event=f"Status changed to {nxt['status']} by organization", actor=user["name"], ip=ip_of(request))
    if nxt["status"] == "Inactive":
        _revoke_sessions_for_candidate(c["id"])
    changed("candidates", "auditLogs")
    return reply(request, {"ok": True})


@route("/candidates/{cid}/assign", "POST")
async def assign_exam(request: Request, cid: str):
    user = admin_only(request)
    b = body_of(request)
    c = db.one("SELECT id FROM candidates WHERE id = ?", cid)
    exam_id = get(b, "examId")
    e = db.one("SELECT id, title FROM exams WHERE id = ?", js_string(exam_id) if truthy(exam_id) else "")
    if not c:
        raise not_found("Candidate")
    if not e:
        raise not_found("Exam")
    with db.tx():
        db.run("INSERT OR IGNORE INTO exam_candidates (exam_id, candidate_id) VALUES (?, ?)", e["id"], c["id"])
        db.audit(candidate_id=c["id"], event=f'Assigned exam "{e["title"]}"', exam_id=e["id"], actor=user["name"], ip=ip_of(request))
    changed("candidates", "exams", "auditLogs")
    return reply(request, {"ok": True})


@route("/candidates/{cid}/flag", "POST")
async def flag(request: Request, cid: str):
    user = any_staff(request)
    b = body_of(request)
    c = db.one("SELECT id FROM candidates WHERE id = ?", cid)
    if not c:
        raise not_found("Candidate")
    exam_id = js_string(get(b, "examId")) if truthy(get(b, "examId")) else None
    flag_candidate(candidate_id=c["id"], exam_id=exam_id,
                   reason=str_(get(b, "reason"), "Reason", max=300, required=False), actor=user["name"])
    changed("candidates", "auditLogs")
    return reply(request, {"ok": True})


# ---- question banks
@route("/banks", "POST")
async def add_bank(request: Request):
    admin_only(request)
    b = body_of(request)
    name = str_(get(b, "name"), "Bank name", max=120)
    topic = str_(get(b, "topic"), "Topic", max=60)
    description = str_(get(b, "description"), "Description", max=500, required=False)
    bank_id = db.new_id("QB")
    db.run("INSERT INTO question_banks (id, name, topic, description, created_at) VALUES (?, ?, ?, ?, ?)",
           bank_id, name, topic, description, db.now())
    changed("questionBanks")
    return reply(request, {"id": bank_id}, 201)


@route("/banks/{bank_id}", "DELETE")
async def delete_bank(request: Request, bank_id: str):
    admin_only(request)
    if not db.run("DELETE FROM question_banks WHERE id = ?", bank_id):
        raise not_found("Question bank")
    changed("questionBanks", "exams")
    return reply(request, {"ok": True})


@route("/banks/{bank_id}/questions", "POST")
async def add_question(request: Request, bank_id: str):
    admin_only(request)
    b = body_of(request)
    bank = db.one("SELECT id FROM question_banks WHERE id = ?", bank_id)
    if not bank:
        raise not_found("Question bank")
    text = str_(get(b, "text"), "Question", max=1000)
    raw_options = get(b, "options")
    if not isinstance(raw_options, list) or len(raw_options) < 2 or len(raw_options) > 8:
        raise bad("Give between 2 and 8 options.")
    options = [str_(o, f"Option {i + 1}", max=300) for i, o in enumerate(raw_options)]
    answer = int_(get(b, "answer"), "Correct answer", 0, len(options) - 1)
    difficulty = get(b, "difficulty")
    difficulty = one_of(difficulty if truthy(difficulty) else "Medium", "Difficulty", ["Easy", "Medium", "Hard"])
    pos = db.one("SELECT COALESCE(MAX(position), 0) + 1 AS p FROM questions WHERE bank_id = ?", bank["id"])["p"]
    qid = db.new_id("Q")
    db.run("INSERT INTO questions (id, bank_id, text, options, answer, difficulty, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
           qid, bank["id"], text, dumps(options), answer, difficulty, pos)
    changed("questionBanks")
    return reply(request, {"id": qid}, 201)


@route("/banks/{bank_id}/questions/{qid}", "DELETE")
async def delete_question(request: Request, bank_id: str, qid: str):
    admin_only(request)
    if not db.run("DELETE FROM questions WHERE id = ? AND bank_id = ?", qid, bank_id):
        raise not_found("Question")
    changed("questionBanks")
    return reply(request, {"ok": True})


# ---- exams
@route("/exams", "POST")
async def add_exam(request: Request):
    admin_only(request)
    b = body_of(request)
    title = str_(get(b, "title"), "Exam title", max=150)
    bank_id = str_(get(b, "bankId"), "Question bank")
    if not db.one("SELECT 1 FROM question_banks WHERE id = ?", bank_id):
        raise not_found("Question bank")
    start_time = iso_date(get(b, "startTime"), "Start time")
    duration = int_(get(b, "duration"), "Duration", 5, 600)
    pass_mark = int_(get(b, "passMark"), "Pass mark", 1, 100)
    exam_id = db.new_id("EX")
    db.run("INSERT INTO exams (id, title, bank_id, start_time, duration, pass_mark, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
           exam_id, title, bank_id, start_time, duration, pass_mark, db.now())
    changed("exams")
    return reply(request, {"id": exam_id}, 201)


@route("/exams/{exam_id}", "PATCH")
async def update_exam(request: Request, exam_id: str):
    user = admin_only(request)
    b = body_of(request)
    e = db.one("SELECT * FROM exams WHERE id = ?", exam_id)
    if not e:
        raise not_found("Exam")
    status = one_of(get(b, "status"), "Status", ["Scheduled", "Live", "Completed"])
    db.run("UPDATE exams SET status = ?, start_time = CASE WHEN ? = 'Live' AND status = 'Scheduled' THEN ? ELSE start_time END WHERE id = ?",
           status, status, db.now(), e["id"])
    if status == "Completed":
        open_attempts = db.all_("SELECT invite_id FROM attempts WHERE exam_id = ? AND status = 'InProgress'", e["id"])
        finish_attempts_for_exam(e["id"])
        for a in open_attempts:
            disconnect_invite(a["invite_id"], "The exam has ended. Your answers were submitted.")
    db.audit(type="Normal", event=f'Exam "{e["title"]}" set to {status}', exam_id=e["id"], actor=user["name"], ip=ip_of(request))
    changed("exams", "results", "auditLogs")
    return reply(request, {"ok": True})


@route("/exams/{exam_id}", "DELETE")
async def delete_exam(request: Request, exam_id: str):
    admin_only(request)
    invites = db.all_("SELECT id FROM invites WHERE exam_id = ?", exam_id)
    if not db.run("DELETE FROM exams WHERE id = ?", exam_id):
        raise not_found("Exam")
    for i in invites:
        revoke_sessions("candidate", i["id"])
        disconnect_invite(i["id"], "This exam was cancelled.")
    changed("exams", "candidates", "results")
    return reply(request, {"ok": True})


# ---- invites
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def new_code() -> str:
    """A new Test ID such as M8NJ-ZPCV. Unique across all invitations, because candidates
    sign in with the Test ID alone (31^8, about 850 billion possibilities)."""
    while True:
        s = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
        if not db.one("SELECT 1 FROM invites WHERE code_hash = ?", db.sha256(s)):
            return f"{s[:4]}-{s[4:]}"


def norm_code(c: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", (js_string(c) if truthy(c) else "").upper())


@route("/exams/{exam_id}/invites", "GET")
async def list_invites(request: Request, exam_id: str):
    admin_only(request)
    e = db.one("SELECT id FROM exams WHERE id = ?", exam_id)
    if not e:
        raise not_found("Exam")
    latest = db.all_(
        """SELECT i.* FROM invites i
           WHERE i.exam_id = ? AND i.created_at = (SELECT MAX(created_at) FROM invites WHERE exam_id = i.exam_id AND candidate_id = i.candidate_id)""",
        e["id"],
    )
    by_cand = {i["candidate_id"]: i for i in latest}
    rows = db.all_("SELECT c.id, c.name, c.email FROM exam_candidates ec JOIN candidates c ON c.id = ec.candidate_id WHERE ec.exam_id = ? ORDER BY c.name", e["id"])
    out = []
    for c in rows:
        inv = by_cand.get(c["id"])
        expired = bool(inv) and inv["expires_at"] < db.now() and inv["status"] in ("Pending", "Started")
        out.append({
            "candidateId": c["id"],
            "name": c["name"],
            "email": c["email"],
            "inviteId": inv["id"] if inv else None,
            "status": ("Expired" if expired else inv["status"]) if inv else "Not invited",
            "createdAt": inv["created_at"] if inv else None,
            "emailedAt": inv["emailed_at"] if inv else None,
        })
    return reply(request, {"emailEnabled": email_enabled(), "emailMode": email_mode(), "invites": out})


@route("/exams/{exam_id}/invites", "POST")
async def create_invites(request: Request, exam_id: str):
    """Creates fresh invites (new link + code) for the chosen assigned candidates. Old links stop working."""
    user = admin_only(request)
    b = body_of(request)
    e = db.one("SELECT * FROM exams WHERE id = ?", exam_id)
    if not e:
        raise not_found("Exam")
    assigned = [r["candidate_id"] for r in db.all_("SELECT candidate_id FROM exam_candidates WHERE exam_id = ?", e["id"])]
    requested = get(b, "candidateIds")
    ids = [js_string(x) for x in requested] if isinstance(requested, list) and requested else list(assigned)
    if not ids:
        raise bad("Assign candidates to this exam first.")
    not_assigned = [i for i in ids if i not in assigned]
    if not_assigned:
        raise bad(f"Not assigned to this exam: {', '.join(not_assigned)}")
    do_email = truthy(get(b, "sendEmail"))
    if do_email and not email_enabled():
        raise bad("Email is not set up. Go to Settings → Email, or copy the links instead.")

    settings = db.get_settings()
    expires = iso(datetime.now(timezone.utc) + timedelta(days=config.invite_valid_days))
    created = []
    with db.tx():
        for cid in ids:
            c = db.one("SELECT id, name, email, status FROM candidates WHERE id = ?", cid)
            # Retire older invites that were never finished.
            for o in db.all_("SELECT id FROM invites WHERE exam_id = ? AND candidate_id = ? AND status IN ('Pending','Locked')", e["id"], cid):
                db.run("UPDATE invites SET status = 'Revoked' WHERE id = ?", o["id"])
                revoke_sessions("candidate", o["id"])
            started = db.one("SELECT id FROM invites WHERE exam_id = ? AND candidate_id = ? AND status IN ('Started','Submitted','Terminated')", e["id"], cid)
            if started:
                created.append({"candidateId": cid, "name": c["name"], "email": c["email"], "skipped": "Already started this exam"})
                continue
            token = db.random_token(24)
            code = new_code()
            inv_id = db.new_id("INV")
            db.run("INSERT INTO invites (id, exam_id, candidate_id, token_hash, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   inv_id, e["id"], cid, db.sha256(token), db.sha256(norm_code(code)), db.now(), expires)
            db.audit(candidate_id=cid, type="Normal", event="Exam invitation created", exam_id=e["id"], actor=user["name"], ip=ip_of(request))
            created.append({"candidateId": cid, "name": c["name"], "email": c["email"], "inviteId": inv_id,
                            "link": f"{base_url(request)}/exam?t={token}", "code": code})

    if do_email:
        for inv in created:
            if not inv.get("link"):
                continue
            try:
                await send_invite_email(
                    to=inv["email"], name=inv["name"], exam_title=e["title"], start_time=e["start_time"], duration=e["duration"],
                    link=inv["link"], code=inv["code"], org_name=settings["organization"]["name"],
                    support_email=settings["organization"]["supportEmail"], signin_url=f"{base_url(request)}/exam",
                )
                db.run("UPDATE invites SET emailed_at = ? WHERE id = ?", db.now(), inv["inviteId"])
                inv["emailed"] = True
            except MailError as err:
                inv["emailError"] = str(err)
            except Exception as err:
                inv["emailError"] = "Email could not be sent."
                print("[mail]", repr(err))
    changed("auditLogs")
    return reply(request, {"invites": created, "emailMode": email_mode() if do_email else None}, 201)


@route("/invites/{invite_id}/revoke", "POST")
async def revoke_invite(request: Request, invite_id: str):
    user = admin_only(request)
    inv = db.one("SELECT * FROM invites WHERE id = ?", invite_id)
    if not inv:
        raise not_found("Invitation")
    db.run("UPDATE invites SET status = 'Revoked' WHERE id = ?", inv["id"])
    revoke_sessions("candidate", inv["id"])
    disconnect_invite(inv["id"], "Your invitation was withdrawn by the organization.")
    db.audit(candidate_id=inv["candidate_id"], type="Normal", event="Exam invitation revoked", exam_id=inv["exam_id"],
             actor=user["name"], ip=ip_of(request))
    changed("auditLogs")
    return reply(request, {"ok": True})


# ---- feedback
@route("/feedback", "POST")
async def add_feedback(request: Request):
    user = any_staff(request)
    b = body_of(request)
    candidate_id = str_(get(b, "candidateId"), "Candidate")
    if not db.one("SELECT 1 FROM candidates WHERE id = ?", candidate_id):
        raise not_found("Candidate")
    exam_id = str_(get(b, "examId"), "Exam") if truthy(get(b, "examId")) else None
    if exam_id and not db.one("SELECT 1 FROM exams WHERE id = ?", exam_id):
        raise not_found("Exam")
    rating = int_(get(b, "rating"), "Rating", 1, 5)
    message = str_(get(b, "message"), "Message", max=2000)
    fb_id = db.new_id("FB")
    with db.tx():
        db.run("INSERT INTO feedback (id, candidate_id, exam_id, rating, message, sent_by, sent_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
               fb_id, candidate_id, exam_id, rating, message, user["name"], db.now())
        db.audit(candidate_id=candidate_id, event="Feedback sent by organization", exam_id=exam_id, actor=user["name"], ip=ip_of(request))
    changed("feedback", "auditLogs")
    return reply(request, {"id": fb_id}, 201)


@route("/feedback/{fb_id}", "DELETE")
async def delete_feedback(request: Request, fb_id: str):
    admin_only(request)
    if not db.run("DELETE FROM feedback WHERE id = ?", fb_id):
        raise not_found("Feedback")
    changed("feedback")
    return reply(request, {"ok": True})


# ---- settings
@route("/settings/{section}", "PUT")
async def update_settings(request: Request, section: str):
    user = admin_only(request)
    b = body_of(request)
    section = one_of(section, "Section", list(db.DEFAULT_SETTINGS))
    nxt = dict(db.get_settings()[section])
    for key, default in db.DEFAULT_SETTINGS[section].items():
        v = get(b, key)
        if v is UNDEFINED:
            continue
        if isinstance(default, bool):
            nxt[key] = truthy(v)
        elif isinstance(default, (int, float)):
            nxt[key] = int_(v, key, 0, 100000)
        else:
            nxt[key] = str_(v, key, max=500, required=False)
    if section == "organization":
        if not truthy(nxt.get("name")):
            raise bad("Organization name is required.")
        for k in ("companyUrl", "logoUrl"):
            if truthy(nxt.get(k)) and not re.match(r"^(https://|data:image/)", js_string(nxt[k]), re.I):
                raise bad(f"{'Logo URL' if k == 'logoUrl' else 'Company URL'} must start with https://")
        if truthy(nxt.get("supportEmail")):
            nxt["supportEmail"] = email_(nxt["supportEmail"], "Support email")
    db.save_settings(section, nxt)
    db.audit(event=f"Settings updated: {section}", actor=user["name"], ip=ip_of(request))
    changed("settings", "auditLogs")
    return reply(request, {"settings": db.get_settings()})


# ---- email (Settings -> Email); admin only, the password never leaves the server
@route("/mail-settings", "GET")
async def get_mail_settings(request: Request):
    admin_only(request)
    return reply(request, {"mail": public_mail_config()})


@route("/mail-settings", "PUT")
async def update_mail_settings(request: Request):
    user = admin_only(request)
    if env_configured():
        raise HttpError(409, "Email is set by SMTP_* in the server's .env file. Change it there, or remove those lines to manage email here.")
    b = body_of(request)
    current = mail_config()
    mode = one_of(get(b, "mode"), "Mode", list(MAIL_MODES))
    nxt = {**current, "mode": mode}
    if mode == "smtp" or any(get(b, k) is not UNDEFINED for k in ("host", "port", "from")):
        host = str_(get(b, "host"), "SMTP server", max=253, required=mode == "smtp")
        if host and re.search(r"[\s/:]", host):
            raise bad("SMTP server should be a name like smtp.gmail.com (no https://, no port).")
        port = int_(get(b, "port"), "Port", 1, 65535) if get(b, "port") is not UNDEFINED else current["port"]
        security = one_of(get(b, "security"), "Security", list(MAIL_SECURITY)) if get(b, "security") is not UNDEFINED else current["security"]
        sender = str_(get(b, "from"), "From address", max=300, required=mode == "smtp")
        if sender and not valid_from(sender):
            raise bad('From address must be an email address, e.g. exams@yourcompany.com or "Exams <exams@yourcompany.com>".')
        nxt.update(host=host, port=port, security=security, user=str_(get(b, "user"), "Username", max=254, required=False))
        nxt["from"] = sender
    password = get(b, "password")
    if isinstance(password, str) and password:
        if js_length(password) > 500:
            raise bad("Password is too long.")
        nxt["password"] = password
    elif get(b, "clearPassword") is True:
        nxt["password"] = ""
    save_mail_config(nxt)
    db.audit(event=f"Email settings updated (mode: {mode})", actor=user["name"], ip=ip_of(request))
    changed("auditLogs")
    return reply(request, {"mail": public_mail_config()})


_test_mail_limit = Limiter(10, 15)


@route("/mail-settings/test", "POST")
async def test_mail(request: Request):
    user = admin_only(request)
    _test_mail_limit.check(request)
    b = body_of(request)
    to = email_(get(b, "to"), "Send test to") if truthy(get(b, "to")) else user["email"]
    if not email_enabled():
        raise bad("Email is off. Choose Test mode or SMTP and save first.")
    try:
        mode = await send_test_email(to=to, org_name=db.get_settings()["organization"]["name"])
    except MailError as err:
        raise bad(str(err)) from None
    db.audit(event=f"Test email {'saved to outbox' if mode == 'test' else 'sent'} for {to}", actor=user["name"], ip=ip_of(request))
    message = (f"Saved to the test outbox for {to} (nothing was sent)." if mode == "test"
               else f"Test email sent to {to}. Check that inbox (and the spam folder).")
    return reply(request, {"ok": True, "mode": mode, "message": message})


@route("/outbox", "GET")
async def outbox(request: Request):
    admin_only(request)
    return reply(request, {"emails": list_outbox(50)})


@route("/outbox", "DELETE")
async def empty_outbox(request: Request):
    admin_only(request)
    return reply(request, {"ok": True, "deleted": clear_outbox()})


# ---- users
def public_user(u: dict) -> dict:
    return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"], "active": bool(u["active"]),
            "createdAt": u["created_at"], "lastLoginAt": u["last_login_at"]}


@route("/users", "GET")
async def list_users(request: Request):
    admin_only(request)
    return reply(request, {"users": [public_user(u) for u in db.all_("SELECT * FROM users ORDER BY created_at")]})


@route("/users", "POST")
async def add_user(request: Request):
    user = admin_only(request)
    b = body_of(request)
    name = str_(get(b, "name"), "Name", max=100)
    mail = email_(get(b, "email"))
    role = one_of(get(b, "role"), "Role", ["admin", "proctor"])
    problem = password_problem(get(b, "password"))
    if problem:
        raise bad(f"Temporary password: {problem}")
    if db.one("SELECT 1 FROM users WHERE email = ?", mail):
        raise bad("A user with this email already exists.")
    uid = db.new_id("USR")
    db.run("INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
           uid, name, mail, await hash_password(b["password"]), role, db.now())
    db.audit(event=f"User {mail} created as {role}", actor=user["name"], ip=ip_of(request))
    return reply(request, {"user": public_user(db.one("SELECT * FROM users WHERE id = ?", uid))}, 201)


@route("/users/{user_id}", "PATCH")
async def update_user(request: Request, user_id: str):
    me_ = admin_only(request)
    b = body_of(request)
    u = db.one("SELECT * FROM users WHERE id = ?", user_id)
    if not u:
        raise not_found("User")
    role = one_of(get(b, "role"), "Role", ["admin", "proctor"]) if get(b, "role") is not UNDEFINED else u["role"]
    active = (1 if truthy(get(b, "active")) else 0) if get(b, "active") is not UNDEFINED else u["active"]
    losing_admin = u["role"] == "admin" and u["active"] and (role != "admin" or not active)
    if losing_admin and db.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1")["n"] <= 1:
        raise bad("There must be at least one active admin.")
    password_hash = u["password_hash"]
    if get(b, "password") is not UNDEFINED:
        problem = password_problem(get(b, "password"))
        if problem:
            raise bad(f"New password: {problem}")
        password_hash = await hash_password(b["password"])
    db.run("UPDATE users SET role = ?, active = ?, password_hash = ? WHERE id = ?", role, active, password_hash, u["id"])
    if not active or password_hash != u["password_hash"] or role != u["role"]:
        if u["id"] != me_["id"] or not active:
            revoke_sessions("staff", u["id"])
            disconnect_user(u["id"])
    db.audit(event=f"User {u['email']} updated", actor=me_["name"], ip=ip_of(request))
    return reply(request, {"user": public_user(db.one("SELECT * FROM users WHERE id = ?", u["id"]))})


# ---- recordings
@route("/recordings", "GET")
async def recordings(request: Request):
    any_staff(request)
    return reply(request, {"recordings": list_recordings()})


@route("/recordings", "POST")
async def upload_recording(request: Request):
    user = any_staff(request)
    mime = request.headers.get("content-type", "").split(";")[0].strip()
    if mime not in ("video/webm", "video/mp4"):
        raise bad("Recordings must be WebM or MP4 video.")
    q = request.query_params
    candidate_id = q.get("candidateId") or ""
    if not db.one("SELECT 1 FROM candidates WHERE id = ?", candidate_id):
        raise not_found("Candidate")
    exam_id = q.get("examId") if q.get("examId") and db.one("SELECT 1 FROM exams WHERE id = ?", q.get("examId")) else None
    n = js_number(q.get("duration", UNDEFINED))
    duration: int | float = 0 if math.isnan(n) or n == 0 else max(0, min(24 * 3600, n))
    if isinstance(duration, float) and duration.is_integer():
        duration = int(duration)
    limit = config.max_recording_mb * 1024 * 1024
    rec_id = db.new_id("REC")
    file_name = f"{rec_id}.{'mp4' if mime == 'video/mp4' else 'webm'}"
    path = REC_DIR / file_name
    size = 0
    try:
        with open(path, "xb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise HttpError(413, f"Recording is larger than {config.max_recording_mb} MB.")
                out.write(chunk)
        if not size:
            raise bad("Recording is empty.")
    except ClientDisconnect:
        path.unlink(missing_ok=True)
        raise bad("Upload was interrupted.") from None
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    db.run("INSERT INTO recordings (id, candidate_id, exam_id, file_name, mime, size, duration, recorded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
           rec_id, candidate_id, exam_id, file_name, mime, size, duration, user["name"], db.now())
    db.audit(candidate_id=candidate_id, type="Validation", event="Session recording saved to server", exam_id=exam_id,
             actor=user["name"], ip=ip_of(request))
    changed("auditLogs", "recordings")
    return reply(request, {"recording": next((r for r in list_recordings() if r["id"] == rec_id), None)}, 201)


@route("/recordings/{rec_id}/file", "GET")
async def recording_file(request: Request, rec_id: str):
    any_staff(request)
    r = db.one("SELECT * FROM recordings WHERE id = ?", rec_id)
    if not r:
        raise not_found("Recording")
    path = REC_DIR / r["file_name"]
    if not path.is_file():
        raise not_found("Recording file")
    headers = {"Cache-Control": "private, no-store"}
    if request.query_params.get("download"):
        stamp = re.sub(r"[:T]", "-", r["created_at"][:19])
        headers["Content-Disposition"] = f'attachment; filename="{r["candidate_id"]}-{stamp}{path.suffix}"'
    return FileResponse(path, media_type=r["mime"], headers=headers)


@route("/recordings/{rec_id}", "DELETE")
async def delete_recording(request: Request, rec_id: str):
    user = admin_only(request)
    r = db.one("SELECT * FROM recordings WHERE id = ?", rec_id)
    if not r:
        raise not_found("Recording")
    db.run("DELETE FROM recordings WHERE id = ?", r["id"])
    (REC_DIR / r["file_name"]).unlink(missing_ok=True)
    db.audit(candidate_id=r["candidate_id"], event="Session recording deleted", exam_id=r["exam_id"], actor=user["name"], ip=ip_of(request))
    changed("recordings", "auditLogs")
    return reply(request, {"ok": True})


# ---- WebRTC config
@route("/ice", "GET")
async def ice(request: Request):
    user = staff_from_cookies(request.cookies)
    cand = None if user else candidate_from_cookies(request.cookies)
    if not user and not cand:
        return reply(request, {"error": "Please sign in."}, 401)
    return reply(request, {"iceServers": ice_servers(f"staff-{user['id']}" if user else f"cand-{cand['invite_id']}")})


# ---- candidate portal
def invite_by_token(token: Any) -> dict | None:
    if not isinstance(token, str) or js_length(token) < 20 or js_length(token) > 100:
        return None
    return db.one(
        """SELECT i.*, c.name, c.status AS candidate_status, e.title, e.duration, e.status AS exam_status, e.start_time
           FROM invites i JOIN candidates c ON c.id = i.candidate_id JOIN exams e ON e.id = i.exam_id
           WHERE i.token_hash = ?""",
        db.sha256(token),
    )


def invite_problem(inv: dict | None) -> str | None:
    if not inv:
        return "This exam link is not valid. Check that you copied the whole link from your invitation."
    if inv["status"] == "Revoked":
        return "This invitation has been withdrawn. Contact your organization for a new link."
    if inv["status"] == "Locked":
        return "This invitation is locked after too many wrong Test IDs. Contact your organization for a new one."
    if inv["status"] == "Submitted":
        return "You have already submitted this exam."
    if inv["status"] == "Terminated":
        return "This exam was ended by the proctor."
    if inv["expires_at"] < db.now():
        return "This invitation has expired. Contact your organization for a new link."
    if inv["candidate_status"] != "Active":
        return "Your account is inactive. Contact your organization."
    if inv["exam_status"] == "Completed":
        return "This exam has already ended."
    return None


_lookup_limit = Limiter(60, 15)
_cand_login_limit = Limiter(20, 15)


@route("/candidate/lookup", "POST")
async def candidate_lookup(request: Request):
    _lookup_limit.check(request)
    update_exam_schedule()
    inv = invite_by_token(get(body_of(request), "token"))
    problem = invite_problem(inv)
    if problem:
        return reply(request, {"error": problem}, 409 if inv else 404)
    org = db.get_settings()["organization"]
    return reply(request, {
        "exam": {"title": inv["title"], "duration": inv["duration"], "status": inv["exam_status"], "startTime": inv["start_time"]},
        "candidate": {"firstName": inv["name"].split(" ")[0]},
        "organization": {"name": org.get("name"), "logoUrl": org.get("logoUrl"), "supportEmail": org.get("supportEmail")},
    })


@route("/candidate/login", "POST")
async def candidate_login(request: Request):
    _cand_login_limit.check(request)
    update_exam_schedule()
    b = body_of(request)
    inv = invite_by_token(get(b, "token"))
    problem = invite_problem(inv)
    if problem:
        return reply(request, {"error": problem}, 409 if inv else 404)
    if not hmac.compare_digest(db.sha256(norm_code(get(b, "code"))), inv["code_hash"]):
        fails = inv["failed_attempts"] + 1
        db.run("UPDATE invites SET failed_attempts = ?, status = CASE WHEN ? >= 5 THEN 'Locked' ELSE status END WHERE id = ?",
               fails, fails, inv["id"])
        db.audit(candidate_id=inv["candidate_id"], type="Warning",
                 event="Invitation locked after 5 wrong Test IDs" if fails >= 5 else "Wrong Test ID entered on the exam link",
                 exam_id=inv["exam_id"], ip=ip_of(request))
        changed("auditLogs")
        message = ("Too many wrong attempts. This invitation is now locked; contact your organization." if fails >= 5
                   else f"That Test ID is not correct. {5 - fails} tries left.")
        return reply(request, {"error": message}, 401)
    return _begin_candidate_session(request, inv, "Signed in with exam link and Test ID")


def _begin_candidate_session(request: Request, inv: dict, how: str) -> Response:
    db.run("UPDATE invites SET failed_attempts = 0 WHERE id = ?", inv["id"])
    revoke_sessions("candidate", inv["id"])  # one active device per invitation
    disconnect_invite(inv["id"], "You signed in to this exam on another device.")
    expires_ms = min(now_ms() + 12 * 3600 * 1000, date_ms(inv["expires_at"]))
    create_session(_res(request), "candidate", inv["id"], datetime.fromtimestamp(expires_ms / 1000, tz=timezone.utc))
    db.audit(candidate_id=inv["candidate_id"], type="Validation", event=how, exam_id=inv["exam_id"], ip=ip_of(request))
    touch_candidate(inv["candidate_id"])
    changed("auditLogs", "candidates")
    return reply(request, {"ok": True})


_signin_limit = Limiter(10, 15)  # Test ID attempts per network address


@route("/candidate/portal", "GET")
async def candidate_portal(request: Request):
    """Public branding for the candidate sign-in page."""
    org = db.get_settings()["organization"]
    return reply(request, {"organization": {"name": org.get("name"), "logoUrl": org.get("logoUrl"), "supportEmail": org.get("supportEmail")}})


@route("/candidate/signin", "POST")
async def candidate_signin(request: Request):
    """Sign in with the Test ID alone (the personal code from the invitation).

    Test IDs are random and unique (about 850 billion possibilities), attempts are limited per
    network address, and wrong guesses never lock anyone's invitation."""
    _signin_limit.check(request)
    update_exam_schedule()
    b = body_of(request)
    test_id = norm_code(get(b, "testId") if get(b, "testId") is not UNDEFINED else get(b, "code"))
    if not test_id:
        raise bad("Enter your Test ID.")
    inv = None
    if len(test_id) == 8:
        inv = db.one(
            """SELECT i.*, c.name, c.status AS candidate_status, e.title, e.duration, e.status AS exam_status, e.start_time
               FROM invites i JOIN candidates c ON c.id = i.candidate_id JOIN exams e ON e.id = i.exam_id
               WHERE i.code_hash = ? ORDER BY i.created_at DESC LIMIT 1""",
            db.sha256(test_id),
        )
    if not inv:
        db.audit(type="Warning", event="Invalid Test ID entered on the candidate sign-in page", ip=ip_of(request))
        changed("auditLogs")
        raise HttpError(401, "That Test ID is not valid. Check the Test ID in your invitation and try again.")
    problem = invite_problem(inv)
    if problem:
        return reply(request, {"error": problem}, 409)
    return _begin_candidate_session(request, inv, "Signed in with Test ID")


def candidate_state(ctx: dict) -> dict:
    settings = db.get_settings()
    attempt = get_attempt_by_invite(ctx["invite_id"])
    bank_size = db.one("SELECT COUNT(*) AS n FROM questions WHERE bank_id = ?", ctx["bank_id"])["n"] if ctx["bank_id"] else 0
    base: dict[str, Any] = {
        "candidate": {"id": ctx["candidate_id"], "name": ctx["name"], "department": ctx["department"]},
        "exam": {"id": ctx["exam_id"], "title": ctx["exam_title"], "status": ctx["exam_status"], "duration": ctx["duration"], "questionCount": bank_size},
        "rules": {"browserLockdown": truthy(settings["security"].get("browserLockdown")),
                  "faceDetection": truthy(settings["security"].get("faceDetection", True))},
        "organization": {"name": settings["organization"].get("name"), "logoUrl": settings["organization"].get("logoUrl")},
        "attempt": None,
    }
    if not attempt:
        return base
    seconds_left = max(0, js_round((date_ms(attempt["deadline"]) - now_ms()) / 1000))
    base["attempt"] = {"status": attempt["status"], "secondsLeft": seconds_left, "startedAt": attempt["started_at"]}
    if attempt["status"] == "InProgress":
        base["attempt"]["questions"] = attempt_questions(attempt)
        base["attempt"]["answers"] = loads(attempt["answers"] or "{}", {})
    elif attempt["status"] == "Submitted" and truthy(settings["exam"].get("showResultsToCandidate")):
        r = db.one("SELECT score, correct, total, result FROM results WHERE candidate_id = ? AND exam_id = ?", ctx["candidate_id"], ctx["exam_id"])
        if r:
            base["attempt"]["result"] = r
    elif attempt["status"] == "Terminated":
        base["attempt"]["reason"] = attempt["terminated_reason"] or ""
    return base


def expire_if_needed(ctx: dict) -> None:
    a = get_attempt_by_invite(ctx["invite_id"])
    if a and a["status"] == "InProgress" and date_ms(a["deadline"]) + 30000 < now_ms():
        finish_attempt(a["id"], reason="time ran out")
        changed("results", "auditLogs")


@route("/candidate/me", "GET")
async def candidate_me(request: Request):
    update_exam_schedule()
    ctx = require_candidate(request)
    expire_if_needed(ctx)
    return reply(request, candidate_state(ctx))


@route("/candidate/start", "POST")
async def candidate_start(request: Request):
    update_exam_schedule()
    ctx = require_candidate(request)
    if ctx["exam_status"] != "Live":
        raise HttpError(409, "The exam has not started yet. This page updates when it does." if ctx["exam_status"] == "Scheduled" else "This exam has ended.")
    if not ctx["bank_id"] or not db.one("SELECT 1 FROM questions WHERE bank_id = ?", ctx["bank_id"]):
        raise HttpError(409, "This exam has no questions yet. Contact your organization.")
    a = get_attempt_by_invite(ctx["invite_id"])
    if a and a["status"] != "InProgress":
        raise HttpError(409, "You have already finished this exam.")
    start_attempt(ctx)
    changed("auditLogs", "candidates")
    return reply(request, candidate_state(ctx))


@route("/candidate/answers", "PUT")
async def candidate_answer(request: Request):
    ctx = require_candidate(request)
    b = body_of(request)
    expire_if_needed(ctx)
    a = get_attempt_by_invite(ctx["invite_id"])
    if not a or a["status"] != "InProgress":
        raise HttpError(409, "This exam is no longer accepting answers.")
    order = json.loads(a["question_order"])
    question_id = get(b, "questionId")
    q = next((o for o in order if isinstance(question_id, str) and o["id"] == question_id), None)
    if not q:
        raise bad("Unknown question.")
    answers = loads(a["answers"] or "{}", {}) or {}
    value = get(b, "value")
    if value is None:
        answers.pop(q["id"], None)
    else:
        n = js_number(value)
        if math.isnan(n) or not n.is_integer() or int(n) not in q["options"]:
            raise bad("Unknown option.")
        answers[q["id"]] = int(n)
    db.run("UPDATE attempts SET answers = ? WHERE id = ?", dumps(answers), a["id"])
    touch_candidate(ctx["candidate_id"])
    return reply(request, {"ok": True, "saved": len(answers)})


@route("/candidate/submit", "POST")
async def candidate_submit(request: Request):
    ctx = require_candidate(request)
    a = get_attempt_by_invite(ctx["invite_id"])
    if not a:
        raise HttpError(409, "You have not started this exam.")
    if a["status"] == "InProgress":
        finish_attempt(a["id"])
    changed("results", "auditLogs", "candidates")
    return reply(request, candidate_state(ctx))


@route("/candidate/logout", "POST")
async def candidate_logout(request: Request):
    destroy_session(request, _res(request), "candidate")
    return reply(request, {"ok": True})


# ---- anything else under /api
@api.api_route("/{rest:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def api_not_found(request: Request, rest: str):
    return reply(request, {"error": "Not found."}, 404)
