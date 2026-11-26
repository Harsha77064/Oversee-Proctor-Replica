"""Password hashing, cookie sessions and role checks.

Password hashes use the same scrypt format as before
(scrypt$<salt b64>$<key b64>, N=16384 r=8 p=1), so existing accounts keep working.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any
from urllib.parse import unquote

from fastapi import Request, Response

from . import db
from .config import config
from .jsutil import iso, js_length, now_iso

STAFF_COOKIE = "ov_staff"
CANDIDATE_COOKIE = "ov_cand"
_SCRYPT = {"n": 16384, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024}


def _scrypt(password: str, salt: bytes, dklen: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=dklen, **_SCRYPT)


async def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = await asyncio.to_thread(_scrypt, password, salt, 64)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"


async def verify_password(password: str, stored: str) -> bool:
    parts = str(stored).split("$")
    if len(parts) < 3 or parts[0] != "scrypt" or not parts[1] or not parts[2]:
        return False
    try:
        salt = base64.b64decode(parts[1])
        expected = base64.b64decode(parts[2])
    except (binascii.Error, ValueError):
        return False
    if not expected:
        return False
    key = await asyncio.to_thread(_scrypt, password, salt, len(expected))
    return hmac.compare_digest(key, expected)


def password_problem(password: Any) -> str | None:
    if not isinstance(password, str) or js_length(password) < 10:
        return "Use at least 10 characters."
    if js_length(password) > 200:
        return "Use at most 200 characters."
    if not re.search(r"[a-zA-Z]", password) or not re.search(r"[0-9]", password):
        return "Use both letters and numbers."
    return None


# ---------------------------------------------------------------- cookies
def _cookie_header(name: str, value: str, expires: datetime | None) -> str:
    parts = [f"{name}={value}", "Path=/"]
    if expires is not None:
        parts.append(f"Expires={format_datetime(expires.astimezone(timezone.utc), usegmt=True)}")
    parts.append("HttpOnly")
    if config.cookie_secure:
        parts.append("Secure")
    parts.append("SameSite=Lax")
    return "; ".join(parts)


def create_session(res: Response, kind: str, subject_id: str, expires_at: datetime) -> None:
    token = db.random_token(32)
    db.run(
        "INSERT INTO sessions (token_hash, kind, subject_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        db.sha256(token), kind, subject_id, now_iso(), iso(expires_at),
    )
    name = STAFF_COOKIE if kind == "staff" else CANDIDATE_COOKIE
    res.headers.append("set-cookie", _cookie_header(name, token, expires_at))


def destroy_session(req: Request, res: Response, kind: str) -> None:
    name = STAFF_COOKIE if kind == "staff" else CANDIDATE_COOKIE
    token = req.cookies.get(name)
    if token:
        db.run("DELETE FROM sessions WHERE token_hash = ?", db.sha256(token))
    res.headers.append("set-cookie", _cookie_header(name, "", datetime(1970, 1, 1, tzinfo=timezone.utc)))


def revoke_sessions(kind: str, subject_id: str) -> None:
    db.run("DELETE FROM sessions WHERE kind = ? AND subject_id = ?", kind, subject_id)


def _lookup(token: str | None, kind: str) -> dict | None:
    if not token:
        return None
    s = db.one("SELECT * FROM sessions WHERE token_hash = ? AND kind = ?", db.sha256(token), kind)
    if not s:
        return None
    if s["expires_at"] < now_iso():
        db.run("DELETE FROM sessions WHERE token_hash = ?", s["token_hash"])
        return None
    return s


def staff_from_cookies(cookies: dict[str, str]) -> dict | None:
    """Staff user for a cookie map, or None. Used by HTTP and WebSocket."""
    s = _lookup(cookies.get(STAFF_COOKIE), "staff")
    if not s:
        return None
    u = db.one("SELECT id, name, email, role, active FROM users WHERE id = ?", s["subject_id"])
    return u if u and u["active"] else None


def candidate_from_cookies(cookies: dict[str, str]) -> dict | None:
    """Candidate invite context for a cookie map, or None."""
    s = _lookup(cookies.get(CANDIDATE_COOKIE), "candidate")
    if not s:
        return None
    inv = db.one(
        """
        SELECT i.id AS invite_id, i.status AS invite_status, i.exam_id, i.candidate_id,
               c.name, c.email, c.department, c.status AS candidate_status,
               e.title AS exam_title, e.status AS exam_status, e.duration, e.bank_id, e.pass_mark
        FROM invites i JOIN candidates c ON c.id = i.candidate_id JOIN exams e ON e.id = i.exam_id
        WHERE i.id = ?""",
        s["subject_id"],
    )
    if not inv or inv["invite_status"] == "Revoked" or inv["candidate_status"] != "Active":
        return None
    return inv


def parse_cookie_header(header: str = "") -> dict[str, str]:
    """Parse a raw Cookie header (for WebSocket upgrades)."""
    out: dict[str, str] = {}
    for part in (header or "").split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = unquote(v.strip())
    return out


def purge_expired_sessions() -> None:
    db.run("DELETE FROM sessions WHERE expires_at < ?", now_iso())
