"""SQLite database: schema, migrations and small query helpers.

One connection is shared by the whole server. All request handling runs on a
single asyncio event loop thread, so queries never overlap (the same model as
the original Node server); blocking work such as password hashing and email
runs in worker threads that do not touch the database.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator

from .config import config
from .jsutil import dumps, now_iso

_conn = sqlite3.connect(
    config.data_dir / "oversee.db",
    isolation_level=None,  # autocommit; transactions are explicit (see tx)
    check_same_thread=False,
)
_conn.row_factory = lambda cur, row: {d[0]: row[i] for i, d in enumerate(cur.description)}
_conn.execute("PRAGMA journal_mode = WAL")
_conn.execute("PRAGMA foreign_keys = ON")
_conn.execute("PRAGMA busy_timeout = 5000")
_lock = threading.RLock()

MIGRATIONS = [
    """
  CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'proctor')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login_at TEXT
  );
  CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('staff', 'candidate')),
    subject_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );
  CREATE INDEX sessions_subject ON sessions(kind, subject_id);
  CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
  CREATE TABLE settings (section TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE candidates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    department TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive')),
    warnings INTEGER NOT NULL DEFAULT 0,
    cheating_flags INTEGER NOT NULL DEFAULT 0,
    last_active TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE question_banks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    topic TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
  );
  CREATE TABLE questions (
    id TEXT PRIMARY KEY,
    bank_id TEXT NOT NULL REFERENCES question_banks(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    options TEXT NOT NULL,
    answer INTEGER NOT NULL,
    difficulty TEXT NOT NULL DEFAULT 'Medium',
    position INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE exams (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    bank_id TEXT REFERENCES question_banks(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'Scheduled' CHECK (status IN ('Scheduled', 'Live', 'Completed')),
    start_time TEXT NOT NULL,
    duration INTEGER NOT NULL,
    pass_mark INTEGER NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL
  );
  CREATE TABLE exam_candidates (
    exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    PRIMARY KEY (exam_id, candidate_id)
  );
  CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    code_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Started', 'Submitted', 'Terminated', 'Revoked', 'Locked')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    emailed_at TEXT
  );
  CREATE INDEX invites_exam ON invites(exam_id, candidate_id);
  CREATE TABLE attempts (
    id TEXT PRIMARY KEY,
    invite_id TEXT NOT NULL UNIQUE REFERENCES invites(id) ON DELETE CASCADE,
    exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'InProgress' CHECK (status IN ('InProgress', 'Submitted', 'Terminated')),
    question_order TEXT NOT NULL,
    answers TEXT NOT NULL DEFAULT '{}',
    started_at TEXT NOT NULL,
    deadline TEXT NOT NULL,
    finished_at TEXT,
    terminated_reason TEXT
  );
  CREATE TABLE results (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    exam_id TEXT NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    correct INTEGER NOT NULL,
    total INTEGER NOT NULL,
    time_taken INTEGER NOT NULL,
    submitted_at TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('Pass', 'Fail')),
    UNIQUE (candidate_id, exam_id)
  );
  CREATE TABLE feedback (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    exam_id TEXT REFERENCES exams(id) ON DELETE SET NULL,
    rating INTEGER NOT NULL,
    message TEXT NOT NULL,
    sent_by TEXT NOT NULL,
    sent_at TEXT NOT NULL
  );
  CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT,
    type TEXT NOT NULL CHECK (type IN ('Normal', 'Warning', 'Validation')),
    event TEXT NOT NULL,
    exam_id TEXT,
    actor TEXT,
    ip TEXT,
    timestamp TEXT NOT NULL
  );
  CREATE INDEX audit_time ON audit_logs(timestamp DESC);
  CREATE INDEX audit_candidate ON audit_logs(candidate_id, timestamp DESC);
  CREATE TABLE recordings (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    exam_id TEXT,
    file_name TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    duration INTEGER NOT NULL DEFAULT 0,
    recorded_by TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  """,
]


# ---------------------------------------------------------------- query helpers
def run(sql: str, *params: Any) -> int:
    """Executes a write; returns the number of rows changed."""
    with _lock:
        return _conn.execute(sql, params).rowcount


def one(sql: str, *params: Any) -> dict | None:
    with _lock:
        return _conn.execute(sql, params).fetchone()


def all_(sql: str, *params: Any) -> list[dict]:
    with _lock:
        return _conn.execute(sql, params).fetchall()


_depth = 0


@contextmanager
def tx() -> Iterator[None]:
    """A transaction. Nested use becomes a savepoint, like better-sqlite3's db.transaction()."""
    global _depth
    with _lock:
        name = f"sp{_depth}"
        _conn.execute("BEGIN" if _depth == 0 else f"SAVEPOINT {name}")
        _depth += 1
        try:
            yield
        except BaseException:
            _depth -= 1
            if _depth == 0:
                _conn.execute("ROLLBACK")
            else:
                _conn.execute(f"ROLLBACK TO {name}")
                _conn.execute(f"RELEASE {name}")
            raise
        else:
            _depth -= 1
            _conn.execute("COMMIT" if _depth == 0 else f"RELEASE {name}")


def backup(path: str) -> None:
    with _lock:
        dest = sqlite3.connect(path)
        try:
            _conn.backup(dest)
        finally:
            dest.close()


def _migrate() -> None:
    _conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = one("SELECT version FROM schema_version")
    current = row["version"] if row else 0
    for v in range(current, len(MIGRATIONS)):
        with tx():
            for statement in MIGRATIONS[v].split(";"):
                if statement.strip():
                    _conn.execute(statement)
            if v == 0:
                run("INSERT INTO schema_version (version) VALUES (?)", 1)
            else:
                run("UPDATE schema_version SET version = ?", v + 1)


_migrate()

# ---------------------------------------------------------------------------
now = now_iso

ID_START = {"CND": 1001, "QB": 101, "Q": 1, "EX": 201, "RS": 3001, "FB": 4001, "INV": 1, "ATT": 1, "REC": 1, "USR": 1}


def next_id(prefix: str, start: int) -> str:
    """Human-readable sequential ids such as CND-1025 or EX-210."""
    with tx():
        row = one("SELECT value FROM counters WHERE name = ?", prefix)
        value = row["value"] + 1 if row else start
        run("INSERT INTO counters (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value", prefix, value)
    return f"{prefix}-{value}"


def new_id(prefix: str) -> str:
    return next_id(prefix, ID_START.get(prefix, 1))


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def random_token(nbytes: int = 32) -> str:
    """URL-safe random token (base64url, no padding)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).rstrip(b"=").decode()


def audit(*, event: Any, candidate_id: str | None = None, type: str = "Normal", exam_id: str | None = None,
          actor: str | None = None, ip: str | None = None) -> None:
    run(
        "INSERT INTO audit_logs (candidate_id, type, event, exam_id, actor, ip, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        candidate_id, type, str(event)[:300], exam_id, actor, ip, now(),
    )


DEFAULT_SETTINGS: dict[str, dict[str, Any]] = {
    "organization": {
        "name": "My Organization",
        "companyUrl": "",
        "logoUrl": "",
        "supportEmail": "",
        "timezone": "Asia/Kolkata",
    },
    "exam": {
        "defaultDuration": 60,
        "passMark": 60,
        "maxAttempts": 1,
        "shuffleQuestions": True,
        "shuffleOptions": True,
        "showResultsToCandidate": False,
        "negativeMarking": False,
    },
    "security": {
        "webcamRequired": True,
        "microphoneRequired": True,
        "screenRecording": True,
        "browserLockdown": True,
        "idVerification": True,
        "faceDetection": True,
        "maxWarningsBeforeFlag": 3,
        "autoSubmitOnFlag": False,
    },
    "notifications": {
        "emailOnExamScheduled": True,
        "emailOnResultPublished": True,
        "alertOnCheatingFlag": True,
        "dailySummary": False,
        "reminderHoursBefore": 24,
    },
}


def get_settings() -> dict[str, dict[str, Any]]:
    """The settings sections shown to staff. Other rows (e.g. the private `mail` section) are never included."""
    out = copy.deepcopy(DEFAULT_SETTINGS)
    for row in all_("SELECT section, value FROM settings"):
        if row["section"] not in DEFAULT_SETTINGS:
            continue
        try:
            value = json.loads(row["value"])
        except ValueError:
            continue  # ignore a corrupt row; defaults stay
        if isinstance(value, dict):
            out[row["section"]] = {**out.get(row["section"], {}), **value}
    return out


def save_settings(section: str, value: dict) -> None:
    run(
        "INSERT INTO settings (section, value) VALUES (?, ?) ON CONFLICT(section) DO UPDATE SET value = excluded.value",
        section, dumps(value),
    )
