"""Runtime configuration, read from environment variables (see .env.example)."""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    """Minimal .env loader so local runs pick up a .env file. Real env vars win."""
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("#"):
            continue
        m = re.match(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$", line)
        if not m:
            continue
        value = re.sub(r"^(['\"])(.*)\1$", r"\2", m.group(2))
        os.environ.setdefault(m.group(1), value)


_load_dotenv()
env = os.environ


def _list(v: str | None) -> list[str]:
    return [s.strip() for s in (v or "").split(",") if s.strip()]


def _int(name: str, default: int) -> int:
    try:
        return int(float(env.get(name, "") or 0)) or default
    except ValueError:
        return default


# APP_ENV=production (NODE_ENV is still honoured for older .env files).
production = (env.get("APP_ENV") or env.get("NODE_ENV") or "") == "production"


@dataclass(frozen=True)
class Smtp:
    host: str = env.get("SMTP_HOST", "")
    port: int = _int("SMTP_PORT", 587)
    secure: bool = env.get("SMTP_SECURE") == "1"
    user: str = env.get("SMTP_USER", "")
    password: str = env.get("SMTP_PASS", "")
    sender: str = env.get("SMTP_FROM", "")


@dataclass(frozen=True)
class Ice:
    stun: list[str] = field(default_factory=lambda: _list(env.get("STUN_URLS") or "stun:stun.l.google.com:19302"))
    turn: list[str] = field(default_factory=lambda: _list(env.get("TURN_URLS")))
    # Either a coturn "static-auth-secret" (preferred: short-lived credentials)...
    turn_secret: str = env.get("TURN_SECRET", "")
    # ...or a fixed username/password.
    turn_username: str = env.get("TURN_USERNAME", "")
    turn_credential: str = env.get("TURN_CREDENTIAL", "")


@dataclass(frozen=True)
class Config:
    root: Path = ROOT
    production: bool = production
    port: int = _int("PORT", 3000 if production else 3001)
    host: str = env.get("HOST") or "0.0.0.0"
    data_dir: Path = (ROOT / (env.get("DATA_DIR") or "data")).resolve()
    dist_dir: Path = ROOT / "dist"
    # Public URL used in invitation links, e.g. https://exams.example.com
    public_url: str = (env.get("PUBLIC_URL") or "").rstrip("/")
    cookie_secure: bool = env["COOKIE_SECURE"] == "1" if env.get("COOKIE_SECURE") else production
    trust_proxy: bool = env["TRUST_PROXY"] == "1" if env.get("TRUST_PROXY") else production
    staff_session_hours: float = _int("SESSION_HOURS", 12)
    invite_valid_days: float = _int("INVITE_VALID_DAYS", 14)
    max_recording_mb: int = _int("MAX_RECORDING_MB", 1024)
    smtp: Smtp = field(default_factory=Smtp)
    ice: Ice = field(default_factory=Ice)


config = Config()

if config.production and re.search("change-me", config.ice.turn_secret, re.I):
    print("TURN_SECRET is still the example value. Set a long random secret in .env (openssl rand -hex 32).", file=sys.stderr)
    sys.exit(1)

(config.data_dir / "recordings").mkdir(parents=True, exist_ok=True)
