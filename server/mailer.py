"""Outgoing email (exam invitations, test emails).

Three modes:
  off   - no email; admins copy invitation links by hand
  test  - nothing is sent: each email is saved to DATA_DIR/outbox and shown in
          Settings -> Email, so the whole flow can be tried without a mail account
  smtp  - real email through any SMTP server (Gmail, Outlook, company mail, ...)

Settings come from Settings -> Email in the app (stored in the database), unless
SMTP_HOST and SMTP_FROM are set in the environment / .env, which then take priority.
The SMTP password is never sent to the browser.
"""
from __future__ import annotations

import asyncio
import html
import json
import secrets
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import format_datetime, parseaddr

from . import db
from .config import config
from .jsutil import js_string, now_iso, parse_date

OUTBOX = config.data_dir / "outbox"
OUTBOX_KEEP = 200
MAIL_SECTION = "mail"  # settings row; deliberately not part of db.DEFAULT_SETTINGS (holds a password)
MODES = ("off", "test", "smtp")
SECURITY = ("starttls", "ssl", "none")
DEFAULT_MAIL = {"mode": "off", "host": "", "port": 587, "security": "starttls", "user": "", "password": "", "from": ""}


class MailError(Exception):
    """A sending problem, with a message an admin can act on."""


# ---------------------------------------------------------------- configuration
def env_configured() -> bool:
    return bool(config.smtp.host and config.smtp.sender)


def mail_config() -> dict:
    """The settings in effect, including the password. Never return this to a browser."""
    if env_configured():
        s = config.smtp
        return {"mode": "smtp", "host": s.host, "port": s.port, "security": "ssl" if s.secure else "starttls",
                "user": s.user, "password": s.password, "from": s.sender, "source": "env"}
    row = db.one("SELECT value FROM settings WHERE section = ?", MAIL_SECTION)
    stored = {}
    if row:
        try:
            stored = json.loads(row["value"]) or {}
        except ValueError:
            stored = {}
    return {**DEFAULT_MAIL, **{k: v for k, v in stored.items() if k in DEFAULT_MAIL}, "source": "app"}


def public_mail_config() -> dict:
    """Settings for the admin screen: everything except the password itself."""
    c = mail_config()
    return {"mode": c["mode"], "host": c["host"], "port": c["port"], "security": c["security"], "user": c["user"],
            "from": c["from"], "passwordSet": bool(c["password"]), "source": c["source"]}


def save_mail_config(values: dict) -> None:
    db.save_settings(MAIL_SECTION, {k: values[k] for k in DEFAULT_MAIL})


def email_mode() -> str:
    c = mail_config()
    if c["mode"] == "smtp" and not (c["host"] and c["from"]):
        return "off"
    return c["mode"] if c["mode"] in MODES else "off"


def email_enabled() -> bool:
    return email_mode() != "off"


# ---------------------------------------------------------------- sending
def _send_smtp(c: dict, msg: EmailMessage) -> None:
    context = ssl.create_default_context()
    host, port = c["host"], int(c["port"])
    try:
        if c["security"] == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(host, port, context=context, timeout=20)
        else:
            client = smtplib.SMTP(host, port, timeout=20)
        with client:
            client.ehlo()
            if c["security"] == "starttls":
                if not client.has_extn("starttls"):
                    raise MailError(f"{host} does not offer a secure connection (STARTTLS) on port {port}. "
                                    "Try security \"SSL\" with port 465.")
                client.starttls(context=context)
                client.ehlo()
            if c["user"]:
                client.login(c["user"], c["password"])
            client.send_message(msg)
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise MailError("The mail server rejected the username or password. For Gmail or Outlook with two-step "
                        "verification, create an App Password and use that instead of your normal password.") from None
    except smtplib.SMTPRecipientsRefused:
        raise MailError("The mail server refused the recipient address.") from None
    except smtplib.SMTPSenderRefused:
        raise MailError("The mail server refused the From address. Use an address your account is allowed to send from.") from None
    except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as err:
        raise MailError(_connect_problem(host, port, err)) from None
    except smtplib.SMTPException as err:  # must come before OSError: SMTP errors are OSErrors too
        raise MailError(f"The mail server reported a problem: {str(err)[:200]}") from None
    except ssl.SSLError:
        raise MailError("The secure connection failed. Check that the port matches the security setting "
                        "(587 = STARTTLS, 465 = SSL).") from None
    except OSError as err:  # DNS failure, connection refused, timeout, ...
        raise MailError(_connect_problem(host, port, err)) from None


def _connect_problem(host: str, port: int, err: Exception) -> str:
    return (f"Could not connect to {host}:{port} ({type(err).__name__}). Check the server name, port and "
            "security setting, and that your network allows outgoing mail.")


def _save_to_outbox(msg: EmailMessage, text: str, html_body: str) -> str:
    OUTBOX.mkdir(parents=True, exist_ok=True)
    email_id = f"{now_iso().replace(':', '').replace('.', '')}-{secrets.token_hex(3)}"
    (OUTBOX / f"{email_id}.json").write_text(json.dumps({
        "id": email_id, "at": now_iso(), "from": msg["From"], "to": msg["To"], "subject": msg["Subject"],
        "text": text, "html": html_body,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    for old in sorted(OUTBOX.glob("*.json"), reverse=True)[OUTBOX_KEEP:]:
        old.unlink(missing_ok=True)
    return email_id


async def send_email(*, to: str, subject: str, text: str, html_body: str) -> str:
    """Sends (or, in test mode, saves) one email. Returns the mode used. Raises MailError."""
    c = mail_config()
    mode = email_mode()
    if mode == "off":
        raise MailError("Email is not set up. Go to Settings → Email.")
    msg = EmailMessage()
    msg["From"] = c["from"] or "Oversee <no-reply@oversee.local>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    if mode == "test":
        _save_to_outbox(msg, text, html_body)
    else:
        await asyncio.to_thread(_send_smtp, c, msg)
    return mode


def list_outbox(limit: int = 50) -> list[dict]:
    if not OUTBOX.exists():
        return []
    out = []
    for f in sorted(OUTBOX.glob("*.json"), reverse=True)[:limit]:
        try:
            e = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({k: e.get(k) for k in ("id", "at", "from", "to", "subject", "text")})
    return out


def clear_outbox() -> int:
    if not OUTBOX.exists():
        return 0
    files = list(OUTBOX.glob("*.json"))
    for f in files:
        f.unlink(missing_ok=True)
    return len(files)


def valid_from(value: str) -> bool:
    name, addr = parseaddr(value)
    return bool(addr) and "@" in addr and "." in addr.split("@")[-1] and " " not in addr


# ---------------------------------------------------------------- messages
def _esc(s) -> str:
    return html.escape("" if s is None else js_string(s), quote=True).replace("&#x27;", "&#39;")


async def send_invite_email(*, to: str, name: str, exam_title: str, start_time: str, duration: int, link: str,
                            code: str, org_name: str, support_email: str, signin_url: str) -> str:
    start = parse_date(start_time)
    when = format_datetime(start, usegmt=True) if start else "Invalid Date"
    text = "\n".join([
        f"Hello {name},",
        "",
        f'You have been invited to take "{exam_title}" with {org_name}.',
        f"Scheduled: {when} · Duration: {duration} minutes",
        "",
        f"Exam link: {link}",
        f"Access code: {code}",
        "",
        f"No link? Go to {signin_url} and sign in with this email address ({to}) and your access code.",
        "",
        "The exam is live proctored: you will need a working webcam and microphone, and you must stay in full screen.",
        "Keep this code private. It can only be used by you.",
        f"Questions? Contact {support_email}." if support_email else "",
    ])
    support = f'<p style="color:#4b5563;font-size:13px">Questions? Contact {_esc(support_email)}.</p>' if support_email else ""
    body = f"""
  <div style="font-family:Arial,sans-serif;max-width:560px;color:#111827">
    <p>Hello {_esc(name)},</p>
    <p>You have been invited to take <b>{_esc(exam_title)}</b> with {_esc(org_name)}.</p>
    <p style="color:#4b5563">Scheduled: {_esc(when)} · Duration: {_esc(duration)} minutes</p>
    <p><a href="{_esc(link)}" style="display:inline-block;background:#5b5bf0;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold">Open your exam</a></p>
    <p>Access code: <b style="font-size:20px;letter-spacing:3px">{_esc(code)}</b></p>
    <p style="color:#4b5563;font-size:13px">No link? Go to <a href="{_esc(signin_url)}">{_esc(signin_url)}</a> and sign in with this email address and your access code.</p>
    <p style="color:#4b5563;font-size:13px">This exam is live proctored. You will need a working webcam and microphone and must stay in full screen. Keep this code private.</p>
    {support}
  </div>"""
    return await send_email(to=to, subject=f"Your exam invitation: {exam_title}", text=text, html_body=body)


async def send_test_email(*, to: str, org_name: str) -> str:
    text = (f"This is a test email from Oversee ({org_name}).\n\n"
            "If you can read this, exam invitations will be delivered the same way.")
    body = (f'<div style="font-family:Arial,sans-serif;color:#111827"><p>This is a test email from <b>Oversee</b> '
            f'({_esc(org_name)}).</p><p>If you can read this, exam invitations will be delivered the same way.</p></div>')
    return await send_email(to=to, subject="Oversee test email", text=text, html_body=body)
