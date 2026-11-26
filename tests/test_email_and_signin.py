"""Email settings (test outbox + real SMTP via a fake mail server) and candidate sign-in with just a Test ID."""
from __future__ import annotations

import base64
import socketserver
import threading
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from conftest import client


# ---------------------------------------------------------------- a tiny fake SMTP server
class FakeSmtp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, user: str, password: str):
        super().__init__(("127.0.0.1", 0), _SmtpHandler)
        self.user, self.password, self.messages = user, password, []


class _SmtpHandler(socketserver.StreamRequestHandler):
    def send(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self) -> None:
        self.send("220 fake.smtp ready")
        authed = False
        mail = {}
        while line := self.rfile.readline().decode(errors="replace").rstrip("\r\n"):
            cmd = line.split(" ", 1)[0].upper()
            if cmd in ("EHLO", "HELO"):
                self.send("250-fake.smtp")  # note: no STARTTLS offered
                self.send("250 AUTH PLAIN")
            elif cmd == "AUTH":
                _, user, pw = base64.b64decode(line.split()[2]).decode().split("\0")
                authed = (user, pw) == (self.server.user, self.server.password)
                self.send("235 ok" if authed else "535 5.7.8 bad credentials")
            elif cmd == "MAIL":
                mail = {"from": line, "rcpt": []}
                self.send("250 ok" if authed else "530 auth required")
            elif cmd == "RCPT":
                mail["rcpt"].append(line)
                self.send("250 ok")
            elif cmd == "DATA":
                self.send("354 go")
                data = []
                while (l := self.rfile.readline().decode(errors="replace")) not in (".\r\n", ""):
                    data.append(l)
                mail["data"] = "".join(data)
                self.server.messages.append(mail)
                self.send("250 queued")
            elif cmd == "QUIT":
                self.send("221 bye")
                return
            else:
                self.send("250 ok")


@pytest.fixture(scope="module")
def smtp():
    server = FakeSmtp("mailer@example.com", "app-password-123")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


# ---------------------------------------------------------------- email settings
def test_mail_settings_are_admin_only_and_never_leak_the_password(base_url, admin, smtp):
    r = admin.get("/api/mail-settings")
    assert r.status_code == 200 and r.json()["mail"]["mode"] in ("off", "test", "smtp")

    r = admin.put("/api/mail-settings", json={"mode": "smtp", "host": "127.0.0.1", "port": smtp.server_address[1], "security": "none",
                                              "user": "mailer@example.com", "password": "app-password-123", "from": "Exams <exams@example.com>"})
    assert r.status_code == 200, r.text
    mail = r.json()["mail"]
    assert mail["passwordSet"] is True and "password" not in mail and "app-password-123" not in r.text

    assert "mail" not in admin.get("/api/data", params={"only": "settings"}).json()["settings"], "mail settings not in general settings"
    assert "app-password-123" not in admin.get("/api/data").text
    anon = client(base_url)
    assert anon.get("/api/mail-settings").status_code == 401
    assert anon.post("/api/mail-settings/test", json={}).status_code == 401


def test_mail_settings_validation(admin):
    assert admin.put("/api/mail-settings", json={"mode": "smtp", "host": "", "from": "a@example.com"}).status_code == 400
    r = admin.put("/api/mail-settings", json={"mode": "smtp", "host": "https://smtp.gmail.com", "from": "a@example.com"})
    assert r.status_code == 400 and "smtp.gmail.com" in r.json()["error"]
    r = admin.put("/api/mail-settings", json={"mode": "smtp", "host": "smtp.gmail.com", "from": "not an email"})
    assert r.status_code == 400 and "From address" in r.json()["error"]
    assert admin.put("/api/mail-settings", json={"mode": "carrier-pigeon"}).status_code == 400


def test_real_smtp_sending_and_clear_errors(admin, smtp):
    port = smtp.server_address[1]
    base = {"mode": "smtp", "host": "127.0.0.1", "port": port, "security": "none", "user": "mailer@example.com", "from": "Exams <exams@example.com>"}
    assert admin.put("/api/mail-settings", json=base).status_code == 200  # password kept from before

    r = admin.post("/api/mail-settings/test", json={"to": "someone@example.com"})
    assert r.status_code == 200 and r.json()["mode"] == "smtp", r.text
    assert "Subject: Oversee test email" in smtp.messages[-1]["data"]
    assert "someone@example.com" in smtp.messages[-1]["rcpt"][0]

    admin.put("/api/mail-settings", json={**base, "password": "wrong-password"})
    r = admin.post("/api/mail-settings/test", json={"to": "someone@example.com"})
    assert r.status_code == 400 and "App Password" in r.json()["error"], r.text

    admin.put("/api/mail-settings", json={**base, "password": "app-password-123", "security": "starttls"})
    r = admin.post("/api/mail-settings/test", json={"to": "someone@example.com"})
    assert r.status_code == 400 and "STARTTLS" in r.json()["error"], r.text

    admin.put("/api/mail-settings", json={**base, "port": 1, "security": "none"})
    r = admin.post("/api/mail-settings/test", json={"to": "someone@example.com"})
    assert r.status_code == 400 and "Could not connect" in r.json()["error"], r.text


def _candidate_with_live_exam(admin, name: str) -> tuple[str, str]:
    email = f"{name.lower().replace(' ', '.')}@example.com"
    cid = admin.post("/api/candidates", json={"name": name, "email": email}).json()["id"]
    ex = admin.post("/api/exams", json={"title": f"Exam for {name}", "bankId": "QB-101",
                                        "startTime": datetime.now(timezone.utc).isoformat(), "duration": 30, "passMark": 50}).json()["id"]
    admin.post(f"/api/candidates/{cid}/assign", json={"examId": ex})
    admin.patch(f"/api/exams/{ex}", json={"status": "Live"})
    return cid, ex


def test_invitation_emails_in_test_mode(admin):
    assert admin.put("/api/mail-settings", json={"mode": "test"}).status_code == 200
    admin.delete("/api/outbox")
    cid, ex = _candidate_with_live_exam(admin, "Olive Outbox")
    assert admin.get(f"/api/exams/{ex}/invites").json()["emailMode"] == "test"

    r = admin.post(f"/api/exams/{ex}/invites", json={"candidateIds": [cid], "sendEmail": True})
    assert r.status_code == 201, r.text
    inv = r.json()["invites"][0]
    assert inv["emailed"] is True and r.json()["emailMode"] == "test"

    emails = admin.get("/api/outbox").json()["emails"]
    assert len(emails) == 1
    e = emails[0]
    assert e["to"] == "olive.outbox@example.com" and e["subject"] == "Your exam invitation: Exam for Olive Outbox"
    assert f"Your Test ID: {inv['code']}" in e["text"] and inv["link"] in e["text"] and "/exam and enter your Test ID" in e["text"]
    status = next(i for i in admin.get(f"/api/exams/{ex}/invites").json()["invites"] if i["candidateId"] == cid)
    assert status["emailedAt"], "invite marked as emailed"
    assert admin.delete("/api/outbox").json()["deleted"] == 1


def test_email_off_hides_sending(admin):
    assert admin.put("/api/mail-settings", json={"mode": "off"}).status_code == 200
    cid, ex = _candidate_with_live_exam(admin, "Fred Offline")
    r = admin.post(f"/api/exams/{ex}/invites", json={"candidateIds": [cid], "sendEmail": True})
    assert r.status_code == 400 and "Settings" in r.json()["error"]
    assert admin.post("/api/mail-settings/test", json={}).status_code == 400


# ---------------------------------------------------------------- candidate sign-in with email + code
def test_candidate_signin_with_test_id_only(base_url, admin):
    portal = client(base_url).get("/api/candidate/portal").json()
    assert portal["organization"]["name"] == "Test Org"

    cid, ex = _candidate_with_live_exam(admin, "Sam Signin")
    inv = admin.post(f"/api/exams/{ex}/invites", json={"candidateIds": [cid]}).json()["invites"][0]
    cand = client(base_url)

    r = cand.post("/api/candidate/signin", json={"testId": "AAAA-AAAA"})
    assert r.status_code == 401 and "Test ID is not valid" in r.json()["error"]
    assert cand.post("/api/candidate/signin", json={"testId": ""}).status_code == 400
    assert cand.get("/api/candidate/me").status_code == 401

    # Wrong guesses never lock anyone's invitation.
    status = next(i for i in admin.get(f"/api/exams/{ex}/invites").json()["invites"] if i["candidateId"] == cid)["status"]
    assert status == "Pending"

    # Just the Test ID (any case, with or without the dash) signs the right candidate into the right exam.
    r = cand.post("/api/candidate/signin", json={"testId": inv["code"].lower().replace("-", " ")})
    assert r.status_code == 200, r.text
    me = cand.get("/api/candidate/me").json()
    assert me["candidate"]["id"] == cid and me["exam"]["title"] == "Exam for Sam Signin"
    assert cand.get("/api/data").status_code == 401, "candidate still cannot see staff data"

    # The invitation link still works too, and signing in elsewhere ends the first session (one device per invite).
    token = parse_qs(urlsplit(inv["link"]).query)["t"][0]
    other = client(base_url)
    assert other.post("/api/candidate/login", json={"token": token, "code": inv["code"]}).status_code == 200
    assert cand.get("/api/candidate/me").status_code == 401

    logs = admin.get("/api/data", params={"only": "auditLogs"}).json()["auditLogs"]
    assert "Signed in with Test ID" in [l["event"] for l in logs if l["candidateId"] == cid]
    assert any(l["event"] == "Invalid Test ID entered on the candidate sign-in page" for l in logs)


def test_each_test_id_is_unique(admin):
    cid, ex = _candidate_with_live_exam(admin, "Uma Unique")
    codes = {admin.post(f"/api/exams/{ex}/invites", json={"candidateIds": [cid]}).json()["invites"][0]["code"] for _ in range(5)}
    assert len(codes) == 5, "every new invitation gets a different Test ID"
