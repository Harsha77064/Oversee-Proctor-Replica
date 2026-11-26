"""API checks: auth, roles, invites, candidate exam flow, server-side scoring, recordings.

The tests run in order and share state (one exam, one candidate) through `state`.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from conftest import ADMIN, client

state: dict = {}


@pytest.fixture(scope="module")
def proctor(base_url):
    c = client(base_url)
    yield c
    c.close()


@pytest.fixture(scope="module")
def cand(base_url):
    c = client(base_url)
    yield c
    c.close()


def test_staff_auth_and_roles(base_url, admin, proctor):
    anon = client(base_url)
    assert anon.post("/api/auth/login", json={"email": ADMIN["email"], "password": "wrong-password1"}).status_code == 401, "wrong password rejected"
    r = client(base_url).post("/api/auth/login", json=ADMIN)
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin", "admin login"

    r = admin.post("/api/users", json={"name": "Pat Proctor", "email": "proctor@example.com", "role": "proctor", "password": "weak"})
    assert r.status_code == 400, "weak password rejected"
    r = admin.post("/api/users", json={"name": "Pat Proctor", "email": "proctor@example.com", "role": "proctor", "password": "Pr0ctorPassw0rd"})
    assert r.status_code == 201, "create proctor"
    assert proctor.post("/api/auth/login", json={"email": "proctor@example.com", "password": "Pr0ctorPassw0rd"}).status_code == 200

    r = proctor.get("/api/data", params={"only": "questionBanks"})
    assert r.status_code == 200 and "answer" not in r.json()["questionBanks"][0]["questions"][0], "proctor cannot see answer keys"
    assert proctor.post("/api/candidates", json={"name": "X", "email": "x@example.com"}).status_code == 403
    assert proctor.get("/api/users").status_code == 403
    assert anon.get("/api/recordings").status_code == 401
    anon.close()


def test_exam_invite_and_candidate_login(admin, cand):
    r = admin.post("/api/candidates", json={"name": "Test Candidate", "email": "test.candidate@example.com", "department": "QA"})
    assert r.status_code == 201
    cid = state["cid"] = r.json()["id"]
    r = admin.post("/api/exams", json={"title": "API Test Exam", "bankId": "QB-101",
                                       "startTime": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(), "duration": 30, "passMark": 50})
    assert r.status_code == 201
    ex_id = state["exId"] = r.json()["id"]
    assert admin.post(f"/api/candidates/{cid}/assign", json={"examId": ex_id}).status_code == 200

    r = admin.post(f"/api/exams/{ex_id}/invites", json={"candidateIds": [cid]})
    assert r.status_code == 201, r.text
    inv = state["inv"] = r.json()["invites"][0]
    assert inv["link"] and len(inv["code"]) == 9 and inv["code"][4] == "-", "invite with link + code"
    token = state["token"] = parse_qs(urlsplit(inv["link"]).query)["t"][0]

    assert cand.post("/api/candidate/lookup", json={"token": "x" * 30}).status_code == 404, "bad token rejected"
    r = cand.post("/api/candidate/lookup", json={"token": token})
    assert r.status_code == 200 and r.json()["exam"]["title"] == "API Test Exam"
    r = cand.post("/api/candidate/login", json={"token": token, "code": "AAAA-AAAA"})
    assert r.status_code == 401 and "tries left" in r.json()["error"]
    r = cand.post("/api/candidate/login", json={"token": token, "code": inv["code"].lower().replace("-", " ")})
    assert r.status_code == 200, "right code (case/spacing tolerant) signs in"
    assert cand.get("/api/data").status_code == 401, "candidate cannot read staff data"
    assert cand.post("/api/candidate/start").status_code == 409, "cannot start before exam is live"


def test_exam_flow_and_server_scoring(admin, cand, base_url):
    cid, ex_id = state["cid"], state["exId"]
    admin.patch(f"/api/exams/{ex_id}", json={"status": "Live"})
    r = cand.post("/api/candidate/start")
    qs = r.json()["attempt"]["questions"]
    assert r.status_code == 200 and len(qs) == 6 and '"answer"' not in r.text, "questions without answer keys"
    assert 1700 < r.json()["attempt"]["secondsLeft"] <= 1800, "timer is server-controlled"

    banks = admin.get("/api/data", params={"only": "questionBanks"}).json()["questionBanks"]
    keys = {q["id"]: q["answer"] for q in next(b for b in banks if b["id"] == "QB-101")["questions"]}
    for q in qs[:4]:
        cand.put("/api/candidate/answers", json={"questionId": q["id"], "value": keys[q["id"]]})
    for q in qs[4:]:
        wrong = next(o["value"] for o in q["options"] if o["value"] != keys[q["id"]])
        cand.put("/api/candidate/answers", json={"questionId": q["id"], "value": wrong})
    assert cand.put("/api/candidate/answers", json={"questionId": "Q-999", "value": 0}).status_code == 400
    assert len(cand.get("/api/candidate/me").json()["attempt"]["answers"]) == 6, "answers saved on server (resume works)"

    r = cand.post("/api/candidate/submit")
    assert r.status_code == 200 and r.json()["attempt"]["status"] == "Submitted"
    results = admin.get("/api/data", params={"only": "results"}).json()["results"]
    res = next(x for x in results if x["candidateId"] == cid and x["examId"] == ex_id)
    assert (res["correct"], res["total"], res["score"], res["result"]) == (4, 6, 67, "Pass"), "server scored 4/6 = 67% Pass"
    assert cand.put("/api/candidate/answers", json={"questionId": qs[0]["id"], "value": 0}).status_code == 409
    assert client(base_url).post("/api/candidate/login", json={"token": state["token"], "code": state["inv"]["code"]}).status_code == 409


def test_recordings(base_url, admin, proctor):
    cid, ex_id = state["cid"], state["exId"]
    data = bytes([7]) * 2048
    r = proctor.post(f"/api/recordings?candidateId={cid}&examId={ex_id}&duration=3", content=data, headers={"content-type": "video/webm"})
    assert r.status_code == 201, r.text
    rec_id = r.json()["recording"]["id"]
    f = proctor.get(f"/api/recordings/{rec_id}/file")
    assert f.status_code == 200 and len(f.content) == 2048
    assert client(base_url).get(f"/api/recordings/{rec_id}/file").status_code == 401
    assert proctor.post(f"/api/recordings?candidateId={cid}", content=data, headers={"content-type": "text/html"}).status_code == 400
    assert proctor.delete(f"/api/recordings/{rec_id}").status_code == 403, "proctor cannot delete recordings"
    r = admin.get("/api/ice")
    assert r.status_code == 200 and isinstance(r.json()["iceServers"], list)


def test_admin_protection_and_deactivation(admin, proctor):
    users = admin.get("/api/users").json()["users"]
    admin_id = next(u["id"] for u in users if u["role"] == "admin")
    assert admin.patch(f"/api/users/{admin_id}", json={"active": False}).status_code == 400, "cannot deactivate the last admin"
    proc_id = next(u["id"] for u in users if u["role"] == "proctor")
    admin.patch(f"/api/users/{proc_id}", json={"active": False})
    assert proctor.get("/api/data", params={"only": "settings"}).status_code == 401, "deactivated proctor is signed out"


def test_security_headers_and_errors(base_url, admin):
    r = client(base_url).get("/api/health")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    r = admin.post("/api/candidates", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 400 and r.json()["error"] == "Request body is not valid JSON."
    assert admin.get("/api/nope").json() == {"error": "Not found."}
    assert admin.delete("/api/health").status_code == 404, "wrong method is a JSON 404, as before"
