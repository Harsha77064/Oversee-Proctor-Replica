"""Scheduled exams start by themselves at their start time; future ones stay closed."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import client


def _scheduled_exam(admin, name: str, starts_in: timedelta, duration: int = 30) -> tuple[str, str, str]:
    """A candidate invited to a *Scheduled* exam (nobody clicks Start Now). Returns (candidate, exam, Test ID)."""
    email = f"{name.lower().replace(' ', '.')}@example.com"
    cid = admin.post("/api/candidates", json={"name": name, "email": email}).json()["id"]
    start = (datetime.now(timezone.utc) + starts_in).isoformat()
    ex = admin.post("/api/exams", json={"title": f"Scheduled exam for {name}", "bankId": "QB-101",
                                        "startTime": start, "duration": duration, "passMark": 50}).json()["id"]
    admin.post(f"/api/candidates/{cid}/assign", json={"examId": ex})
    test_id = admin.post(f"/api/exams/{ex}/invites", json={"candidateIds": [cid]}).json()["invites"][0]["code"]
    return cid, ex, test_id


def _exam_status(admin, ex: str) -> str:
    return next(e for e in admin.get("/api/data", params={"only": "exams"}).json()["exams"] if e["id"] == ex)["status"]


def test_exam_starts_automatically_at_its_scheduled_time(base_url, admin):
    cid, ex, test_id = _scheduled_exam(admin, "Tara Ontime", timedelta(seconds=-5))  # start time just passed

    cand = client(base_url)
    assert cand.post("/api/candidate/signin", json={"testId": test_id}).status_code == 200
    me = cand.get("/api/candidate/me").json()
    assert me["exam"]["status"] == "Live", "the start time has passed, so the exam opened by itself"

    r = cand.post("/api/candidate/start")
    assert r.status_code == 200, r.text
    assert len(r.json()["attempt"]["questions"]) == 6

    assert _exam_status(admin, ex) == "Live"
    events = [l["event"] for l in admin.get("/api/data", params={"only": "auditLogs"}).json()["auditLogs"] if l["examId"] == ex]
    assert 'Exam "Scheduled exam for Tara Ontime" started automatically at its scheduled time' in events


def test_future_exam_stays_closed_until_its_time(base_url, admin):
    cid, ex, test_id = _scheduled_exam(admin, "Fiona Future", timedelta(hours=2))

    cand = client(base_url)
    assert cand.post("/api/candidate/signin", json={"testId": test_id}).status_code == 200
    assert cand.get("/api/candidate/me").json()["exam"]["status"] == "Scheduled"
    r = cand.post("/api/candidate/start")
    assert r.status_code == 409 and "not started yet" in r.json()["error"]
    assert _exam_status(admin, ex) == "Scheduled"


def test_exam_that_is_already_over_cannot_be_entered(base_url, admin):
    # 5-minute exam that started 6 minutes ago and was never opened by anyone.
    cid, ex, test_id = _scheduled_exam(admin, "Lena Late", timedelta(minutes=-6), duration=5)
    r = client(base_url).post("/api/candidate/signin", json={"testId": test_id})
    assert r.status_code == 409 and "already ended" in r.json()["error"], r.text
    assert _exam_status(admin, ex) == "Completed"


def test_exam_ends_by_itself_when_time_runs_out(base_url, admin):
    import time

    # A 5-minute exam with only ~4 seconds of its time left.
    email = "max.midexam@example.com"
    cid = admin.post("/api/candidates", json={"name": "Max Midexam", "email": email}).json()["id"]
    start = (datetime.now(timezone.utc) - timedelta(minutes=5) + timedelta(seconds=4)).isoformat()
    ex = admin.post("/api/exams", json={"title": "Almost over", "bankId": "QB-101", "startTime": start, "duration": 5, "passMark": 50}).json()["id"]
    admin.post(f"/api/candidates/{cid}/assign", json={"examId": ex})
    test_id = admin.post(f"/api/exams/{ex}/invites", json={"candidateIds": [cid]}).json()["invites"][0]["code"]

    cand = client(base_url)
    assert cand.post("/api/candidate/signin", json={"testId": test_id}).status_code == 200
    r = cand.post("/api/candidate/start")
    assert r.status_code == 200, r.text
    attempt = r.json()["attempt"]
    assert attempt["secondsLeft"] <= 5, "a late starter's timer stops at the exam's end, not after a full 5 minutes"
    q = attempt["questions"][0]
    assert cand.put("/api/candidate/answers", json={"questionId": q["id"], "value": q["options"][0]["value"]}).status_code == 200

    time.sleep(6)  # exam end (+1 s grace in tests) passes
    me = cand.get("/api/candidate/me").json()
    assert me["exam"]["status"] == "Completed" and me["attempt"]["status"] == "Submitted"
    assert _exam_status(admin, ex) == "Completed"

    results = admin.get("/api/data", params={"only": "results"}).json()["results"]
    res = next(x for x in results if x["candidateId"] == cid and x["examId"] == ex)
    assert res["total"] == 6, "the saved answer was scored automatically"
    events = [l["event"] for l in admin.get("/api/data", params={"only": "auditLogs"}).json()["auditLogs"] if l["examId"] == ex]
    assert 'Exam "Almost over" ended automatically when its time ran out' in events
    assert any("auto-submitted (exam time ended)" in e for e in events)


def test_face_detection_setting_reaches_the_candidate_page(base_url, admin):
    cid, ex, test_id = _scheduled_exam(admin, "Gina Gaze", timedelta(seconds=-5))
    cand = client(base_url)
    assert cand.post("/api/candidate/signin", json={"testId": test_id}).status_code == 200
    assert cand.get("/api/candidate/me").json()["rules"]["faceDetection"] is True, "on by default"

    assert admin.put("/api/settings/security", json={"faceDetection": False}).status_code == 200
    assert cand.get("/api/candidate/me").json()["rules"]["faceDetection"] is False
    assert admin.put("/api/settings/security", json={"faceDetection": True}).status_code == 200


def test_security_policy_allows_the_face_detector(base_url):
    csp = client(base_url).get("/api/health").headers["content-security-policy"]
    assert "script-src 'self' 'wasm-unsafe-eval'" in csp, "WebAssembly may run, but only our own scripts"
