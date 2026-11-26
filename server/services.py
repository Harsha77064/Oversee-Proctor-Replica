"""Domain logic shared by the HTTP API and the signaling server."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Callable

from . import db
from .jsutil import date_ms, dumps, iso, js_round, loads, now_ms


def _ids_in(ids: list[str]) -> str:
    return ",".join("?" for _ in ids) or "''"


# ---------------------------------------------------------------- serializers
def list_candidates(is_online: Callable[[str], bool] = lambda _id: False) -> list[dict]:
    assigned: dict[str, list[str]] = {}
    for r in db.all_("SELECT exam_id, candidate_id FROM exam_candidates"):
        assigned.setdefault(r["candidate_id"], []).append(r["exam_id"])
    return [
        {
            "id": c["id"],
            "name": c["name"],
            "email": c["email"],
            "department": c["department"],
            "status": c["status"],
            "online": is_online(c["id"]),
            "warnings": c["warnings"],
            "cheatingFlags": c["cheating_flags"],
            "assignedExams": assigned.get(c["id"], []),
            "lastActive": c["last_active"] or c["created_at"],
        }
        for c in db.all_("SELECT * FROM candidates ORDER BY id")
    ]


def list_banks(*, include_answers: bool) -> list[dict]:
    qs: dict[str, list[dict]] = {}
    for q in db.all_("SELECT * FROM questions ORDER BY position, id"):
        item = {"id": q["id"], "text": q["text"], "options": loads(q["options"], [])}
        if include_answers:
            item["answer"] = q["answer"]
        item["difficulty"] = q["difficulty"]
        qs.setdefault(q["bank_id"], []).append(item)
    return [
        {
            "id": b["id"],
            "name": b["name"],
            "topic": b["topic"],
            "description": b["description"],
            "createdAt": b["created_at"],
            "questions": qs.get(b["id"], []),
        }
        for b in db.all_("SELECT * FROM question_banks ORDER BY created_at DESC")
    ]


def list_exams() -> list[dict]:
    members: dict[str, list[str]] = {}
    for r in db.all_("SELECT exam_id, candidate_id FROM exam_candidates ORDER BY candidate_id"):
        members.setdefault(r["exam_id"], []).append(r["candidate_id"])
    return [
        {
            "id": e["id"],
            "title": e["title"],
            "bankId": e["bank_id"],
            "status": e["status"],
            "startTime": e["start_time"],
            "duration": e["duration"],
            "passMark": e["pass_mark"],
            "candidates": members.get(e["id"], []),
        }
        for e in db.all_("SELECT * FROM exams ORDER BY start_time")
    ]


def list_results() -> list[dict]:
    return [
        {
            "id": r["id"],
            "candidateId": r["candidate_id"],
            "examId": r["exam_id"],
            "score": r["score"],
            "correct": r["correct"],
            "total": r["total"],
            "timeTaken": r["time_taken"],
            "submittedAt": r["submitted_at"],
            "result": r["result"],
        }
        for r in db.all_("SELECT * FROM results ORDER BY submitted_at DESC")
    ]


def list_feedback() -> list[dict]:
    return [
        {
            "id": f["id"],
            "candidateId": f["candidate_id"],
            "examId": f["exam_id"],
            "rating": f["rating"],
            "message": f["message"],
            "sentBy": f["sent_by"],
            "sentAt": f["sent_at"],
        }
        for f in db.all_("SELECT * FROM feedback ORDER BY sent_at DESC")
    ]


def list_audit(limit: int = 1000) -> list[dict]:
    return [
        {
            "id": f"LOG-{l['id']}",
            "candidateId": l["candidate_id"],
            "type": l["type"],
            "event": l["event"],
            "examId": l["exam_id"],
            "actor": l["actor"],
            "ip": l["ip"] or "",
            "timestamp": l["timestamp"],
        }
        for l in db.all_("SELECT * FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT ?", limit)
    ]


def list_recordings() -> list[dict]:
    rows = db.all_(
        "SELECT r.*, c.name AS candidate_name, e.title AS exam_title FROM recordings r "
        "LEFT JOIN candidates c ON c.id = r.candidate_id LEFT JOIN exams e ON e.id = r.exam_id ORDER BY r.created_at DESC"
    )
    return [
        {
            "id": r["id"],
            "candidateId": r["candidate_id"],
            "name": r["candidate_name"] or r["candidate_id"],
            "examId": r["exam_id"],
            "examTitle": r["exam_title"] or "",
            "mime": r["mime"],
            "size": r["size"],
            "duration": r["duration"],
            "recordedBy": r["recorded_by"],
            "at": r["created_at"],
            "url": f"/api/recordings/{r['id']}/file",
        }
        for r in rows
    ]


# ---------------------------------------------------------------- proctoring
def touch_candidate(candidate_id: str) -> None:
    db.run("UPDATE candidates SET last_active = ? WHERE id = ?", db.now(), candidate_id)


def record_proctor_event(*, candidate_id: str, exam_id: str | None, type: str, event: str,
                         actor: str | None = None, ip: str | None = None) -> dict:
    """Logs an integrity event; warnings count towards the auto-flag limit. Returns {autoFlagged}."""
    with db.tx():
        db.audit(candidate_id=candidate_id, type=type, event=event, exam_id=exam_id, actor=actor, ip=ip)
        touch_candidate(candidate_id)
        if type != "Warning":
            return {"autoFlagged": False}
        try:
            limit = max(1, int(db.get_settings()["security"].get("maxWarningsBeforeFlag") or 3))
        except (TypeError, ValueError):
            limit = 3
        db.run("UPDATE candidates SET warnings = warnings + 1 WHERE id = ?", candidate_id)
        row = db.one("SELECT warnings FROM candidates WHERE id = ?", candidate_id)
        warnings = row["warnings"] if row else 0
        if warnings > 0 and warnings % limit == 0:
            db.run("UPDATE candidates SET cheating_flags = cheating_flags + 1 WHERE id = ?", candidate_id)
            db.audit(candidate_id=candidate_id, type="Warning", event=f"Auto-flagged: reached {limit} warnings", exam_id=exam_id)
            return {"autoFlagged": True}
        return {"autoFlagged": False}


def flag_candidate(*, candidate_id: str, exam_id: str | None, reason: str, actor: str) -> None:
    with db.tx():
        db.run("UPDATE candidates SET cheating_flags = cheating_flags + 1 WHERE id = ?", candidate_id)
        db.audit(candidate_id=candidate_id, type="Warning", event=f"Flagged by proctor{f': {reason}' if reason else ''}",
                 exam_id=exam_id, actor=actor)


# ---------------------------------------------------------------- exam attempts
def get_attempt_by_invite(invite_id: str) -> dict | None:
    return db.one("SELECT * FROM attempts WHERE invite_id = ?", invite_id)


def start_attempt(ctx: dict) -> dict:
    """Starts (or resumes) the candidate's attempt. Question and option order are fixed per attempt."""
    with db.tx():
        existing = get_attempt_by_invite(ctx["invite_id"])
        if existing:
            return existing
        settings = db.get_settings()
        questions = db.all_("SELECT id, options FROM questions WHERE bank_id = ? ORDER BY position, id", ctx["bank_id"])
        order = [{"id": q["id"], "options": list(range(len(loads(q["options"], []))))} for q in questions]
        if settings["exam"].get("shuffleOptions"):
            for q in order:
                random.shuffle(q["options"])
        if settings["exam"].get("shuffleQuestions"):
            random.shuffle(order)
        started = datetime.now(timezone.utc)
        deadline = started + timedelta(minutes=ctx["duration"])
        exam_end = exam_end_ms(db.one("SELECT start_time, duration FROM exams WHERE id = ?", ctx["exam_id"]))
        if exam_end is not None:  # a late starter only gets the time left in the exam
            deadline = min(deadline, datetime.fromtimestamp(exam_end / 1000, tz=timezone.utc))
        attempt_id = db.new_id("ATT")
        db.run(
            "INSERT INTO attempts (id, invite_id, exam_id, candidate_id, question_order, started_at, deadline) VALUES (?, ?, ?, ?, ?, ?, ?)",
            attempt_id, ctx["invite_id"], ctx["exam_id"], ctx["candidate_id"], dumps(order),
            iso(started), iso(deadline),
        )
        db.run("UPDATE invites SET status = 'Started' WHERE id = ?", ctx["invite_id"])
        db.audit(candidate_id=ctx["candidate_id"], type="Normal", event="Started exam", exam_id=ctx["exam_id"])
        return get_attempt_by_invite(ctx["invite_id"])


def attempt_questions(attempt: dict) -> list[dict]:
    """Questions for the candidate, in their attempt order, without answer keys."""
    order = loads(attempt["question_order"], [])
    ids = [o["id"] for o in order]
    by_id = {q["id"]: q for q in db.all_(f"SELECT id, text, options FROM questions WHERE id IN ({_ids_in(ids)})", *ids)}
    out = []
    for o in order:
        q = by_id.get(o["id"])
        if not q:
            continue
        opts = loads(q["options"], [])
        # `value` is the original option index; the candidate never sees which one is correct.
        out.append({
            "id": o["id"],
            "text": q["text"],
            "options": [{"value": i, "label": opts[i] if 0 <= i < len(opts) else None} for i in o["options"]],
        })
    return out


def finish_attempt(attempt_id: str, *, status: str = "Submitted", reason: str | None = None, actor: str | None = None) -> dict | None:
    """Scores an attempt on the server and writes the result. Idempotent."""
    with db.tx():
        a = db.one("SELECT * FROM attempts WHERE id = ?", attempt_id)
        if not a or a["status"] != "InProgress":
            return None
        finished_ms = now_ms()
        finished_iso = db.now()
        db.run("UPDATE attempts SET status = ?, finished_at = ?, terminated_reason = ? WHERE id = ?",
               status, finished_iso, reason, a["id"])
        db.run("UPDATE invites SET status = ? WHERE id = ?", status, a["invite_id"])
        if status == "Terminated":
            db.audit(candidate_id=a["candidate_id"], type="Warning",
                     event=f"Exam terminated by proctor{f': {reason}' if reason else ''}", exam_id=a["exam_id"], actor=actor)
            return {"status": status}
        order = loads(a["question_order"], [])
        answers = loads(a["answers"], {}) or {}
        ids = [o["id"] for o in order]
        keys = {q["id"]: q["answer"] for q in db.all_(f"SELECT id, answer FROM questions WHERE id IN ({_ids_in(ids)})", *ids)}
        total = len(order)
        correct = sum(1 for o in order if o["id"] in answers and o["id"] in keys and answers[o["id"]] == keys[o["id"]]
                      and not isinstance(answers[o["id"]], bool))
        score = js_round(correct / total * 100) if total else 0
        exam = db.one("SELECT pass_mark FROM exams WHERE id = ?", a["exam_id"])
        pass_mark = exam["pass_mark"] if exam and exam["pass_mark"] is not None else 60
        end_ms = min(finished_ms, date_ms(a["deadline"]))
        minutes = max(1, js_round((end_ms - date_ms(a["started_at"])) / 60000))
        pass_fail = "Pass" if score >= pass_mark else "Fail"
        db.run(
            """INSERT INTO results (id, candidate_id, exam_id, score, correct, total, time_taken, submitted_at, result)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(candidate_id, exam_id) DO UPDATE SET score = excluded.score, correct = excluded.correct,
                 total = excluded.total, time_taken = excluded.time_taken, submitted_at = excluded.submitted_at, result = excluded.result""",
            db.new_id("RS"), a["candidate_id"], a["exam_id"], score, correct, total, minutes, finished_iso, pass_fail,
        )
        db.audit(
            candidate_id=a["candidate_id"],
            type="Normal",
            event=f"Exam auto-submitted ({reason}) — scored {score}%" if reason else f"Submitted exam — scored {score}%",
            exam_id=a["exam_id"],
        )
        return {"status": status, "correct": correct, "total": total, "score": score, "result": pass_fail}


def start_due_exams() -> list[str]:
    """Scheduled exams whose start time has arrived go Live automatically. Returns the exam ids started."""
    started = []
    for e in db.all_("SELECT id, title FROM exams WHERE status = 'Scheduled' AND start_time <= ?", db.now()):
        with db.tx():
            if db.run("UPDATE exams SET status = 'Live' WHERE id = ? AND status = 'Scheduled'", e["id"]):
                db.audit(type="Normal", event=f'Exam "{e["title"]}" started automatically at its scheduled time', exam_id=e["id"])
                started.append(e["id"])
    return started


def sweep_expired_attempts() -> None:
    """Auto-submits attempts whose time ran out (with a 30 s grace for slow connections)."""
    cutoff = iso(datetime.now(timezone.utc) - timedelta(seconds=30))
    for a in db.all_("SELECT id FROM attempts WHERE status = 'InProgress' AND deadline < ?", cutoff):
        finish_attempt(a["id"], reason="time ran out")


def finish_attempts_for_exam(exam_id: str, reason: str = "exam ended by admin") -> None:
    for a in db.all_("SELECT id FROM attempts WHERE status = 'InProgress' AND exam_id = ?", exam_id):
        finish_attempt(a["id"], reason=reason)


def exam_end_ms(exam: dict | None) -> float | None:
    """When an exam's time runs out: its start time + duration (milliseconds), or None if unknown."""
    if not exam:
        return None
    start = date_ms(exam["start_time"])
    if start != start:  # NaN: unparsable start time
        return None
    return start + int(exam["duration"]) * 60000


def end_finished_exams(grace_seconds: int = 30) -> list[tuple[str, list[str]]]:
    """Live exams whose time (start + duration) has run out are completed automatically: answers
    in progress are submitted and scored. Returns [(exam id, invite ids that were mid-exam)]."""
    ended = []
    now = now_ms()
    for e in db.all_("SELECT id, title, start_time, duration FROM exams WHERE status = 'Live'"):
        end = exam_end_ms(e)
        if end is None or now < end + grace_seconds * 1000:
            continue
        open_invites = [a["invite_id"] for a in db.all_("SELECT invite_id FROM attempts WHERE exam_id = ? AND status = 'InProgress'", e["id"])]
        with db.tx():
            if not db.run("UPDATE exams SET status = 'Completed' WHERE id = ? AND status = 'Live'", e["id"]):
                continue
            finish_attempts_for_exam(e["id"], reason="exam time ended")
            db.audit(type="Normal", event=f'Exam "{e["title"]}" ended automatically when its time ran out', exam_id=e["id"])
        ended.append((e["id"], open_invites))
    return ended
