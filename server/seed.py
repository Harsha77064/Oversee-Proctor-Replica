"""Optional demo data (seed_data.json: the same dataset the UI was designed with)."""
from __future__ import annotations

import json
from pathlib import Path

from . import db
from .jsutil import dumps

SEED_FILE = Path(__file__).with_name("seed_data.json")


def _num(id_: str) -> int:
    try:
        return int(str(id_).split("-")[-1]) or 0
    except ValueError:
        return 0


def seed_demo() -> bool:
    if db.one("SELECT COUNT(*) AS n FROM candidates")["n"]:
        return False
    data = json.loads(SEED_FILE.read_text(encoding="utf-8"))
    with db.tx():
        t = db.now()
        for c in data["candidates"]:
            db.run(
                "INSERT INTO candidates (id, name, email, department, status, warnings, cheating_flags, last_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                c["id"], c["name"], c["email"], c["department"], c["status"], c["warnings"], c["cheatingFlags"], c["lastActive"], t,
            )
        for b in data["questionBanks"]:
            db.run("INSERT INTO question_banks (id, name, topic, description, created_at) VALUES (?, ?, ?, ?, ?)",
                   b["id"], b["name"], b["topic"], b["description"], b["createdAt"])
            for i, q in enumerate(b["questions"]):
                db.run("INSERT INTO questions (id, bank_id, text, options, answer, difficulty, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       q["id"], b["id"], q["text"], dumps(q["options"]), q["answer"], q["difficulty"], i + 1)
        for e in data["exams"]:
            db.run("INSERT INTO exams (id, title, bank_id, status, start_time, duration, pass_mark, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   e["id"], e["title"], e["bankId"], e["status"], e["startTime"], e["duration"], e["passMark"], t)
            for cid in e["candidates"]:
                db.run("INSERT OR IGNORE INTO exam_candidates (exam_id, candidate_id) VALUES (?, ?)", e["id"], cid)
        for r in data["results"]:
            db.run("INSERT INTO results (id, candidate_id, exam_id, score, correct, total, time_taken, submitted_at, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   r["id"], r["candidateId"], r["examId"], r["score"], r["correct"], r["total"], r["timeTaken"], r["submittedAt"], r["result"])
        for f in data["feedback"]:
            db.run("INSERT INTO feedback (id, candidate_id, exam_id, rating, message, sent_by, sent_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   f["id"], f["candidateId"], f["examId"], f["rating"], f["message"], f["sentBy"], f["sentAt"])
        for l in data["auditLogs"]:
            db.run("INSERT INTO audit_logs (candidate_id, type, event, exam_id, ip, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                   l["candidateId"], l["type"], l["event"], l["examId"], l["ip"], l["timestamp"])

        def set_counter(name: str, value: int) -> None:
            db.run("INSERT INTO counters (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = MAX(value, excluded.value)",
                   name, value)

        set_counter("CND", max(_num(c["id"]) for c in data["candidates"]))
        set_counter("QB", max(_num(b["id"]) for b in data["questionBanks"]))
        set_counter("EX", max(_num(e["id"]) for e in data["exams"]))
        set_counter("RS", max([3000, *(_num(r["id"]) for r in data["results"])]))
        set_counter("FB", max([4000, *(_num(f["id"]) for f in data["feedback"])]))

        current = db.get_settings()
        for section in ("exam", "security", "notifications"):
            db.save_settings(section, {**current[section], **data["settings"].get(section, {})})
    return True
