"""Server maintenance commands.

  python -m server.cli create-admin --name "Jane Admin" --email jane@example.com --password '...'
  python -m server.cli reset-password --email jane@example.com --password '...'
  python -m server.cli seed-demo
  python -m server.cli backup            (copies the database to DATA_DIR/backups)
"""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

from . import db
from .auth import hash_password, password_problem, revoke_sessions
from .config import config
from .seed import seed_demo


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(1)


def main(argv: list[str]) -> None:
    cmd, rest = (argv[0] if argv else ""), argv[1:]
    args = {rest[i].removeprefix("--"): rest[i + 1] if i + 1 < len(rest) else "" for i in range(0, len(rest), 2)}

    if cmd in ("create-admin", "reset-password"):
        if not args.get("email") or not args.get("password"):
            fail("Pass --email and --password.")
        problem = password_problem(args["password"])
        if problem:
            fail(f"Password: {problem}")
        password_hash = asyncio.run(hash_password(args["password"]))
        email = args["email"].lower()
        existing = db.one("SELECT id FROM users WHERE email = ?", email)
        if cmd == "create-admin":
            if existing:
                fail("A user with that email already exists. Use reset-password.")
            db.run("INSERT INTO users (id, name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                   db.new_id("USR"), args.get("name") or "Administrator", email, password_hash, "admin", db.now())
            print(f"Admin {args['email']} created.")
        else:
            if not existing:
                fail("No user with that email.")
            db.run("UPDATE users SET password_hash = ?, active = 1 WHERE id = ?", password_hash, existing["id"])
            revoke_sessions("staff", existing["id"])
            print(f"Password reset for {args['email']}.")
    elif cmd == "backup":
        folder = config.data_dir / "backups"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        file = folder / f"oversee-{stamp}.db"
        db.backup(str(file))
        print(f"Database backed up to {file}")
    elif cmd == "seed-demo":
        print("Demo data loaded." if seed_demo() else "Skipped: the database already has candidates.")
    else:
        fail("Commands: create-admin, reset-password, seed-demo, backup")


if __name__ == "__main__":
    main(sys.argv[1:])
