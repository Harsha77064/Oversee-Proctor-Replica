# Oversee

**Smart online proctoring & assessment platform.** Admins build question banks, schedule
exams and invite candidates; candidates take the exam in their browser while proctors
watch their camera and microphone live.

- **Frontend:** React 18 + Vite, React Router, Recharts, Lucide icons
- **Backend:** Python 3.11+ with FastAPI + Uvicorn, SQLite (built-in `sqlite3`), WebSocket signaling
- **Live video:** WebRTC, browser to browser, with a TURN relay for strict networks
- **Deployment:** Docker Compose with Caddy (automatic HTTPS) and coturn — see **[DEPLOY.md](DEPLOY.md)**

## Run it locally

Requires **Python 3.11+** (for the server) and **Node.js 20+** (only to run and build the
React frontend; browsers can only run JavaScript).

One-time setup:

```bash
py -3.13 -m venv .venv                         # macOS/Linux: python3 -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt   # macOS/Linux: .venv/bin/pip install -r requirements-dev.txt
npm install
```

Then:

```bash
npm run dev
```

You don't need to activate the virtual environment: the server switches to `.venv`
automatically. To run only the server: `python -m server --reload`.

Open http://localhost:5173. The first visit shows **Set up Oversee**: create your
organization and admin account (tick "Load demo data" to try it with sample data).

`npm run dev` starts two processes: the Python API + proctoring server on port 3001 and the
Vite dev server on 5173 (which forwards `/api` and `/signal` to the server). Data is
stored in `./data` (database and recordings).

**Try a proctored exam on one computer**
1. Exams → Live tab (or Start Now on a scheduled exam) → **Invitations** → tick a candidate → **Create links**.
2. Open the link in a different browser (or a private window) and enter the access code.
3. Allow the camera, start the exam, and watch it under **Live Monitoring**.

**Other devices on your network:** browsers only allow cameras on `https://` or
`localhost`, so run `npm run dev:lan` and use the `https://<your-ip>:5173` address it
prints (accept the self-signed certificate warning once).

## Production

```bash
npm run build                          # builds the React app into dist/
APP_ENV=production python -m server    # serves the app, API and signaling on port 3000
```

For a real deployment with HTTPS, TURN and backups use Docker Compose: **[DEPLOY.md](DEPLOY.md)**.
Configuration is via environment variables; see [.env.example](.env.example).

## Roles

| Role | Can do |
|---|---|
| **Admin** | Everything: candidates, question banks, exams, invitations, settings, users |
| **Proctor** | Monitor live exams, record, warn, flag, terminate, send feedback; read-only elsewhere; never sees answer keys |
| **Candidate** | Signs in with a personal invitation link + access code; takes only their assigned exam |

## Sections

| Section | What it does |
|---|---|
| **Dashboard** | Candidate stats (total, active, inactive, online), live and completed exams, average / highest / lowest score, warnings, cheating flags; candidate table with user ID, department, status and **Assign Exam**. |
| **Question Bank** | Create banks and multiple-choice questions with difficulty. Demo banks: React JS, Selenium, Python, Java OOPs, JavaScript, SQL, DevOps. |
| **Exams** | Scheduled / Live / Completed. Schedule, start, end, delete; **Invitations** creates personal links + access codes and can email them. |
| **Results** | Server-scored results with Pass / Fail, pass rate and filters. |
| **Feedback** | Organization → candidate feedback with a rating. |
| **Live Monitoring** | Real-time camera + microphone of every candidate. Record (saved on the server), snapshot, listen, message, warn, flag, terminate. Integrity alerts arrive live. |
| **Candidate portal** (`/exam`) | Candidates open the link from their invitation, or go to `/exam` and sign in with their email + access code. Then a camera/microphone/connection check, consent, full-screen timed exam. Answers save as they go and survive a reload. Tab switches, focus loss, leaving full screen, copy/paste, blocked shortcuts and a covered or disconnected camera are reported and logged. |
| **Audit Logs** | Per-candidate summary and full event log (who did what, when, from which IP), CSV export. |
| **Reports** | Charts and CSV exports. |
| **Settings** | Organization (company URL, logo URL, support email), exam defaults, security, notifications, and **Email** (how invitations are sent: off, test mode with an in-app outbox, or real SMTP such as Gmail/Outlook, with a "Send test email" button). |
| **Users** | Add admins and proctors, change roles, reset passwords, deactivate; change your own password. |

## Project structure

```
server/                      Python package (FastAPI)
  __main__.py     `python -m server`: runs Uvicorn (add --reload while developing)
  main.py         App: security headers, API, static files, background jobs
  api.py          REST API (staff + candidate routes, validation, permissions)
  signaling.py    Authenticated WebSocket relay for WebRTC + live proctoring events
  services.py     Scoring, attempts, proctoring events, data serializers
  auth.py         scrypt passwords, cookie sessions, role checks
  db.py           SQLite schema and migrations
  mailer.py       Invitation emails: off / test outbox / SMTP (settings from Settings → Email or SMTP_* in .env)
  ice.py          STUN/TURN config with short-lived TURN credentials
  jsutil.py       Keeps validation, rounding and timestamps identical to the browser's
  seed.py + seed_data.json   Demo data
  cli.py          Admin/backup commands (python -m server.cli <command>)
requirements.txt, requirements-dev.txt   Python dependencies
src/
  App.jsx                    Routing, sign-in gate, layout
  api.js                     Fetch wrapper
  context/                   Auth and data stores
  live/                      WebRTC + signaling client, admin live context
  pages/                     One file per section, plus Login, Setup, Users, CandidatePortal
tests/                       pytest suite: API + WebSocket (npm test)
Dockerfile, docker-compose.yml, deploy/Caddyfile, DEPLOY.md
```

## Email invitations

Set this up under **Settings → Email** (admins only):

- **Test mode**: nothing is sent; every email is saved and shown in a *Test outbox* on that page.
  Use it to try invitations without a mail account.
- **Send real email**: enter your SMTP details (Quick setup fills in Gmail, Outlook or Zoho), save, then
  **Send test email**. For Gmail or Outlook with two-step sign-in, use an **App Password**, not your
  normal password. The password is stored on the server and never shown again.

Then in **Exams → Invitations**, tick candidates and click **Create and email** (or *Create and save to
outbox* in test mode). Each email contains the candidate's personal link and access code, plus the
sign-in address below. `SMTP_*` settings in `.env`, if present, take priority over the page.

**Candidates** can open the link in the email, or go to **`/exam`** (e.g. `https://exams.example.com/exam`)
and sign in with their email address and access code. Wrong attempts there are rate-limited and logged,
but never lock the invitation.

## Checking a running server

With the server running (`npm run dev`, or `python -m server`), check every API area from
the terminal. It only reads data, so it is safe on your real server:

```bash
python -m server.check                                        # public checks, http://localhost:3001
python -m server.check http://localhost:3001 --email you@example.com   # + signed-in checks (asks for the password)
python -m server.check https://exams.example.com --email you@example.com
```

It reports PASS/FAIL for health, setup, security headers, sign-in, data, users, invitations,
recordings, video (ICE) settings and the live-proctoring WebSocket.

## Tests

```bash
npm test                 # or: .venv\Scripts\python -m pytest tests
```

Starts a throwaway server with an empty database and checks sign-in, roles, invitations,
the candidate exam flow, server-side scoring, recordings, security headers, and the live
proctoring WebSocket (authentication, relay rules, audit logging, ending sessions).
