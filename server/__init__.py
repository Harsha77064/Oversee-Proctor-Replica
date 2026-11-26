"""Oversee server: REST API, WebSocket signaling and the built web app (Python / FastAPI)."""
import importlib.util as _util
import os as _os
import subprocess as _subprocess
import sys as _sys
from pathlib import Path as _Path

# Started with a Python that lacks the server's packages (e.g. the system Python
# instead of the project's virtual environment)? Re-run the same command with
# .venv's Python, so `npm run dev` / `python -m server` work without activating it.
if _util.find_spec("fastapi") is None and not _os.environ.get("OVERSEE_NO_VENV_SWITCH"):
    _venv = _Path(__file__).resolve().parent.parent / ".venv"
    _python = _venv / ("Scripts/python.exe" if _os.name == "nt" else "bin/python")
    if _python.exists() and _Path(_sys.executable).resolve() != _python.resolve() and getattr(_sys, "orig_argv", None):
        _env = {**_os.environ, "OVERSEE_NO_VENV_SWITCH": "1"}
        _sys.exit(_subprocess.call([str(_python), *_sys.orig_argv[1:]], env=_env))
    raise SystemExit(
        "The server's Python packages are not installed for this Python.\n"
        "Set up once with:\n"
        "  py -3.13 -m venv .venv            (macOS/Linux: python3 -m venv .venv)\n"
        "  .venv\\Scripts\\pip install -r requirements-dev.txt   (macOS/Linux: .venv/bin/pip ...)"
    )
