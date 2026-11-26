"""Starts a throwaway Oversee server with an empty database and creates the first
admin (with demo data). Tests talk to it over real HTTP and WebSockets."""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
ADMIN = {"email": "admin@example.com", "password": "Str0ngPassw0rd"}


@pytest.fixture(scope="session")
def base_url():
    data_dir = tempfile.mkdtemp(prefix="oversee-test-")
    port = 3900 + random.randrange(90)
    env = {
        **os.environ,
        "APP_ENV": "test", "PORT": str(port), "HOST": "127.0.0.1", "DATA_DIR": data_dir,
        "SMTP_HOST": "", "TURN_URLS": "", "PUBLIC_URL": "", "EXAM_END_GRACE_SECONDS": "1",
    }
    proc = subprocess.Popen([sys.executable, "-m", "server"], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(f"{base}/api/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if proc.poll() is not None:
                raise RuntimeError(f"Server exited: {proc.stderr.read()}")
            time.sleep(0.1)
        else:
            raise RuntimeError("Server did not start")
        r = httpx.post(f"{base}/api/setup", json={"name": "Test Admin", **ADMIN, "orgName": "Test Org", "loadDemo": True})
        assert r.status_code == 200, r.text
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(data_dir, ignore_errors=True)


def client(base: str) -> httpx.Client:
    """A browser-like client with its own cookie jar."""
    return httpx.Client(base_url=base, timeout=30)


@pytest.fixture(scope="session")
def admin(base_url):
    c = client(base_url)
    r = c.post("/api/auth/login", json=ADMIN)
    assert r.status_code == 200, r.text
    yield c
    c.close()
