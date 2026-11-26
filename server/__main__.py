"""Run the server:  python -m server            (add --reload while developing)"""
from __future__ import annotations

import sys

import uvicorn

from .config import config
from .signaling import MAX_MESSAGE_BYTES


def main() -> None:
    reload = "--reload" in sys.argv[1:]
    uvicorn.run(
        "server.main:app",
        host=config.host,
        port=config.port,
        reload=reload,
        reload_dirs=[str(config.root / "server")] if reload else None,
        ws_max_size=MAX_MESSAGE_BYTES,
        ws_ping_interval=15,  # drop dead connections so staff see candidates leave promptly
        ws_ping_timeout=15,
        proxy_headers=False,  # X-Forwarded-* are handled by the app (TRUST_PROXY)
        server_header=False,
        access_log=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
