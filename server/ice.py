"""ICE servers for WebRTC. STUN finds a direct route; TURN relays video when no
direct route exists (strict firewalls, mobile networks, different offices)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import time

from .config import config


def ice_servers(identity: str = "oversee") -> list[dict]:
    servers: list[dict] = []
    ice = config.ice
    if ice.stun:
        servers.append({"urls": ice.stun})
    if ice.turn:
        if ice.turn_secret:
            # coturn "use-auth-secret" REST credentials, valid for 12 hours.
            username = f"{int(time.time()) + 12 * 3600}:{identity}"
            digest = hmac.new(ice.turn_secret.encode(), username.encode(), hashlib.sha1).digest()
            servers.append({"urls": ice.turn, "username": username, "credential": base64.b64encode(digest).decode()})
        elif ice.turn_username:
            servers.append({"urls": ice.turn, "username": ice.turn_username, "credential": ice.turn_credential})
    return servers
