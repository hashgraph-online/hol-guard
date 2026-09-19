"""Read live Cloud Review worker evidence from an existing authenticated daemon."""

from __future__ import annotations

from pathlib import Path

from .live_identity import verified_live_guard_daemon_identity
from .local_status_transport import read_local_status
from .manager import load_guard_daemon_auth_token


def read_cloud_review_worker_observation(guard_home: Path) -> object:
    try:
        identity = verified_live_guard_daemon_identity(guard_home)
        token = load_guard_daemon_auth_token(guard_home)
    except (OSError, RuntimeError, ValueError):
        return None
    if identity is None:
        return None
    url = identity.get("daemon_url")
    if not isinstance(url, str) or not isinstance(token, str) or not token:
        return None
    payload = read_local_status(url, token, path="/v1/cloud-review")
    return payload.get("worker") if isinstance(payload, dict) else None
