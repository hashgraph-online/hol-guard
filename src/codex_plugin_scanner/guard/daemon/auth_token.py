"""Read the guard home's shared daemon auth token without loading the daemon manager."""

from __future__ import annotations

from pathlib import Path

from ..private_file_io import read_private_regular_text


def auth_token_path(guard_home: Path) -> Path:
    return guard_home / "daemon-auth-token"


def load_guard_daemon_auth_token(guard_home: Path) -> str | None:
    token = read_private_regular_text(
        auth_token_path(guard_home),
        max_bytes=4096,
        require_private_parent=True,
    )
    return token or None
