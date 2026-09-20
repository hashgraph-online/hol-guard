"""Fixtures for authenticated local approval-link tests."""

from __future__ import annotations

from pathlib import Path


def write_synthetic_daemon_auth_token(
    guard_home: Path,
    token: str = "synthetic-daemon-token",
) -> None:
    """Create the private daemon credential used by signed-link tests."""

    guard_home.mkdir(parents=True, exist_ok=True)
    guard_home.chmod(0o700)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text(token, encoding="utf-8")
    token_path.chmod(0o600)
