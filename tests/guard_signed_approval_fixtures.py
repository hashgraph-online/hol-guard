"""Fixtures for authenticated local approval-link tests."""

from __future__ import annotations

import re
from pathlib import Path

_SHORT_CODE = r"/[0-9]{1,12}-[0-9a-f]{32}(?![0-9A-Za-z/_-])"


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


def short_signed_link(review_url: str | None = None) -> re.Pattern[str]:
    """Match the short signed approval link for `review_url`, or for any request."""

    base = re.escape(review_url) if review_url else r"/requests/[0-9a-f]{32}"
    return re.compile(base + _SHORT_CODE)
