from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.bridge import _validate_guard_daemon_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ("http://127.0.0.1:4999", "http://127.0.0.1:4999"),
        ("http://localhost:4999/", "http://localhost:4999"),
        ("http://[::1]:4999", "http://[::1]:4999"),
    ),
)
def test_bridge_daemon_url_accepts_only_loopback_http_origins(raw: str, expected: str) -> None:
    assert _validate_guard_daemon_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    (
        "https://127.0.0.1:4999",
        "http://example.com:4999",
        "http://10.0.0.5:4999",
        "http://user:secret@127.0.0.1:4999",
        "http://127.0.0.1:4999/v1",
        "http://127.0.0.1:4999?token=secret",
        "http://127.0.0.1:65536",
    ),
)
def test_bridge_daemon_url_rejects_remote_or_secret_bearing_targets(raw: str) -> None:
    with pytest.raises(ValueError):
        _validate_guard_daemon_url(raw)
