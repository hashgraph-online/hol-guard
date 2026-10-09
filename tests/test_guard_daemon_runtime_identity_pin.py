"""Pin the daemon runtime identity before an in-place upgrade can relabel it."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer, manager
from codex_plugin_scanner.guard.store import GuardStore


def test_daemon_pins_runtime_fingerprint_at_construction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installed = {"generation": "previous-generation"}
    monkeypatch.setattr(manager, "_runtime_fingerprint_cache", None)
    monkeypatch.setattr(manager, "_load_runtime_fingerprint_cache", lambda *_args: None)
    monkeypatch.setattr(manager, "_store_runtime_fingerprint_cache", lambda *_args: None)
    monkeypatch.setattr(manager, "_hash_runtime_contents", lambda *_args: installed["generation"])

    daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    try:
        installed["generation"] = "replacement-generation"
        assert manager.current_guard_daemon_runtime_fingerprint() == "previous-generation"
    finally:
        daemon.stop()
