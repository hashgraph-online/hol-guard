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


def test_upgraded_install_cannot_adopt_previous_generation_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed = {"generation": "previous-generation"}
    monkeypatch.setattr(manager, "_runtime_fingerprint_cache", None)
    monkeypatch.setattr(manager, "_load_runtime_fingerprint_cache", lambda *_args: None)
    monkeypatch.setattr(manager, "_store_runtime_fingerprint_cache", lambda *_args: None)
    monkeypatch.setattr(manager, "_hash_runtime_contents", lambda *_args: installed["generation"])
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = manager.load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        details = manager._daemon_healthz_details_payload(f"http://127.0.0.1:{daemon.port}", auth_token, timeout=5)
        assert details is not None
        assert details["source_root"] == manager.current_guard_daemon_source_root()
        assert manager._daemon_healthz_details_match_current_runtime(details) is True

        installed["generation"] = "replacement-generation"
        monkeypatch.setattr(manager, "_runtime_fingerprint_cache", None)
        assert details["runtime_fingerprint"] == "previous-generation"
        assert manager._daemon_healthz_details_match_current_runtime(details) is False
        legacy_details = {key: value for key, value in details.items() if key != "source_root"}
        assert manager._daemon_healthz_details_match_current_runtime(legacy_details) is False
    finally:
        daemon.stop()
