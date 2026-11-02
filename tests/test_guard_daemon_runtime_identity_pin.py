"""Pin the daemon runtime identity before an in-place upgrade can relabel it."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer, manager
from codex_plugin_scanner.guard.store import GuardStore


def test_daemon_pins_runtime_fingerprint_at_construction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installed = {"generation": "previous-generation"}
    monkeypatch.setattr(manager, "_runtime_fingerprint_cache", None)
    monkeypatch.setattr(
        manager, "_measure_runtime_fingerprint", lambda *_args: ("tree", installed["generation"], False)
    )

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
    monkeypatch.setattr(
        manager, "_measure_runtime_fingerprint", lambda *_args: ("tree", installed["generation"], False)
    )
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


def test_runtime_fingerprint_waits_out_a_cold_capability_probe_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    answers: list[dict[str, object] | None] = [
        None,
        {"tree_sig": "tree", "fingerprint": "a" * 64, "reused": False},
    ]
    waits: list[float] = []
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: answers.pop(0))
    monkeypatch.setattr(manager, "await_native_runtime", lambda budget: waits.append(budget) or 0.6)

    assert manager._measure_runtime_fingerprint(tmp_path, None) == ("tree", "a" * 64, False)
    assert waits == [60.0]


def test_runtime_fingerprint_refuses_when_no_probe_miss_is_waited_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    calls: list[str] = []
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: calls.append("ask"))
    monkeypatch.setattr(manager, "await_native_runtime", lambda _budget: 0.0)

    with pytest.raises(RuntimeError, match="requires the native runtime"):
        manager._measure_runtime_fingerprint(tmp_path, None)
    assert calls == ["ask"]
