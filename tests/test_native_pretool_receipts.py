"""Receipt handoff from the native hook worker to the daemon owner."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_entrypoint


def test_resident_entrypoint_returns_worker_receipt_to_daemon_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = {"schema": "guard-native-hook-decision-receipt.v1", "decision_id": "receipt-1"}

    class FakeWorker:
        last_native_decision_receipt = receipt

        def __init__(self, *, store: object, **_kwargs: object) -> None:
            del store
            del _kwargs

        def review_http_payload(self, **_kwargs: object) -> dict[str, object]:
            return {"policy_action": "allow"}

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.HookWorker", FakeWorker)
    monkeypatch.setattr(hook_process_entrypoint, "_current_decision_route", lambda: "native_resident")
    guard_home = tmp_path / "guard-home"
    result = hook_process_entrypoint._run_resident_hook_request(
        {
            "payload": {"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            "harness": "codex",
            "home_dir": str(tmp_path / "home"),
            "guard_home": str(guard_home),
            "workspace": str(tmp_path / "workspace"),
        },
        stores={},
        hook_workers={},
        configured_guard_home=str(guard_home),
    )

    assert result == {
        "payload": {"policy_action": "allow"},
        "reason_code": None,
        "route": "native_resident",
        "receipt": receipt,
    }


def test_resident_entrypoint_forwards_parent_deadline_to_hook_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeWorker:
        last_native_decision_receipt = None

        def __init__(self, *, store: object, **_kwargs: object) -> None:
            del store
            del _kwargs

        def review_http_payload(self, **kwargs: object) -> dict[str, object]:
            captured.update(kwargs)
            return {"policy_action": "allow"}

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.HookWorker", FakeWorker)
    monkeypatch.setattr(hook_process_entrypoint, "_current_decision_route", lambda: "native_resident")
    guard_home = tmp_path / "guard-home"
    result = hook_process_entrypoint._run_resident_hook_request(
        {
            "payload": {"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            "harness": "codex",
            "home_dir": str(tmp_path / "home"),
            "guard_home": str(guard_home),
            "workspace": str(tmp_path / "workspace"),
            "deadline": 12.5,
        },
        stores={},
        hook_workers={},
        configured_guard_home=str(guard_home),
    )

    assert result["reason_code"] is None
    assert captured["deadline"] == 12.5
