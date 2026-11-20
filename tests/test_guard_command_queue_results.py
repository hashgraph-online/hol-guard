"""Command queue results built by the native runtime.

These tests need the compiled runtime, so they live apart from the queue tests
that mock it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_executors, command_queue
from tests.test_guard_command_queue import (  # noqa: F401 - autouse fixtures apply here too
    FakeStore,
    _context,
    _default_store_platform,
    _isolate_legacy_queue_mechanics,
)

# Every job is planned by the native runtime before it runs.
pytestmark = pytest.mark.usefixtures("native_command_capability_runtime")


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_poll_once_posts_failed_result_when_execution_raises(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    result_payloads: list[dict[str, object]] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )
    monkeypatch.setattr(
        command_executors,
        "package_shim_status",
        lambda context: (_ for _ in ()).throw(RuntimeError("shim status failed")),
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        if path == "/lease":
            return {
                "item": {
                    "id": "job-5",
                    "leaseId": "lease-5",
                    "operation": "guard.packageShims.status",
                }
            }
        if path.endswith("/result"):
            result_payloads.append(payload)
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert result_payloads[0]["status"] == "failed"
    assert result_payloads[0]["failureCode"] == "execution_error"
    assert "shim status failed" in str(result_payloads[0]["failureMessage"])


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_poll_once_posts_waiting_local_confirm_result_for_destructive_job(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    result_payloads: list[dict[str, object]] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        if path == "/lease":
            return {
                "item": {
                    "id": "job-6",
                    "leaseId": "lease-6",
                    "operation": "guard.packageShims.remove",
                    "payload": {"managers": ["npm"]},
                }
            }
        if path.endswith("/result"):
            result_payloads.append(payload)
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert result_payloads[0]["status"] == "waiting_local_confirm"
    assert result_payloads[0]["idempotencyKey"] == "job-6:lease-6:waiting_local_confirm"
    result = result_payloads[0]["result"]
    assert isinstance(result, dict)
    assert "waitingLocalConfirm" not in result
    data = result["data"]
    assert isinstance(data, dict)
    assert data["confirm_command"] == "hol-guard package-shims uninstall --manager npm"
    assert data["summary"] == (
        "Run the local package-shim uninstall command on this machine to confirm removal for npm."
    )


@pytest.mark.usefixtures("native_command_capability_runtime")
def test_result_payload_reuses_stable_success_idempotency_key() -> None:
    job = {"id": "job-duplicate-result", "leaseId": "lease-duplicate-result"}
    execution = {"data": {"ok": True}}

    first = command_queue._result_payload(job, execution)
    second = command_queue._result_payload(job, execution)

    assert first["status"] == "succeeded"
    assert first["idempotencyKey"] == "job-duplicate-result:lease-duplicate-result:succeeded"
    assert second["idempotencyKey"] == first["idempotencyKey"]
