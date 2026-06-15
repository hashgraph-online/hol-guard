from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.daemon import client as daemon_client_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.command_queue_worker import (
    CommandQueueWorker,
    start_command_queue_worker,
)
from codex_plugin_scanner.guard.runtime import command_executors, command_queue
from codex_plugin_scanner.guard.store import GuardStore


class FakeStore:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.payloads: dict[str, dict[str, object] | list[object]] = {}

    def get_sync_payload(self, key: str) -> dict[str, object] | list[object] | None:
        return self.payloads.get(key)

    def set_sync_payload(self, key: str, payload: dict[str, object] | list[object], now: str) -> None:
        self.payloads[key] = payload

    def get_cloud_sync_profile(self) -> dict[str, str]:
        return {
            "auth_mode": "oauth",
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "workspace_id": "workspace-1",
        }

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
        return {
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "workspace_id": "workspace-1",
        }

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        del status, harness, limit, cursor, search
        return []


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path,
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def _block_local_daemon_client(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("Guard Cloud command execution must not use the local daemon client.")

    monkeypatch.setattr(daemon_client_module, "load_guard_surface_daemon_client", fail)
    for module in (daemon_client_module, daemon_manager_module):
        monkeypatch.setattr(module, "ensure_guard_daemon", fail)
        monkeypatch.setattr(module, "load_guard_daemon_url", fail)
        monkeypatch.setattr(module, "load_guard_daemon_auth_token", fail)


def test_command_queue_enabled_defaults_on(monkeypatch) -> None:
    monkeypatch.delenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, raising=False)

    assert command_queue.command_queue_enabled() is True


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_command_queue_enabled_allows_explicit_opt_in(value: str, monkeypatch) -> None:
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, value)

    assert command_queue.command_queue_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "disabled"])
def test_command_queue_enabled_allows_explicit_opt_out(value: str, monkeypatch) -> None:
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, value)

    assert command_queue.command_queue_enabled() is False


@pytest.mark.parametrize("value", ["garbage", "maybe"])
def test_command_queue_enabled_disables_unrecognized_explicit_values(value: str, monkeypatch) -> None:
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, value)

    assert command_queue.command_queue_enabled() is False


def test_poll_once_leases_heartbeats_executes_and_posts_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_auth_context(current_store: object) -> dict[str, object]:
        assert current_store is store
        return {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"}

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append((method, path, payload))
        if path == "/lease":
            return {
                "item": {
                    "id": "job-1",
                    "leaseId": "lease-1",
                    "operation": "guard.packageShims.status",
                }
            }
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_resolve_guard_sync_auth_context", fake_auth_context)
    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)
    monkeypatch.setattr(
        command_executors,
        "package_shim_status",
        lambda context: {"active_managers": ["npm"]},
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls[0] == (
        "POST",
        "/lease",
        {
            "workspaceId": "workspace-1",
            "deviceId": "machine-1",
            "daemonVersion": command_queue.__version__,
            "capabilities": {
                "operations": list(command_executors.SUPPORTED_COMMAND_OPERATIONS),
                "schemaVersions": dict(command_executors.COMMAND_OPERATION_SCHEMA_VERSIONS),
            },
            "localRequestsSnapshot": {"requests": []},
            "maxJobs": 1,
            "waitMs": 25000,
        },
    )
    assert calls[1] == ("POST", "/job-1/heartbeat", {"leaseId": "lease-1"})
    assert calls[2] == ("POST", "/job-1/heartbeat", {"leaseId": "lease-1"})
    assert calls[3][0:2] == ("POST", "/job-1/result")
    assert calls[3][2]["status"] == "succeeded"
    assert calls[3][2]["leaseId"] == "lease-1"
    assert "machineInstallationId" not in calls[0][2]
    assert "machineInstallationId" not in calls[1][2]
    assert "machineInstallationId" not in calls[2][2]
    assert "machineInstallationId" not in calls[3][2]


def test_executor_app_remove_never_uses_local_daemon_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _block_local_daemon_client(monkeypatch)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.remove",
            "payload": {"harness": "codex", "surface": "cli"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard apps disconnect codex --surface cli --confirm disconnect-codex",
        "confirmation_phrase": "disconnect-codex",
        "harness": "codex",
        "summary": ("Run the local disconnect command on this machine to confirm removing Guard protection for codex."),
        "surface": "cli",
    }


def test_poll_once_executes_app_connect_without_local_daemon_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    calls: list[tuple[str, str, dict[str, object]]] = []
    _block_local_daemon_client(monkeypatch)
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
        calls.append((method, path, payload))
        if path == "/lease":
            return {
                "item": {
                    "id": "job-app-connect-1",
                    "leaseId": "lease-app-connect-1",
                    "operation": "guard.app.connect",
                    "payload": {"harness": "codex", "surface": "cli"},
                }
            }
        return {"ok": True}

    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        del install_all, context, store, workspace
        assert command == "install"
        assert requested_harness == "codex"
        assert isinstance(now, str) and now
        return {"managed_install": {"harness": requested_harness}, "surface": surface}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)
    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls[-1][0:2] == ("POST", "/job-app-connect-1/result")
    assert calls[-1][2]["status"] == "succeeded"
    result = calls[-1][2]["result"]
    assert isinstance(result, dict)
    assert result["data"] == {
        "managed_install": {"harness": "codex"},
        "surface": "cli",
    }


def test_poll_once_continues_when_local_request_snapshot_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class BrokenSnapshotStore(FakeStore):
        def list_approval_requests(
            self,
            *,
            status: str | None = "pending",
            harness: str | None = None,
            limit: int | None = 50,
            cursor: str | None = None,
            search: str | None = None,
        ) -> list[dict[str, object]]:
            del status, harness, limit, cursor, search
            raise OSError("approval store locked")

    store = BrokenSnapshotStore(tmp_path / "guard-home")
    calls: list[tuple[str, str, dict[str, object]]] = []
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
        calls.append((method, path, payload))
        if path == "/lease":
            return {
                "item": {
                    "id": "job-1",
                    "leaseId": "lease-1",
                    "operation": "guard.packageShims.status",
                }
            }
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)
    monkeypatch.setattr(
        command_executors,
        "package_shim_status",
        lambda context: {"active_managers": []},
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls[0][0:2] == ("POST", "/lease")
    assert calls[0][2]["localRequestsSnapshot"] == {"requests": []}
    assert calls[-1][0:2] == ("POST", "/job-1/result")


def test_poll_once_persists_result_retry_when_result_upload_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = FakeStore(tmp_path / "guard-home")

    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )
    monkeypatch.setattr(command_executors, "package_shim_status", lambda context: {"active_managers": []})

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
                    "id": "job-2",
                    "leaseId": "lease-2",
                    "operation": "guard.packageShims.status",
                }
            }
        if path.endswith("/result"):
            raise OSError("upload failed")
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    try:
        command_queue.poll_command_queue_once(store, _context(tmp_path))
    except OSError:
        pass
    else:
        raise AssertionError("result upload should fail")

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "result_pending"
    assert isinstance(state["pending_result"], dict)


def test_poll_once_clears_active_job_when_heartbeat_fails(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
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
                    "id": "job-2",
                    "leaseId": "lease-2",
                    "operation": "guard.packageShims.status",
                }
            }
        if path.endswith("/heartbeat"):
            raise OSError("heartbeat failed")
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    try:
        command_queue.poll_command_queue_once(store, _context(tmp_path))
    except OSError:
        pass
    else:
        raise AssertionError("heartbeat should fail")

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "error"
    assert "active_job" not in state


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


def test_poll_once_retries_pending_result_before_leasing(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {
            "state": "result_pending",
            "pending_result": {
                "job": {"id": "job-3", "leaseId": "lease-3"},
                "payload": {
                    "leaseId": "lease-3",
                    "idempotencyKey": "job-3:lease-3:succeeded",
                    "status": "succeeded",
                    "result": {"data": {}},
                },
            },
        },
        "2026-06-13T00:00:00+00:00",
    )
    calls: list[str] = []
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
        calls.append(path)
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls == ["/job-3/result"]
    assert status["pending_result"] is None


def test_poll_once_clears_active_job_for_malformed_pending_result(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {
            "state": "result_pending",
            "active_job": {"id": "job-4", "leaseId": "lease-4"},
            "pending_result": {"job": "bad", "payload": {}},
        },
        "2026-06-13T00:00:00+00:00",
    )
    calls: list[str] = []
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
        calls.append(path)
        return {"item": None}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    command_queue.poll_command_queue_once(store, _context(tmp_path))

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert "active_job" not in state
    assert "pending_result" not in state
    assert calls == ["/lease"]


def test_command_queue_loop_backs_off_after_empty_polls(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    waits: list[float] = []

    class StopAfterThreeWaits:
        def is_set(self) -> bool:
            return False

        def wait(self, seconds: float) -> bool:
            waits.append(seconds)
            return len(waits) >= 3

    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_POLL_INTERVAL_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ERROR_BACKOFF_ENV, "8")

    def fake_poll_once(current_store: object, context: HarnessContext) -> dict[str, object]:
        return {"last_poll_was_empty": True}

    monkeypatch.setattr(command_queue, "poll_command_queue_once", fake_poll_once)

    command_queue.command_queue_loop(
        store,
        _context(tmp_path),
        stop_event=StopAfterThreeWaits(),
    )

    assert waits == [1, 2, 4]


def test_start_worker_replaces_stopped_alive_worker(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")

    class FakeThread:
        def __init__(self) -> None:
            self.started = False

        def is_alive(self) -> bool:
            return True

        def start(self) -> None:
            self.started = True

    class FakeEvent:
        def __init__(self, stopped: bool = False) -> None:
            self.stopped = stopped

        def is_set(self) -> bool:
            return self.stopped

    created_threads: list[FakeThread] = []

    def fake_thread(*args: object, **kwargs: object) -> FakeThread:
        thread = FakeThread()
        created_threads.append(thread)
        return thread

    monkeypatch.delenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.command_queue_worker.threading.Thread", fake_thread)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.command_queue_worker.threading.Event",
        lambda: FakeEvent(False),
    )
    existing = CommandQueueWorker(thread=FakeThread(), stop_event=FakeEvent(True))  # type: ignore[arg-type]

    worker = start_command_queue_worker(store, existing)  # type: ignore[arg-type]

    assert worker is not existing
    assert created_threads[0].started is True


def test_start_worker_respects_command_queue_opt_out(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "0")

    assert start_command_queue_worker(store, None) is None  # type: ignore[arg-type]


def test_command_queue_loop_backs_off_after_errors(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    waits: list[float] = []

    class StopAfterThreeWaits:
        def is_set(self) -> bool:
            return False

        def wait(self, seconds: float) -> bool:
            waits.append(seconds)
            return len(waits) >= 3

    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_POLL_INTERVAL_ENV, "1")
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ERROR_BACKOFF_ENV, "8")
    monkeypatch.setattr(
        command_queue,
        "poll_command_queue_once",
        lambda current_store, context: (_ for _ in ()).throw(OSError("network down")),
    )

    command_queue.command_queue_loop(
        store,
        _context(tmp_path),
        stop_event=StopAfterThreeWaits(),
    )

    assert waits == [1, 2, 4]


def test_commands_status_outputs_command_queue_state(tmp_path: Path, capsys, monkeypatch) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {"state": "idle", "last_poll_at": "2026-06-13T00:00:00+00:00"},
        "2026-06-13T00:00:00+00:00",
    )
    monkeypatch.setenv(command_queue.COMMAND_QUEUE_ENABLED_ENV, "1")

    rc = main(["guard", "commands", "status", "--guard-home", str(guard_home), "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "idle"
    assert payload["enabled"] is True
    assert payload["supported_operations"] == list(command_executors.SUPPORTED_COMMAND_OPERATIONS)


def test_doctor_repair_clears_malformed_command_queue_state(tmp_path: Path, capsys) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {"state": "result_pending", "active_job": "bad", "pending_result": {"job": "bad"}},
        "2026-06-13T00:00:00+00:00",
    )

    rc = main(["guard", "doctor", "--guard-home", str(guard_home), "--repair", "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    repair = payload["command_queue"]["repair"]
    assert repair["repaired_count"] == 2
    assert sorted(repair["repaired"]) == ["active_job", "pending_result"]
    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert state["state"] == "idle"
    assert "active_job" not in state
    assert "pending_result" not in state


def test_executor_rejects_duplicate_package_managers(tmp_path: Path) -> None:
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.install",
            "payload": {"managers": ["npm", "npm"]},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["failureCode"] == "duplicate_manager"


def test_executor_status_ignores_speculative_managers_field(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(command_executors, "package_shim_status", lambda context: {"active_managers": []})

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.status",
            "payload": {"managers": ["not-a-manager"]},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert result["data"] == {"active_managers": []}


def test_executor_dispatches_app_connect(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[str, str | None, str | None]] = []

    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        assert install_all is False
        calls.append((command, requested_harness, surface))
        return {"managed_install": {"harness": requested_harness}, "surface": surface}

    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.connect",
            "payload": {"harness": "codex", "surface": "cli"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert calls == [("install", "codex", "cli")]
    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert isinstance(result["data"], dict)


def test_executor_returns_waiting_local_confirm_for_package_shim_remove(tmp_path: Path) -> None:
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.remove",
            "payload": {"managers": ["npm"]},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard package-shims uninstall --manager npm",
        "managers": ["npm"],
        "summary": ("Run the local package-shim uninstall command on this machine to confirm removal for npm."),
    }


def test_executor_returns_waiting_local_confirm_for_package_shim_remove_all_managers(tmp_path: Path) -> None:
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.packageShims.remove",
            "payload": {},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard package-shims uninstall",
        "managers": [],
        "summary": "Run the local package-shim uninstall command on this machine to confirm removal.",
    }


def test_executor_returns_waiting_local_confirm_for_app_remove(tmp_path: Path, monkeypatch) -> None:
    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        del command, requested_harness, install_all, context, store, workspace, now, surface
        raise AssertionError("app remove should not uninstall without local confirmation")

    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.remove",
            "payload": {"harness": "codex", "surface": "cli"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard apps disconnect codex --surface cli --confirm disconnect-codex",
        "confirmation_phrase": "disconnect-codex",
        "harness": "codex",
        "summary": ("Run the local disconnect command on this machine to confirm removing Guard protection for codex."),
        "surface": "cli",
    }


def test_executor_returns_waiting_local_confirm_for_app_remove_without_surface(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fake_apply_managed_install(
        command: str,
        requested_harness: str | None,
        install_all: bool,
        context: HarnessContext,
        store: object,
        workspace: str | None,
        now: str,
        *,
        surface: str | None = None,
    ) -> dict[str, object]:
        del command, requested_harness, install_all, context, store, workspace, now, surface
        raise AssertionError("app remove should not uninstall without local confirmation")

    monkeypatch.setattr(command_executors, "apply_managed_install", fake_apply_managed_install)

    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.app.remove",
            "payload": {"harness": "codex"},
        },
        context=_context(tmp_path),
        store=FakeStore(tmp_path / "guard-home"),  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["waitingLocalConfirm"] is True
    assert result["data"] == {
        "confirm_command": "hol-guard apps disconnect codex --confirm disconnect-codex",
        "confirmation_phrase": "disconnect-codex",
        "harness": "codex",
        "summary": ("Run the local disconnect command on this machine to confirm removing Guard protection for codex."),
        "surface": None,
    }


def test_executor_resolves_local_approval_request(tmp_path: Path) -> None:
    class ApprovalStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.resolved: list[dict[str, object]] = []

        def resolve_request_with_queue_result(
            self,
            request_id: str,
            *,
            resolution_action: str,
            resolution_scope: str,
            reason: str | None,
            resolved_at: str,
        ) -> dict[str, object]:
            self.resolved.append(
                {
                    "request_id": request_id,
                    "resolution_action": resolution_action,
                    "resolution_scope": resolution_scope,
                    "reason": reason,
                    "resolved_at": resolved_at,
                }
            )
            return {"resolved": True, "resolved_request": {"request_id": request_id}}

    store = ApprovalStore(tmp_path / "guard-home")
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {"localRequestId": "request-1", "action": "allow_once", "scope": "artifact"},
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["generatedAt"] == "2026-06-13T00:00:00+00:00"
    assert result["data"]["status"] == "completed"
    assert store.resolved == [
        {
            "request_id": "request-1",
            "resolution_action": "allow",
            "resolution_scope": "artifact",
            "reason": "Guard Cloud approval command",
            "resolved_at": "2026-06-13T00:00:00+00:00",
        }
    ]


def test_executor_syncs_policy_without_local_request_id(tmp_path: Path) -> None:
    class PolicyStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.upserts: list[tuple[dict[str, object], str]] = []

        def upsert_policy(self, decision: object, generated_at: str) -> None:
            self.upserts.append((decision.to_dict(), generated_at))

    store = PolicyStore(tmp_path / "guard-home")
    result = command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "policyMemory": {
                    "scope": "workspace",
                    "reason": "approved in cloud",
                    "target": {
                        "artifactId": "pkg:npm/react",
                        "harness": "package-install",
                        "workspaceId": "workspace-1",
                    },
                },
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert result["data"]["status"] == "completed"
    assert result["data"]["localRequestId"] is None
    assert store.upserts == [
        (
            {
                "harness": "package-install",
                "scope": "workspace",
                "action": "allow",
                "artifact_id": "pkg:npm/react",
                "artifact_hash": None,
                "workspace": "workspace-1",
                "publisher": None,
                "reason": "approved in cloud",
                "owner": None,
                "source": "cloud-sync",
                "expires_at": None,
            },
            "2026-06-13T00:00:00+00:00",
        )
    ]


def test_executor_maps_unknown_cloud_policy_scope_to_artifact(tmp_path: Path) -> None:
    class PolicyStore(FakeStore):
        def __init__(self, guard_home: Path) -> None:
            super().__init__(guard_home)
            self.upserts: list[dict[str, object]] = []

        def upsert_policy(self, decision: object, generated_at: str) -> None:
            del generated_at
            self.upserts.append(decision.to_dict())

    store = PolicyStore(tmp_path / "guard-home")
    command_executors.execute_guard_command_job(
        {
            "operation": "guard.approval.resolve",
            "payload": {
                "action": "policy_sync",
                "policyMemory": {
                    "scope": "global",
                    "target": {
                        "artifactId": "pkg:npm/react",
                        "harness": "package-install",
                    },
                },
            },
        },
        context=_context(tmp_path),
        store=store,  # type: ignore[arg-type]
        now=lambda: "2026-06-13T00:00:00+00:00",
    )

    assert store.upserts[0]["scope"] == "artifact"
