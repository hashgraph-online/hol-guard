"""Daemon terminal results retain the same admitted source and selection."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import aibom_operation_authority as authority
from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_aibom_operation_authority import _context, _selected
from tests.test_inventory_consumer_authority import Response, _fixture, _offline
from tests.test_oauth_connection_authority import NOW, _store

# Retain the actual pre-I/O network guard used by the consumer proof.
assert _offline is not None


class _OneIteration:
    def __init__(self) -> None:
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return False

    def wait(self, interval: float) -> bool:
        self.waits.append(interval)
        return True


def _daemon(store: GuardStore, *, home: Path | None = None, workspace: Path | None = None) -> Any:
    # Exercise the actual worker and persistence methods without opening an
    # unrelated dashboard listener or starting the other daemon workers.
    daemon = cast(Any, object.__new__(server.GuardDaemonServer))
    daemon._server = SimpleNamespace(store=store)
    daemon._aibom_home_dir = home
    daemon._aibom_workspace_dir = workspace
    daemon._aibom_context_source = store.capture_oauth_connection() if workspace is not None else None
    daemon._aibom_refresh_interval_seconds = 60
    daemon._aibom_refresh_backoff_seconds = 0.05
    daemon._shutdown_started = _OneIteration()
    return daemon


def _loop(daemon: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "_now", lambda: NOW)
    daemon._refresh_aibom_inventory_loop()
    assert len(daemon._shutdown_started.waits) == 1


@pytest.mark.parametrize("outcome", ["missing", "success", "auth", "not-configured", "error"])
@pytest.mark.parametrize(
    "mutation", ["unchanged", "source-aba", "selection-aba", "refresh", "installation", "unrelated"]
)
def test_all_five_terminal_paths_commit_only_their_captured_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str, mutation: str
) -> None:
    store, inputs = _store(tmp_path)
    context = _context(store, tmp_path)
    selected = _selected(context)
    if outcome != "missing":
        store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, selected, NOW)
    sentinel = {"status": "prior"}
    store.set_sync_payload("aibom_inventory_daemon", sentinel, NOW)
    store.set_sync_payload("receipt_sync_cursor", {"last_rowid": 17}, NOW)
    daemon = _daemon(store)
    calls: list[str] = []

    def sync(_store: GuardStore, **kwargs: Any) -> dict[str, object]:
        calls.append(outcome)
        assert kwargs["operation"].workspace_id == "synthetic-workspace"
        if outcome == "auth":
            raise runner.GuardSyncAuthorizationExpiredError("controlled expired authorization")
        if outcome == "not-configured":
            raise runner.GuardSyncNotConfiguredError("controlled unavailable authorization")
        if outcome == "error":
            raise RuntimeError("controlled collection failure")
        return {"synced": True, "snapshots": 2, "accepted": 2}

    commit = server.commit_aibom_daemon_result
    commits: list[bool] = []

    def committing(*args: Any, **kwargs: Any) -> bool:
        if mutation == "source-aba":
            store.clear_oauth_local_credentials()
            store.set_oauth_local_credentials(**inputs)
        elif mutation == "selection-aba":
            prior = store.get_sync_payload(authority.INVENTORY_CONTEXT_KEY)
            store.set_sync_payload(
                authority.INVENTORY_CONTEXT_KEY, {**selected, "workspace_dir": str(tmp_path / "other")}, NOW
            )
            if prior is None:
                store.delete_sync_payload(authority.INVENTORY_CONTEXT_KEY)
            else:
                store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, prior, NOW)
        elif mutation == "refresh":
            before = store.capture_oauth_connection()
            assert before is not None
            refreshed: dict[str, Any] = {**inputs, "access_token": "rotated-synthetic"}
            store.set_oauth_local_credentials(**refreshed, expected_connection=before)
        elif mutation == "installation":
            store.rotate_installation_id(NOW)
        elif mutation == "unrelated":
            store.set_sync_payload("receipt_sync_cursor", {"last_rowid": 18}, NOW)
        result = commit(*args, **kwargs)
        commits.append(result)
        return result

    monkeypatch.setattr(server, "_sync_aibom_snapshots_if_due_admitted", sync)
    monkeypatch.setattr(server, "commit_aibom_daemon_result", committing)
    _loop(daemon, monkeypatch)
    valid = mutation in {"unchanged", "refresh", "unrelated"}
    assert commits == [valid]
    result = store.get_sync_payload("aibom_inventory_daemon")
    if valid:
        assert isinstance(result, dict)
        assert (
            result["status"]
            == {
                "missing": "missing_workspace_context",
                "success": "synced",
                "auth": "auth_expired",
                "not-configured": "not_configured",
                "error": "error",
            }[outcome]
        )
        if outcome == "auth":
            assert result["message"] == "controlled expired authorization"
        if outcome == "error":
            assert result["error"] == "controlled collection failure"
    else:
        assert result == sentinel
    assert calls == ([] if outcome == "missing" else [outcome])
    assert daemon._shutdown_started.waits == ([60] if outcome == "success" and valid else [0.05])
    assert store.get_sync_payload("receipt_sync_cursor") == {"last_rowid": 18 if mutation == "unrelated" else 17}
    assert store.get_sync_payload("aibom_sync_summary") is None


@pytest.mark.parametrize("phase", ["unchanged", "collection", "response", "terminal", "identical", "refresh"])
def test_real_daemon_collection_authentication_upload_and_terminal_are_one_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    from codex_plugin_scanner.guard import aibom_cli

    store, inputs, context = _fixture(tmp_path)
    selected = _selected(context)
    store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, selected, NOW)
    sentinel = {"status": "prior"}
    store.set_sync_payload("aibom_inventory_daemon", sentinel, NOW)
    daemon = _daemon(store)
    requests: list[object] = []
    collect = aibom_cli.collect_aibom_snapshots
    commit = server.commit_aibom_daemon_result

    def change() -> None:
        store.set_sync_payload(
            authority.INVENTORY_CONTEXT_KEY, {**selected, "workspace_dir": str(tmp_path / "other")}, NOW
        )

    def collection(*args: Any, **kwargs: Any):
        result = collect(*args, **kwargs)
        if phase == "collection":
            change()
        return result

    def transport(request: Any, *, timeout: int):
        assert timeout == 90
        requests.append(request)
        response = Response(request)
        if phase == "response":
            change()
        elif phase == "identical":
            store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, dict(selected), NOW)
        elif phase == "refresh":
            before = store.capture_oauth_connection()
            assert before is not None
            refreshed: dict[str, Any] = {**inputs, "access_token": "rotated-synthetic"}
            store.set_oauth_local_credentials(**refreshed, expected_connection=before)
        return response

    def committing(*args: Any, **kwargs: Any):
        if phase == "terminal":
            change()
        return commit(*args, **kwargs)

    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", collection)
    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(server, "commit_aibom_daemon_result", committing)
    _loop(daemon, monkeypatch)
    valid = phase in {"unchanged", "identical", "refresh"}
    terminal = store.get_sync_payload("aibom_inventory_daemon")
    if valid:
        assert isinstance(terminal, dict)
        assert terminal["synced"] is True
        assert terminal["status"] == "synced"
        assert terminal["accepted"] == terminal["snapshots"]
    else:
        assert terminal == sentinel
    assert len(requests) == (0 if phase == "collection" else 1)
    assert daemon._shutdown_started.waits == ([60] if valid else [0.05])


@pytest.mark.parametrize("source_name", ["default", "named"])
@pytest.mark.parametrize("change", ["unchanged", "refresh", "reconnect", "workspace"])
def test_constructor_context_persistence_is_bound_to_actual_source(
    tmp_path: Path, source_name: str, change: str
) -> None:
    store, inputs = _store(tmp_path, source=source_name)
    context = _context(store, tmp_path)
    daemon = _daemon(store, home=context.home_dir, workspace=context.workspace_dir)
    if change == "refresh":
        before = store.capture_oauth_connection()
        assert before is not None
        refreshed: dict[str, Any] = {**inputs, "access_token": "new-synthetic"}
        store.set_oauth_local_credentials(**refreshed, expected_connection=before)
    elif change in {"reconnect", "workspace"}:
        replacement: dict[str, Any] = {
            **inputs,
            "workspace_id": "other" if change == "workspace" else inputs["workspace_id"],
        }
        store.set_oauth_local_credentials(**replacement)
    daemon._persist_aibom_inventory_context()
    assert store.get_sync_payload(authority.INVENTORY_CONTEXT_KEY) == (
        _selected(context) if change in {"unchanged", "refresh"} else None
    )


@pytest.mark.parametrize("failure", ["admission", "capture"])
def test_failure_before_capture_cannot_overwrite_another_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    store, _ = _store(tmp_path)
    daemon = _daemon(store)
    sentinel = {"status": "prior", "synced": True}
    store.set_sync_payload("aibom_inventory_daemon", sentinel, NOW)

    def fail(*args: Any, **kwargs: Any):
        raise TimeoutError("controlled unavailable admission")

    if failure == "admission":
        monkeypatch.setattr(store, "hold_aibom_sync_lock", fail)
    else:
        monkeypatch.setattr(server, "capture_aibom_daemon_attempt", fail)
    _loop(daemon, monkeypatch)
    assert store.get_sync_payload("aibom_inventory_daemon") == sentinel
    assert daemon._shutdown_started.waits == [0.05]


@pytest.mark.parametrize("outcome", ["expired", "provider-error"])
@pytest.mark.parametrize("replace_source", [False, True])
def test_actual_provider_failure_retains_category_only_for_its_original_daemon_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str, replace_source: bool
) -> None:
    import io
    import urllib.error
    from email.message import Message

    store, inputs, context = _fixture(tmp_path)
    expired: dict[str, Any] = {**inputs, "access_token_expires_at": "2000-01-01T00:00:00Z"}
    store.set_oauth_local_credentials(**expired)
    store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    sentinel = {"status": "prior"}
    store.set_sync_payload("aibom_inventory_daemon", sentinel, NOW)
    daemon = _daemon(store)
    calls: list[int] = []

    def transport(request: Any, *, timeout: int):
        assert timeout == 20
        assert request.full_url.endswith("/oauth/token")
        calls.append(timeout)
        if replace_source:
            store.set_oauth_local_credentials(**inputs)
        raise urllib.error.HTTPError(
            request.full_url,
            400 if outcome == "expired" else 503,
            "controlled",
            Message(),
            io.BytesIO(b'{"error":"invalid_grant"}' if outcome == "expired" else b"{}"),
        )

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    _loop(daemon, monkeypatch)
    terminal = store.get_sync_payload("aibom_inventory_daemon")
    if replace_source:
        assert terminal == sentinel
    else:
        assert isinstance(terminal, dict)
        assert terminal["status"] == ("auth_expired" if outcome == "expired" else "error")
    assert len(calls) == (2 if outcome == "expired" and not replace_source else 1)
    assert daemon._shutdown_started.waits == [0.05]
    assert store.get_sync_payload("aibom_sync_summary") is None


def test_actual_daemon_second_iteration_uses_bound_freshness_without_duplicate_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _inputs, context = _fixture(tmp_path)
    store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    daemon = _daemon(store)
    requests: list[object] = []

    def transport(request: Any, *, timeout: int):
        assert timeout == 90
        requests.append(request)
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    _loop(daemon, monkeypatch)
    first_summary = store.get_sync_payload("aibom_sync_summary")
    daemon._shutdown_started = _OneIteration()
    _loop(daemon, monkeypatch)
    terminal = store.get_sync_payload("aibom_inventory_daemon")
    assert isinstance(terminal, dict)
    assert terminal["status"] == "recently_synced"
    assert terminal["synced"] is False
    assert terminal["skipped"] is True
    assert store.get_sync_payload("aibom_sync_summary") == first_summary
    assert len(requests) == 1
    assert daemon._shutdown_started.waits == [60]


@pytest.mark.parametrize("failed", [False, True])
def test_daemon_keeps_actual_inventory_admission_through_success_and_error_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed: bool
) -> None:
    import threading

    from codex_plugin_scanner.guard import aibom_cli
    from tests.test_aibom_sync_admission import _finish, _observe_waiter, _start

    store, _inputs, context = _fixture(tmp_path)
    store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    daemon = _daemon(store)
    entered = threading.Event()
    release = threading.Event()
    blocked = _observe_waiter(monkeypatch)
    commit = server.commit_aibom_daemon_result
    requests: list[object] = []

    def sync(*args: Any, **kwargs: Any) -> dict[str, object]:
        if failed:
            raise RuntimeError("controlled terminal error")
        return {"synced": True}

    def committing(*args: Any, **kwargs: Any) -> bool:
        entered.set()
        assert release.wait(10)
        return commit(*args, **kwargs)

    def transport(request: Any, *, timeout: int):
        assert timeout == 90
        requests.append(request)
        return Response(request)

    def first_iteration() -> dict[str, object]:
        daemon._refresh_aibom_inventory_loop()
        return {"done": True}

    monkeypatch.setattr(server, "_now", lambda: NOW)
    monkeypatch.setattr(server, "_sync_aibom_snapshots_if_due_admitted", sync)
    monkeypatch.setattr(server, "commit_aibom_daemon_result", committing)
    monkeypatch.setattr(runner, "managed_urlopen", transport)
    first = _start(first_iteration, "first")
    second = None
    try:
        assert entered.wait(10)
        second = _start(
            lambda: aibom_cli.sync_aibom_snapshots_if_due(
                peer, generated_at=NOW, home_dir=context.home_dir, workspace_dir=context.workspace_dir
            )
        )
        assert blocked.wait(10)
        assert requests == []
        with peer.hold_oauth_credential_lock(timeout_seconds=0):
            assert peer.get_sync_payload("aibom_inventory_daemon") is None
    finally:
        release.set()
        first[0].join(timeout=10)
        if second is not None:
            second[0].join(timeout=10)
    assert _finish(first) == {"done": True}
    assert second is not None
    assert _finish(second)["synced"] is True
    assert len(requests) == 1
    terminal = store.get_sync_payload("aibom_inventory_daemon")
    assert isinstance(terminal, dict)
    assert terminal["status"] == ("error" if failed else "synced")
