"""Daemon observations report only their exact captured local state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import aibom_daemon_authority as api
from codex_plugin_scanner.guard import aibom_operation_authority as operation_api
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_aibom_operation_authority import _context, _selected
from tests.test_oauth_connection_authority import NOW, _inputs, _store


def _capture(store: GuardStore, tmp_path: Path, **kwargs: Any) -> api.AibomDaemonAttempt:
    return api.capture_aibom_daemon_attempt(
        store,
        now=NOW,
        explicit=None,
        explicit_source=None,
        fallback_home=tmp_path / "fallback",
        bind_installation=True,
        **kwargs,
    )


@pytest.mark.parametrize("source_name", ["default", "named"])
def test_valid_active_source_and_selection_capture_one_operation(tmp_path: Path, source_name: str) -> None:
    store, _ = _store(tmp_path, source=source_name)
    context = _context(store, tmp_path)
    store.set_sync_payload(operation_api.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    captured = _capture(store, tmp_path)
    assert captured.operation is not None
    assert captured.context().workspace_dir == context.workspace_dir
    assert captured.context().home_dir == context.home_dir
    payload: dict[str, object] = {"status": "synced", "synced": True, "refreshed_at": NOW}
    assert api.commit_aibom_daemon_result(store, captured, payload, now=NOW)
    assert operation_api.read_aibom_result(store, captured.operation, "aibom_inventory_daemon") == payload
    assert str(tmp_path) not in repr(captured)
    assert "synthetic-refresh" not in repr(captured)


@pytest.mark.parametrize(
    "mutation", ["unchanged", "connect", "connect-disconnect", "selection", "selection-aba", "installation"]
)
def test_absent_source_observation_cannot_survive_actual_state_transitions(tmp_path: Path, mutation: str) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    captured = _capture(store, tmp_path)
    assert captured.operation is None
    context = _context(store, tmp_path)
    if mutation in {"connect", "connect-disconnect"}:
        store.set_oauth_local_credentials(**_inputs())
        if mutation == "connect-disconnect":
            store.clear_oauth_local_credentials()
    elif mutation in {"selection", "selection-aba"}:
        store.set_sync_payload(operation_api.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
        if mutation == "selection-aba":
            store.delete_sync_payload(operation_api.INVENTORY_CONTEXT_KEY)
    elif mutation == "installation":
        store.rotate_installation_id(NOW)
    payload: dict[str, object] = {"status": "missing_workspace_context", "skipped": True, "refreshed_at": NOW}
    assert api.commit_aibom_daemon_result(store, captured, payload, now=NOW) is (mutation == "unchanged")
    assert store.get_sync_payload("aibom_inventory_daemon") == (payload if mutation == "unchanged" else None)
    assert store.get_sync_payload("aibom_sync_summary") is None
    assert store.get_sync_payload("aibom_guard_events_backoff") is None


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "synced"},
        {"status": "error", "synced": True},
        {"status": "recently_synced"},
        {"status": "error", "synced": 1},
        {"status": "error", "synced": "true"},
        {"status": "error", "synced": [True]},
        {"status": "error", "synced": 0},
        {"status": "error", "synced": None},
    ],
)
def test_unavailable_observation_cannot_report_success(tmp_path: Path, payload: dict[str, object]) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    captured = _capture(store, tmp_path)
    with pytest.raises(ValueError, match="cannot report successful"):
        api.commit_aibom_daemon_result(store, captured, payload, now=NOW)
    assert store.get_sync_payload("aibom_inventory_daemon") is None


@pytest.mark.parametrize("failure", [False, True])
def test_actual_reset_interval_observation_is_bound_through_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: bool
) -> None:
    store, _ = _store(tmp_path)
    captured: list[api.AibomDaemonAttempt] = []
    payload: dict[str, object] = {"status": "not_configured", "refreshed_at": NOW}
    original = store.clear_policy_bundle_authority

    def while_pending(*args: Any, **kwargs: Any) -> None:
        current = _capture(store, tmp_path)
        assert current.operation is None
        captured.append(current)
        assert api.commit_aibom_daemon_result(store, current, payload, now=NOW)
        if failure:
            raise RuntimeError("controlled reset interruption")
        original(*args, **kwargs)

    monkeypatch.setattr(store, "clear_policy_bundle_authority", while_pending)
    if failure:
        with pytest.raises(RuntimeError, match="controlled reset interruption"):
            store.clear_cloud_sync_state_for_reconnect(now=NOW)
        assert api.commit_aibom_daemon_result(store, captured[0], payload, now=NOW)
    else:
        store.clear_cloud_sync_state_for_reconnect(now=NOW)
        assert not api.commit_aibom_daemon_result(store, captured[0], payload, now=NOW)
    monkeypatch.setattr(store, "clear_policy_bundle_authority", original)
    store.clear_cloud_sync_state_for_reconnect(now=NOW)
    assert not api.commit_aibom_daemon_result(store, captured[0], payload, now=NOW)


@pytest.mark.parametrize("raw", ["{", "null", "[]", '{"home_dir":null}', "{}"])
def test_malformed_selection_can_only_report_its_exact_unavailable_state(tmp_path: Path, raw: str) -> None:
    store, _ = _store(tmp_path)
    with store._connect() as connection:
        connection.execute("insert into sync_state values (?, ?, ?)", (operation_api.INVENTORY_CONTEXT_KEY, raw, NOW))
    captured = _capture(store, tmp_path)
    assert captured.operation is None
    payload: dict[str, object] = {"status": "error", "refreshed_at": NOW}
    assert api.commit_aibom_daemon_result(store, captured, payload, now=NOW)
    store.set_sync_payload(operation_api.INVENTORY_CONTEXT_KEY, _selected(_context(store, tmp_path)), NOW)
    assert not api.commit_aibom_daemon_result(store, captured, payload, now=NOW)
    assert _capture(store, tmp_path).operation is not None


def test_identical_normalized_selection_does_not_starve_absent_source_result(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    context = _context(store, tmp_path)
    selected = _selected(context)
    store.set_sync_payload(operation_api.INVENTORY_CONTEXT_KEY, selected, NOW)
    captured = _capture(store, tmp_path)
    store.set_sync_payload(operation_api.INVENTORY_CONTEXT_KEY, dict(reversed(list(selected.items()))), NOW)
    assert api.commit_aibom_daemon_result(store, captured, {"status": "not_configured"}, now=NOW)
    store.set_sync_payload(
        operation_api.INVENTORY_CONTEXT_KEY, {**selected, "workspace_dir": str(tmp_path / "unused/../workspace")}, NOW
    )
    assert api.commit_aibom_daemon_result(store, captured, {"status": "not_configured"}, now=NOW)


def test_terminal_and_companion_roll_back_together(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    captured = _capture(store, tmp_path)
    before = store.get_sync_payload("aibom_inventory_result_bindings")
    original = api._write

    def write(connection: Any, key: str, payload: object, now: str) -> None:
        if key == "aibom_inventory_result_bindings":
            raise RuntimeError("controlled companion failure")
        original(connection, key, payload, now)

    monkeypatch.setattr(api, "_write", write)
    with pytest.raises(RuntimeError, match="controlled companion failure"):
        api.commit_aibom_daemon_result(store, captured, {"status": "not_configured"}, now=NOW)
    assert store.get_sync_payload("aibom_inventory_daemon") is None
    assert store.get_sync_payload("aibom_inventory_result_bindings") == before


@pytest.mark.parametrize("restore", [False, True])
def test_external_secret_recovery_invalidates_unavailable_observation_without_metadata_change(
    tmp_path: Path, restore: bool
) -> None:
    store, _ = _store(tmp_path)
    backend = store._oauth_secret_store
    secret_ref = store._oauth_local_credentials_ref
    secret = backend.get_secret(secret_ref)
    assert secret is not None
    metadata = store.get_sync_payload(store._oauth_local_credentials_state_key)
    backend.delete_secret(secret_ref)
    store._clear_oauth_secret_payload_cache()
    assert store.capture_oauth_connection(allow_primary=True, allow_recoverable=True) is None
    captured = _capture(store, tmp_path)
    assert captured.operation is None
    if restore:
        backend.set_secret(secret_ref, secret)
    payload: dict[str, object] = {"status": "auth_expired"}
    assert api.commit_aibom_daemon_result(store, captured, payload, now=NOW) is (not restore)
    assert store.get_sync_payload(store._oauth_local_credentials_state_key) == metadata
    assert store.get_sync_payload("aibom_inventory_daemon") == (None if restore else payload)


@pytest.mark.parametrize("transition", ["unchanged", "refresh", "reconnect"])
def test_explicit_daemon_roots_require_original_connection_authority(tmp_path: Path, transition: str) -> None:
    store, inputs = _store(tmp_path)
    explicit = _context(store, tmp_path, "explicit")
    saved = _context(store, tmp_path, "saved")
    store.set_sync_payload(operation_api.INVENTORY_CONTEXT_KEY, _selected(saved), NOW)
    source = store.capture_oauth_connection()
    assert source is not None
    if transition == "refresh":
        rotated: dict[str, Any] = {**inputs, "access_token": "rotated-synthetic"}
        store.set_oauth_local_credentials(**rotated, expected_connection=source)
    elif transition == "reconnect":
        store.clear_oauth_local_credentials()
        store.set_oauth_local_credentials(**inputs)
    captured = api.capture_aibom_daemon_attempt(
        store,
        now=NOW,
        explicit=explicit,
        explicit_source=source,
        fallback_home=tmp_path / "fallback",
        bind_installation=True,
    )
    assert captured.operation is not None
    assert captured.context().workspace_dir == (
        saved.workspace_dir if transition == "reconnect" else explicit.workspace_dir
    )
    assert api.commit_aibom_daemon_result(store, captured, {"status": "synced", "synced": True}, now=NOW)


def test_actual_child_selection_write_invalidates_daemon_observation(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    captured = _capture(store, tmp_path)
    code = """
import socket,sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
def denied(*args,**kwargs):raise AssertionError('Unexpected raw network')
socket.create_connection=denied
socket.socket.connect=denied
store=GuardStore(Path(sys.argv[1]),allow_system_keyring=False)
store.set_sync_payload('aibom_inventory_context',{'home_dir':sys.argv[2]},'2026-06-01T00:00:00Z')
"""
    child = subprocess.run(
        [sys.executable, "-c", code, str(store.guard_home), str(tmp_path / "other")],
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    assert child.returncode == 0 and child.stderr == ""
    assert not api.commit_aibom_daemon_result(store, captured, {"status": "not_configured"}, now=NOW)
    assert store.get_sync_payload("aibom_inventory_daemon") is None
