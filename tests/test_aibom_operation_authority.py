"""Actual selection mutations and atomic inventory result authority."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import aibom_operation_authority as api
from codex_plugin_scanner.guard import store_cloud_events
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_oauth_connection_authority import NOW, _store


def _context(store: GuardStore, tmp_path: Path, root: str = "workspace") -> HarnessContext:
    return HarnessContext(tmp_path / "operator", tmp_path / root, store.guard_home)


def _selected(context: HarnessContext) -> dict[str, object]:
    return {
        "home_dir": str(context.home_dir),
        "workspace_dir": str(context.workspace_dir),
        "workspace_id": "synthetic-workspace",
    }


def _operation(store: GuardStore, context: HarnessContext, *, bound: bool = True) -> api.AibomOperation:
    captured = api.capture_aibom_operation(store, context, now=NOW, bind_installation=bound)
    assert captured is not None
    return captured


def _raw(store: GuardStore, key: str, value: str | None) -> None:
    with store._connect() as connection:
        if value is None:
            connection.execute("delete from sync_state where state_key = ?", (key,))
        else:
            connection.execute(
                "insert into sync_state values (?, ?, ?) "
                "on conflict(state_key) do update set payload_json=excluded.payload_json",
                (key, value, NOW),
            )


@pytest.mark.parametrize("shape", ["absent", "home-only", "workspace-only", "workspace-bound", "complete"])
def test_legacy_context_adoption_preserves_public_payload(tmp_path: Path, shape: str) -> None:
    store, _ = _store(tmp_path)
    context = _context(store, tmp_path)
    selected = _selected(context)
    if shape == "home-only":
        selected = {"home_dir": selected["home_dir"]}
    elif shape == "workspace-only":
        selected = {"workspace_dir": selected["workspace_dir"]}
    elif shape == "workspace-bound":
        selected.pop("home_dir")
    if shape != "absent":
        _raw(store, api.INVENTORY_CONTEXT_KEY, json.dumps(selected))
    before = store.get_sync_payload(api.INVENTORY_CONTEXT_KEY)
    first = _operation(store, context)
    second = _operation(store, context)
    assert first == second
    assert store.get_sync_payload(api.INVENTORY_CONTEXT_KEY) == before
    assert api.aibom_operation_is_current(store, first)


@pytest.mark.parametrize("mutation", ["identical", "normalized", "cursor", "other-source", "refresh"])
def test_semantic_identity_and_unrelated_writes_do_not_starve_operation(tmp_path: Path, mutation: str) -> None:
    store, inputs = _store(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    context = _context(store, tmp_path)
    selected = _selected(context)
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, selected, NOW)
    captured = _operation(store, context)
    if mutation == "identical":
        peer.set_sync_payload(api.INVENTORY_CONTEXT_KEY, dict(selected), "2026-06-01T00:01:00Z")
    elif mutation == "normalized":
        peer.set_sync_payload(
            api.INVENTORY_CONTEXT_KEY, {**selected, "workspace_dir": str(tmp_path / "x/../workspace")}, NOW
        )
    elif mutation == "cursor":
        peer.set_sync_payload("receipt_cursor", {"cursor": 42}, NOW)
    elif mutation == "other-source":
        GuardStore(store.guard_home, source="other", allow_system_keyring=False).set_oauth_local_credentials(**inputs)
    else:
        rotated: dict[str, Any] = {**inputs, "access_token": "rotated"}
        peer.set_oauth_local_credentials(**rotated, expected_connection=captured.connection)
    assert api.aibom_operation_is_current(store, captured)
    summary = {"synced": True, "synced_at": NOW}
    assert api.commit_aibom_results(store, captured, {"aibom_sync_summary": summary}, now=NOW)
    assert api.read_aibom_result(store, _operation(store, context), "aibom_sync_summary") == summary


@pytest.mark.parametrize(
    "mutation",
    ["change", "aba", "delete", "bulk-delete", "invalid", "connection", "disconnect", "reset", "installation"],
)
def test_supported_authority_changes_refuse_stale_results(tmp_path: Path, mutation: str) -> None:
    store, inputs = _store(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    context = _context(store, tmp_path)
    selected = _selected(context)
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, selected, NOW)
    captured = _operation(store, context)
    old = {"synced": True, "synced_at": NOW}
    assert api.commit_aibom_results(store, captured, {"aibom_sync_summary": old}, now=NOW)
    if mutation in {"change", "aba"}:
        peer.set_sync_payload(api.INVENTORY_CONTEXT_KEY, {**selected, "workspace_dir": str(tmp_path / "other")}, NOW)
        if mutation == "aba":
            peer.set_sync_payload(api.INVENTORY_CONTEXT_KEY, selected, NOW)
    elif mutation == "delete":
        peer.delete_sync_payload(api.INVENTORY_CONTEXT_KEY)
    elif mutation == "bulk-delete":
        peer.delete_sync_payloads(["receipt_cursor", api.INVENTORY_CONTEXT_KEY])
    elif mutation == "invalid":
        peer.set_sync_payload(api.INVENTORY_CONTEXT_KEY, {"workspace_dir": []}, NOW)
    elif mutation == "connection":
        peer.set_oauth_local_credentials(**inputs)
    elif mutation == "disconnect":
        peer.clear_oauth_local_credentials()
    elif mutation == "reset":
        peer.clear_cloud_sync_state_for_reconnect(now=NOW)
    elif mutation == "installation":
        peer.rotate_installation_id(NOW)
    before = store.get_sync_payload("aibom_sync_summary")
    assert not api.aibom_operation_is_current(store, captured)
    with pytest.raises(RuntimeError, match="context changed"):
        api.require_current_aibom_operation(store, captured)
    assert not api.commit_aibom_results(store, captured, {"aibom_sync_summary": {"synced": False}}, now=NOW)
    assert store.get_sync_payload("aibom_sync_summary") == before
    assert api.read_aibom_result(store, captured, "aibom_sync_summary") is None


def test_explicit_roots_do_not_replace_persisted_selection_or_its_freshness(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    explicit = _context(store, tmp_path, "explicit")
    selected_context = _context(store, tmp_path, "selected")
    selected = _selected(selected_context)
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, selected, NOW)
    operation = _operation(store, explicit)
    summary = {"synced": True, "synced_at": NOW}
    assert api.commit_aibom_results(store, operation, {"aibom_sync_summary": summary}, now=NOW)
    assert store.get_sync_payload(api.INVENTORY_CONTEXT_KEY) == selected
    assert api.read_aibom_result(store, _operation(store, explicit), "aibom_sync_summary") == summary
    assert api.read_aibom_result(store, _operation(store, selected_context), "aibom_sync_summary") is None


def test_backoff_is_connection_scoped_not_a_claim_of_collected_roots(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    first = _operation(store, _context(store, tmp_path, "first"))
    backoff = {"unavailable_at": NOW}
    assert api.commit_aibom_results(store, first, {"aibom_guard_events_backoff": backoff}, now=NOW)
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, _selected(_context(store, tmp_path, "second")), NOW)
    second = _operation(store, _context(store, tmp_path, "second"))
    assert api.read_aibom_result(store, second, "aibom_guard_events_backoff") == backoff
    store.set_oauth_local_credentials(**inputs)
    assert api.read_aibom_result(store, _operation(store, second.context()), "aibom_guard_events_backoff") is None


def test_named_source_uses_its_own_workspace_and_generation(tmp_path: Path) -> None:
    store, _ = _store(tmp_path, source="secondary")
    assert store.get_cloud_workspace_id() is None
    operation = _operation(store, _context(store, tmp_path))
    assert operation.workspace_id == "synthetic-workspace"
    assert operation.connection.credential_key.endswith(":secondary")
    assert api.aibom_operation_is_current(store, operation)


@pytest.mark.parametrize("bound", [False, True])
def test_installation_authority_is_applicable_only_when_captured(tmp_path: Path, bound: bool) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path), bound=bound)
    store.rotate_installation_id(NOW)
    assert api.aibom_operation_is_current(store, operation) is (not bound)


@pytest.mark.parametrize("mutation", ["overwrite", "delete", "malformed", "duplicate", "legacy"])
def test_unbound_summary_cannot_borrow_companion(tmp_path: Path, mutation: str) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    assert api.commit_aibom_results(store, operation, {"aibom_sync_summary": {"synced": False}}, now=NOW)
    if mutation == "overwrite":
        store.set_sync_payload("aibom_sync_summary", {"synced": True}, NOW)
    elif mutation == "delete":
        store.delete_sync_payload("aibom_sync_summary")
    elif mutation == "malformed":
        _raw(store, "aibom_sync_summary", "[")
    elif mutation == "duplicate":
        _raw(store, "aibom_sync_summary", '{"synced":true,"synced":false}')
    else:
        _raw(store, api._RESULT_BINDINGS_KEY, None)
    assert api.read_aibom_result(store, operation, "aibom_sync_summary") is None


@pytest.mark.parametrize("key", [api._CONTEXT_AUTHORITY_KEY, api._CONTEXT_ADOPTED_KEY])
@pytest.mark.parametrize(
    "value", [None, "[", "[]", '{"version":true}', '{"version":1,"extra":0}', '{"version":1,"version":1}']
)
def test_adopted_metadata_loss_or_corruption_never_reinitializes(tmp_path: Path, key: str, value: str | None) -> None:
    store, _ = _store(tmp_path)
    context = _context(store, tmp_path)
    captured = _operation(store, context)
    _raw(store, key, value)
    assert not api.aibom_operation_is_current(store, captured)
    assert api.capture_aibom_operation(store, context, now=NOW, bind_installation=True) is None
    # An explicit new valid selection establishes fresh authority; old work never revives.
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    assert _operation(store, context) != captured
    assert not api.aibom_operation_is_current(store, captured)


@pytest.mark.parametrize(
    "payload", [{}, [], {"home_dir": ""}, {"home_dir": 7}, {"workspace_id": " "}, {"unknown": "/tmp"}]
)
def test_malformed_legacy_selection_is_not_absence(tmp_path: Path, payload: Any) -> None:
    store, _ = _store(tmp_path)
    _raw(store, api.INVENTORY_CONTEXT_KEY, json.dumps(payload))
    assert api.capture_aibom_operation(store, _context(store, tmp_path), now=NOW, bind_installation=False) is None


@pytest.mark.parametrize("key", sorted(api._PRIVATE_KEYS))
@pytest.mark.parametrize("method", ["set", "unlocked-set", "delete", "unlocked-delete", "reserve"])
def test_generic_mutation_cannot_remove_or_forge_private_metadata(tmp_path: Path, key: str, method: str) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    before = store.get_sync_payload(key)
    with pytest.raises(ValueError, match="dedicated mutation"):
        if method == "set":
            store.set_sync_payload(key, {}, NOW)
        elif method == "unlocked-set":
            store._set_sync_payload_unlocked(key, {}, NOW)
        elif method == "delete":
            store.delete_sync_payloads([api.INVENTORY_CONTEXT_KEY, key])
        elif method == "unlocked-delete":
            store._delete_sync_payloads_unlocked([api.INVENTORY_CONTEXT_KEY, key])
        else:
            store.reserve_sync_sequence(key, "counter", NOW)
    assert store.get_sync_payload(key) == before
    assert api.aibom_operation_is_current(store, operation)


def test_deleted_selection_keeps_tombstone_and_does_not_revive_aba(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    context = _context(store, tmp_path)
    absent = _operation(store, context)
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    selected = _operation(store, context)
    assert store.delete_sync_payload(api.INVENTORY_CONTEXT_KEY) is None
    tombstone = _operation(store, context)
    assert not api.aibom_operation_is_current(store, absent)
    assert not api.aibom_operation_is_current(store, selected)
    store.delete_sync_payload(api.INVENTORY_CONTEXT_KEY)
    assert _operation(store, context) == tombstone
    assert store.get_sync_payload(api._CONTEXT_ADOPTED_KEY) == {"version": 1}


def test_all_summary_companions_rollback_together(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    old = {"aibom_sync_summary": {"synced": True}, "aibom_inventory_daemon": {"state": "idle"}}
    assert api.commit_aibom_results(store, operation, old, now=NOW)
    before = store.get_sync_payload(api._RESULT_BINDINGS_KEY)
    with store._connect() as connection:
        connection.execute(
            "create trigger refuse_daemon before update on sync_state "
            "when new.state_key = 'aibom_inventory_daemon' "
            "begin select raise(abort, 'controlled refusal'); end"
        )
    with pytest.raises(sqlite3.IntegrityError, match="controlled refusal"):
        api.commit_aibom_results(store, operation, {key: {"changed": True} for key in old}, now=NOW)
    for key, payload in old.items():
        assert store.get_sync_payload(key) == payload
        assert api.read_aibom_result(store, operation, key) == payload
    assert store.get_sync_payload(api._RESULT_BINDINGS_KEY) == before


def test_context_and_authority_rollback_together(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    context = _context(store, tmp_path)
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    before = _operation(store, context)
    with store._connect() as connection:
        connection.execute(
            "create trigger refuse_selection before update on sync_state "
            "when new.state_key = 'aibom_inventory_context' "
            "begin select raise(abort, 'controlled refusal'); end"
        )
    with pytest.raises(sqlite3.IntegrityError, match="controlled refusal"):
        store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, {"home_dir": str(tmp_path / "other")}, NOW)
    assert _operation(store, context) == before


def test_representation_and_context_copy_do_not_expose_or_mutate_operation(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    context = HarnessContext(
        tmp_path / "operator", tmp_path / "workspace", store.guard_home, {"tool": "private-executable"}
    )
    operation = _operation(store, context)
    shown = repr(operation) + str(operation)
    for sentinel in [inputs["refresh_token"], inputs["dpop_private_key_pem"], str(tmp_path), "private-executable"]:
        assert sentinel not in shown
    copied = operation.context()
    assert isinstance(copied.executable_overrides, dict)
    copied.executable_overrides["tool"] = "changed"
    assert operation.context().executable_overrides["tool"] == "private-executable"
    assert api.aibom_operation_is_current(store, operation)


def test_wrong_store_or_unknown_result_key_cannot_commit(tmp_path: Path) -> None:
    first, _ = _store(tmp_path / "first")
    second, _ = _store(tmp_path / "second")
    context = _context(first, tmp_path)
    operation = _operation(first, context)
    with pytest.raises(ValueError, match="different local store"):
        api.capture_aibom_operation(second, context, now=NOW, bind_installation=False)
    assert not api.commit_aibom_results(second, operation, {"aibom_sync_summary": {}}, now=NOW)
    with pytest.raises(ValueError, match="result state key"):
        api.commit_aibom_results(first, operation, {"receipt_cursor": {"cursor": 9}}, now=NOW)
    assert first.get_sync_payload("receipt_cursor") is None


@pytest.mark.parametrize("fails", [False, True])
def test_pending_reset_refuses_new_operations_and_old_commits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    store, _ = _store(tmp_path)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    actual_clear = store.clear_policy_bundle_authority
    observations: list[object] = []

    def during_reset(*args: Any, **kwargs: Any) -> None:
        observations.append(api.capture_aibom_operation(store, context, now=NOW, bind_installation=True))
        observations.append(
            api.commit_aibom_results(store, operation, {"aibom_inventory_daemon": {"state": "done"}}, now=NOW)
        )
        if fails:
            raise RuntimeError("controlled reset failure")
        actual_clear(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(store, "clear_policy_bundle_authority", during_reset)
        if fails:
            with pytest.raises(RuntimeError, match="controlled reset failure"):
                store.clear_cloud_sync_state_for_reconnect(now=NOW)
        else:
            store.clear_cloud_sync_state_for_reconnect(now=NOW)
    assert observations == [None, False]
    assert not api.aibom_operation_is_current(store, operation)
    if fails:
        assert api.capture_aibom_operation(store, context, now=NOW, bind_installation=True) is None
    else:
        assert _operation(store, context) != operation
    assert store.get_sync_payload("aibom_inventory_daemon") is None


@pytest.mark.parametrize("mutation", ["selection", "installation"])
def test_final_sql_fence_observes_changes_after_source_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store, _ = _store(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    actual = api._source_current

    def between_source_and_transaction(current_store: GuardStore, captured: api.AibomOperation) -> bool:
        current = actual(current_store, captured)
        if mutation == "selection":
            # Deliberate raw SQL mutation models an independent writer beyond the
            # credential-lock API, without reentering that non-reentrant lock.
            _raw(peer, api.INVENTORY_CONTEXT_KEY, json.dumps(_selected(context)))
        else:
            peer.rotate_installation_id(NOW)
        return current

    monkeypatch.setattr(api, "_source_current", between_source_and_transaction)
    assert not api.commit_aibom_results(store, operation, {"aibom_sync_summary": {"synced": True}}, now=NOW)
    assert store.get_sync_payload("aibom_sync_summary") is None
    assert store.get_sync_payload(api._RESULT_BINDINGS_KEY) is None


def test_sql_writer_cannot_rotate_installation_between_validation_and_result_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    actual = api._write
    observations: list[str] = []

    def competing_write(connection: sqlite3.Connection, key: str, payload: object, now: str) -> None:
        if key == "aibom_sync_summary":
            with (
                sqlite3.connect(store.path, timeout=0) as competing,
                pytest.raises(sqlite3.OperationalError, match="locked"),
            ):
                competing.execute(
                    "update guard_devices set installation_id='replacement' where device_key='local-device'"
                )
            observations.append("writer-refused-during-transaction")
        actual(connection, key, payload, now)

    monkeypatch.setattr(api, "_write", competing_write)
    summary = {"synced": True}
    assert api.commit_aibom_results(store, operation, {"aibom_sync_summary": summary}, now=NOW)
    assert observations == ["writer-refused-during-transaction"]
    assert api.read_aibom_result(store, operation, "aibom_sync_summary") == summary
    store.rotate_installation_id(NOW)
    assert api.read_aibom_result(store, operation, "aibom_sync_summary") is None


@pytest.mark.parametrize(
    "reason", ["success", "empty", "oversized", "partial", "network_error", "missing_endpoint", "auth_expired"]
)
def test_all_terminal_outcomes_share_atomic_context_binding(tmp_path: Path, reason: str) -> None:
    store, _ = _store(tmp_path)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    result = {"reason": reason, "synced_at": NOW, "synced": reason == "success"}
    daemon = {"state": "idle", "lastResult": result}
    assert api.commit_aibom_results(
        store, operation, {"aibom_sync_summary": result, "aibom_inventory_daemon": daemon}, now=NOW
    )
    assert api.read_aibom_result(store, operation, "aibom_sync_summary") == result
    assert api.read_aibom_result(store, operation, "aibom_inventory_daemon") == daemon
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
    assert not api.commit_aibom_results(store, operation, {"aibom_sync_summary": {"reason": "late"}}, now=NOW)
    assert store.get_sync_payload("aibom_sync_summary") == result
    assert store.get_sync_payload("aibom_inventory_daemon") == daemon


def test_root_aliases_normalize_without_changing_explicit_path_contents(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    root = tmp_path / " directory with spaces "
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    first = _operation(store, HarnessContext(tmp_path, root, store.guard_home))
    second = _operation(store, HarnessContext(tmp_path, alias, store.guard_home))
    assert first == second
    assert first.context().workspace_dir == root
    assert api.commit_aibom_results(store, first, {"aibom_sync_summary": {"synced": True}}, now=NOW)
    assert api.read_aibom_result(store, second, "aibom_sync_summary") == {"synced": True}


@pytest.mark.parametrize("raw", ['{"synced":NaN}', '{"synced":Infinity}', '{"synced":-Infinity}'])
def test_non_json_summary_values_refuse_freshness(tmp_path: Path, raw: str) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    assert api.commit_aibom_results(store, operation, {"aibom_sync_summary": {"synced": True}}, now=NOW)
    _raw(store, "aibom_sync_summary", raw)
    assert api.read_aibom_result(store, operation, "aibom_sync_summary") is None


def test_changing_mapping_is_copied_once_before_allowlist_validation(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))

    class ChangingResults(Mapping[str, Mapping[str, object]]):
        iterations = 0

        def __len__(self) -> int:
            return 1

        def __iter__(self) -> Iterator[str]:
            self.iterations += 1
            return iter(["aibom_sync_summary"] if self.iterations == 1 else ["receipt_sync_cursor"])

        def __getitem__(self, key: str) -> Mapping[str, object]:
            return {"controlled": True}

    changing = ChangingResults()
    assert api.commit_aibom_results(store, operation, changing, now=NOW)
    assert changing.iterations == 1
    assert store.get_sync_payload("receipt_sync_cursor") is None
    assert api.read_aibom_result(store, operation, "aibom_sync_summary") == {"controlled": True}


@pytest.mark.parametrize("payload", [None, [], "scalar", 42, True])
def test_result_copy_requires_object_payloads_without_partial_writes(tmp_path: Path, payload: object) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    results = cast(Mapping[str, Mapping[str, object]], {"aibom_sync_summary": {}, "aibom_inventory_daemon": payload})
    with pytest.raises(ValueError, match="must be objects"):
        api.commit_aibom_results(store, operation, results, now=NOW)
    assert store.get_sync_payload("aibom_sync_summary") is None
    assert store.get_sync_payload("aibom_inventory_daemon") is None
    assert store.get_sync_payload(api._RESULT_BINDINGS_KEY) is None


def test_context_write_uses_one_snapshot_for_authority_and_public_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _store(tmp_path)
    context = _context(store, tmp_path)
    payload = _selected(context)
    captured = dict(payload)
    actual = store_cloud_events.record_inventory_context_mutation

    def mutate_after_metadata(connection: sqlite3.Connection, value: Any, now: str) -> None:
        actual(connection, value, now)
        payload["workspace_dir"] = str(tmp_path / "changed-after-metadata")

    monkeypatch.setattr(store_cloud_events, "record_inventory_context_mutation", mutate_after_metadata)
    store.set_sync_payload(api.INVENTORY_CONTEXT_KEY, payload, NOW)
    assert payload != captured
    assert store.get_sync_payload(api.INVENTORY_CONTEXT_KEY) == captured
    authority = store.get_sync_payload(api._CONTEXT_AUTHORITY_KEY)
    assert isinstance(authority, dict)
    assert authority["projection"] == captured
    assert api.aibom_operation_is_current(store, _operation(store, context))


@pytest.mark.parametrize("direct", [False, True])
def test_mutable_deletion_keys_are_copied_before_reserved_key_validation(tmp_path: Path, direct: bool) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    store.set_sync_payload("receipt_sync_cursor", {"controlled": True}, NOW)

    class ChangingKeys(list[str]):
        iterations = 0

        def __iter__(self) -> Iterator[str]:
            self.iterations += 1
            threshold = 4 if direct else 6
            return iter([api._CONTEXT_AUTHORITY_KEY] if self.iterations >= threshold else ["receipt_sync_cursor"])

    changing = ChangingKeys(["receipt_sync_cursor"])
    before = store.get_sync_payload(api._CONTEXT_AUTHORITY_KEY)
    deleted = (store._delete_sync_payloads_unlocked if direct else store.delete_sync_payloads)(changing)
    assert deleted == 1
    assert changing.iterations == 1
    assert store.get_sync_payload("receipt_sync_cursor") is None
    assert store.get_sync_payload(api._CONTEXT_AUTHORITY_KEY) == before
    assert api.aibom_operation_is_current(store, operation)


@pytest.mark.parametrize("method", ["commit", "read", "set", "unlocked-set", "delete", "unlocked-delete", "reserve"])
def test_typed_key_aliases_cannot_disagree_with_sqlite_binding(tmp_path: Path, method: str) -> None:
    store, _ = _store(tmp_path)
    operation = _operation(store, _context(store, tmp_path))
    actual = "receipt_sync_cursor" if method in {"commit", "read"} else api._CONTEXT_AUTHORITY_KEY
    alias = "aibom_sync_summary" if method in {"commit", "read"} else "receipt_sync_cursor"
    comparisons: list[str] = []

    class AliasKey(str):
        def __hash__(self) -> int:
            comparisons.append("hash")
            return hash(alias)

        def __eq__(self, other: object) -> bool:
            comparisons.append("equality")
            return isinstance(other, str) and other == alias

    key = AliasKey(actual)
    results: dict[str, Mapping[str, object]] = {key: {"controlled": True}}
    comparisons.clear()
    before = store.get_sync_payload(api._CONTEXT_AUTHORITY_KEY)
    with pytest.raises(ValueError):
        if method == "commit":
            api.commit_aibom_results(store, operation, results, now=NOW)
        elif method == "read":
            api.read_aibom_result(store, operation, key)
        elif method == "set":
            store.set_sync_payload(key, {"controlled": True}, NOW)
        elif method == "unlocked-set":
            store._set_sync_payload_unlocked(key, {"controlled": True}, NOW)
        elif method == "delete":
            store.delete_sync_payloads([key])
        elif method == "unlocked-delete":
            store._delete_sync_payloads_unlocked([key])
        else:
            store.reserve_sync_sequence(key, "counter", NOW)
    assert comparisons == []
    assert store.get_sync_payload("receipt_sync_cursor") is None
    assert store.get_sync_payload("aibom_sync_summary") is None
    assert store.get_sync_payload(api._CONTEXT_AUTHORITY_KEY) == before
    assert api.aibom_operation_is_current(store, operation)
