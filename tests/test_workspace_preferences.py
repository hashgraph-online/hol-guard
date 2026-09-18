"""Strict negotiated preferences use actual durable state and preserve consent."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from codex_plugin_scanner.guard.runtime.workspace_preferences import (
    CONTRACT,
    accept_workspace_preferences,
    effective_receipt_redaction_level,
    optional_upload_allowed,
    parse_workspace_preferences,
    preference_sync_context,
    read_workspace_preferences,
    receipt_upload_accepted,
)
from codex_plugin_scanner.guard.store import GuardStore

WORKSPACE = "00000000-0000-4000-8000-000000000042"
OTHER = "00000000-0000-4000-8000-000000000043"
NOW = "2026-09-18T00:00:00Z"


def wire(
    revision: int = 1, *, sync: bool = True, telemetry: bool = False, redaction: str = "full"
) -> dict[str, object]:
    return {
        "contractVersion": CONTRACT,
        "workspaceId": WORKSPACE,
        "revision": revision,
        "updatedAt": NOW,
        "preferences": {"syncEnabled": sync, "telemetryEnabled": telemetry, "receiptRedactionLevel": redaction},
    }


@pytest.fixture
def store(tmp_path: Path) -> GuardStore:
    result = GuardStore(tmp_path / "guard")
    result.set_sync_payload("oauth_local_credentials", {"workspace_id": WORKSPACE}, NOW)
    return result


@pytest.mark.parametrize(
    "field,value",
    [
        ("contractVersion", "unknown"),
        ("workspaceId", OTHER),
        ("revision", True),
        ("revision", -1),
        ("revision", 1.5),
        ("revision", 2**53),
        ("revision", "1"),
        ("updatedAt", "not-a-date"),
        ("updatedAt", "2026-02-30T00:00:00Z"),
        ("updatedAt", "2026-09-18T00:00:00"),
        ("preferences", []),
        ("preferences", {}),
        ("extra", True),
    ],
)
def test_contract_rejects_invalid_or_unbound_values(field: str, value: object) -> None:
    payload = wire()
    payload[field] = value
    with pytest.raises((ValueError, TypeError)):
        parse_workspace_preferences(payload, workspace_id=WORKSPACE)


@pytest.mark.parametrize(
    "field,value",
    [
        ("syncEnabled", 1),
        ("telemetryEnabled", "false"),
        ("receiptRedactionLevel", "unknown"),
        ("extra", False),
    ],
)
def test_preferences_are_strict(field: str, value: object) -> None:
    payload = wire()
    prefs = payload["preferences"]
    assert isinstance(prefs, dict)
    prefs[field] = value
    with pytest.raises(ValueError):
        parse_workspace_preferences(payload, workspace_id=WORKSPACE)


def test_semantic_revision_survives_reopen_and_timestamp_only_updates(store: GuardStore) -> None:
    first = accept_workspace_preferences(store, wire(2), workspace_id=WORKSPACE)
    same = wire(2)
    same["updatedAt"] = "2026-09-19T00:00:00+00:00"
    assert (
        accept_workspace_preferences(store, same, workspace_id=WORKSPACE).semantic_identity()
        == first.semantic_identity()
    )
    reopened = GuardStore(store.guard_home)
    assert read_workspace_preferences(reopened) == parse_workspace_preferences(same, workspace_id=WORKSPACE)
    for candidate in (wire(1), wire(2, sync=False)):
        with pytest.raises(ValueError):
            accept_workspace_preferences(reopened, candidate, workspace_id=WORKSPACE)
    assert read_workspace_preferences(reopened) == parse_workspace_preferences(same, workspace_id=WORKSPACE)


def test_transaction_rechecks_workspace_and_keeps_namespace_isolated(store: GuardStore) -> None:
    accept_workspace_preferences(store, wire(3), workspace_id=WORKSPACE)
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": OTHER}, NOW)
    with pytest.raises(ValueError, match="scope_changed"):
        accept_workspace_preferences(store, wire(4), workspace_id=WORKSPACE)
    assert read_workspace_preferences(store) is None
    assert not receipt_upload_accepted(store, {}, workspace_id=WORKSPACE, sent_revision=3)
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": WORKSPACE}, NOW)
    restored = read_workspace_preferences(store)
    assert restored is not None and restored.revision == 3


def test_two_connections_serialize_conflicting_same_revision_responses(store: GuardStore) -> None:
    second = GuardStore(store.guard_home)
    barrier = Barrier(2)

    def submit(target: GuardStore, enabled: bool) -> str:
        barrier.wait(timeout=5)
        try:
            accept_workspace_preferences(target, wire(1, sync=enabled), workspace_id=WORKSPACE)
            return "accepted"
        except ValueError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(submit, store, True), pool.submit(submit, second, False)]
        outcomes = [future.result(timeout=10) for future in futures]
    assert sorted(outcomes) == ["accepted", "workspace_preferences_conflict"]
    assert read_workspace_preferences(store) == read_workspace_preferences(second)


def test_two_connections_never_roll_back_a_newer_response(store: GuardStore) -> None:
    second = GuardStore(store.guard_home)
    barrier = Barrier(2)

    def submit(target: GuardStore, revision: int) -> None:
        barrier.wait(timeout=5)
        try:
            accept_workspace_preferences(target, wire(revision), workspace_id=WORKSPACE)
        except ValueError as error:
            assert str(error) == "workspace_preferences_stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(submit, store, 4), pool.submit(submit, second, 5)]
        for future in futures:
            future.result(timeout=10)
    current = read_workspace_preferences(store)
    assert current is not None
    assert current.revision == 5


@pytest.mark.parametrize(
    "ack,sent,enabled,expected",
    [
        (True, 1, True, True),
        (False, 1, True, False),
        (None, 1, True, False),
        ("true", 1, True, False),
        (1, 1, True, False),
        (True, None, True, False),
        (True, 0, True, False),
        (True, True, True, False),
        (True, 1, False, False),
    ],
)
def test_ack_requires_exact_sent_revision_and_acceptance(
    store: GuardStore, ack: object, sent: object, enabled: bool, expected: bool
) -> None:
    payload = {"workspacePreferences": wire(sync=enabled), "receiptSyncAccepted": ack}
    assert receipt_upload_accepted(store, payload, workspace_id=WORKSPACE, sent_revision=sent) is expected
    assert read_workspace_preferences(store) is not None


def test_negotiation_cannot_fall_back_after_receiving_preferences(store: GuardStore) -> None:
    assert preference_sync_context(store) == {"workspacePreferencesContract": CONTRACT}
    assert not receipt_upload_accepted(store, {}, workspace_id=WORKSPACE, sent_revision=None)
    assert receipt_upload_accepted(
        store, {"syncedAt": NOW, "receiptsStored": 0}, workspace_id=WORKSPACE, sent_revision=None
    )
    assert not receipt_upload_accepted(
        store, {"workspacePreferences": wire()}, workspace_id=WORKSPACE, sent_revision=None
    )
    assert preference_sync_context(store)["workspacePreferenceRevision"] == 1
    assert not receipt_upload_accepted(store, {}, workspace_id=WORKSPACE, sent_revision=1)
    bad = copy.deepcopy(wire())
    bad["revision"] = -1
    assert not receipt_upload_accepted(
        store, {"workspacePreferences": bad, "receiptSyncAccepted": True}, workspace_id=WORKSPACE, sent_revision=1
    )
    current = read_workspace_preferences(store)
    assert current is not None and current.revision == 1


@pytest.mark.parametrize(
    "local_sync,local_telemetry,cloud_sync,cloud_telemetry",
    [(a, b, c, d) for a in (False, True) for b in (False, True) for c in (False, True) for d in (False, True)],
)
def test_cloud_permission_never_grants_local_consent(
    store: GuardStore, local_sync: bool, local_telemetry: bool, cloud_sync: bool, cloud_telemetry: bool
) -> None:
    (store.guard_home / "config.toml").write_text(
        f"sync = {str(local_sync).lower()}\ntelemetry = {str(local_telemetry).lower()}\n"
    )
    accept_workspace_preferences(store, wire(sync=cloud_sync, telemetry=cloud_telemetry), workspace_id=WORKSPACE)
    assert optional_upload_allowed(store) is (local_sync and cloud_sync)
    assert optional_upload_allowed(store, telemetry=True) is (
        local_sync and local_telemetry and cloud_sync and cloud_telemetry
    )


@pytest.mark.parametrize(
    "local,remote,expected",
    [
        ("none", "full", "full"),
        ("full", "none", "full"),
        ("partial", "none", "partial"),
        ("none", "partial", "partial"),
    ],
)
def test_redaction_keeps_the_stricter_local_or_current_floor(
    store: GuardStore, local: str, remote: str, expected: str
) -> None:
    (store.guard_home / "config.toml").write_text(f'receipt_redaction_level = "{local}"\n')
    accept_workspace_preferences(store, wire(redaction=remote), workspace_id=WORKSPACE)
    assert effective_receipt_redaction_level(store) == expected


def test_corrupt_durable_preferences_fail_closed_without_modifying_them(store: GuardStore) -> None:
    key = "workspace_preferences:" + WORKSPACE
    store.set_sync_payload(key, {"revision": 1}, NOW)
    assert not optional_upload_allowed(store)
    assert effective_receipt_redaction_level(store) == "full"
    assert not receipt_upload_accepted(store, {}, workspace_id=WORKSPACE, sent_revision=None)
    with pytest.raises(ValueError):
        accept_workspace_preferences(store, wire(2), workspace_id=WORKSPACE)
    assert store.get_sync_payload(key) == {"revision": 1}
