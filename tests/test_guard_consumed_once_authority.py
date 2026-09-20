"""Authenticated consumed evidence cannot be invented from terminal DB state."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore

CREATED = "2026-09-17T12:00:00+00:00"
CLAIMED = "2026-09-17T12:01:00.000001+00:00"
EXPIRES = "2026-09-17T12:02:00.000001+00:00"
IDENTITY = {
    "request_id": "codex-waiter-1",
    "harness": "codex",
    "artifact_id": "codex:native-pretool:Bash",
    "artifact_hash": "a" * 64,
    "workspace": "/workspace/project",
    "publisher": "publisher-1",
}


def _fixture(tmp_path: Path, *, consume: bool = True, **identity):
    store = GuardStore(tmp_path / "guard-home")
    target = {**IDENTITY, **identity}
    approval_id = store.record_local_once_approval(**target, action="allow", created_at=CREATED, expires_at=EXPIRES)
    assert approval_id is not None
    if consume:
        assert store.claim_local_once_approval(approval_id, claimed_at=CLAIMED)
    return store, approval_id, target


def _lookup(store: GuardStore, *, now: str = CLAIMED, **identity):
    return store.peek_consumed_local_once_approval(**{**IDENTITY, **identity}, now=now)


def _row(store: GuardStore, approval_id: str):
    with store._connect() as connection:
        return dict(
            connection.execute(
                "select * from guard_local_once_approvals where approval_id = ?", (approval_id,)
            ).fetchone()
        )


def test_real_committed_claim_is_verified_and_lookup_is_read_only(tmp_path):
    store, approval_id, _ = _fixture(tmp_path)
    before = _row(store, approval_id)
    events = store.list_events()
    result = _lookup(store)
    assert result is not None
    assert result["approval_id"] == approval_id
    assert result["request_id"] == IDENTITY["request_id"]
    assert result["artifact_hash"] == IDENTITY["artifact_hash"]
    assert result["action"] == "allow" and result["source"] == "approval-gate-once"
    assert result["integrity_status"] == "valid"
    assert _lookup(GuardStore(store.guard_home)) == result
    assert _row(store, approval_id) == before and store.list_events() == events
    assert not store.claim_local_once_approval(approval_id, claimed_at=CLAIMED)


def test_unconsumed_approval_and_rolled_back_claim_are_not_consumption(tmp_path):
    store, approval_id, _ = _fixture(tmp_path, consume=False)
    assert _lookup(store) is None
    key, key_id = store._policy_integrity_secret_material(create=False)
    with store._connect() as connection:
        connection.execute("begin immediate")
        assert (
            store._claim_local_once_approval_by_id_locked(
                connection, approval_id=approval_id, now=CLAIMED, integrity_key=key, integrity_key_id=key_id
            )
            is not None
        )
        connection.rollback()
    assert _lookup(store) is None
    assert _row(store, approval_id)["claimed_at"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "another-waiter"),
        ("harness", "claude-code"),
        ("artifact_id", "codex:native-pretool:Read"),
        ("artifact_hash", "b" * 64),
        ("workspace", "/workspace/other"),
        ("workspace", None),
        ("publisher", "other-publisher"),
        ("publisher", None),
        ("request_id", ""),
        ("artifact_id", None),
        ("artifact_hash", None),
    ],
)
def test_every_request_identity_is_exact(tmp_path, field, value):
    store, _, _ = _fixture(tmp_path)
    assert _lookup(store, **{field: value}) is None


@pytest.mark.parametrize("field", ["workspace", "publisher"])
def test_null_stored_identity_does_not_grant_a_specific_scope(tmp_path, field):
    store, _, target = (
        _fixture(tmp_path, workspace=None) if field == "workspace" else _fixture(tmp_path, publisher=None)
    )
    assert _lookup(store) is None
    assert store.peek_consumed_local_once_approval(**target, now=CLAIMED) is not None


def test_workspace_uses_existing_windows_canonical_key(tmp_path):
    store, _, _ = _fixture(tmp_path, workspace="C:\\Workspace\\Project\\")
    assert _lookup(store, workspace="c:/workspace/project") is not None
    assert _lookup(store, workspace="c:/workspace/other") is None


@pytest.mark.parametrize(
    "now,valid",
    [
        ("2026-09-17T12:01:00.000000+00:00", False),
        (CLAIMED, True),
        ("2026-09-17T14:01:00.000001+02:00", True),
        ("2026-09-17T12:02:00.000000+00:00", True),
        (EXPIRES, False),
        ("2026-09-17T12:02:00.000002+00:00", False),
        ("not-a-timestamp", False),
    ],
)
def test_claim_and_expiry_boundaries_are_exact_to_microseconds(tmp_path, now, valid):
    store, _, _ = _fixture(tmp_path)
    assert (_lookup(store, now=now) is not None) is valid


@pytest.mark.parametrize(
    "field,value",
    [
        ("claimed_at", "2026-09-17T12:01:00+00:00"),
        ("claimed_at", None),
        ("claimed_at", "malformed"),
        ("expires_at", "2026-09-17T12:03:00+00:00"),
        ("request_id", "forged-waiter"),
        ("artifact_hash", "b" * 64),
        ("action", "block"),
        ("payload_mac", "0" * 64),
        ("payload_hash", "0" * 64),
        ("integrity_key_id", "another-key"),
        ("signed_at", "2026-09-17T12:01:01+00:00"),
        ("integrity_version", 999),
    ],
)
def test_mutated_signed_consumption_never_becomes_authority(tmp_path, field, value):
    store, approval_id, _ = _fixture(tmp_path)
    assert _lookup(store) is not None
    # The column comes exclusively from the fixed test parameter list.
    with store._connect() as connection:
        connection.execute(
            f"update guard_local_once_approvals set {field} = ? where approval_id = ?", (value, approval_id)
        )
    lookup_changes = {field: value} if field in {"request_id", "artifact_hash"} else {}
    assert _lookup(store, **lookup_changes) is None


@pytest.mark.parametrize("change", ["missing", "rotated_key", "rotated_id"])
def test_lookup_never_creates_or_recovers_missing_or_rotated_key(tmp_path, monkeypatch, change):
    store, _, _ = _fixture(tmp_path)
    key, key_id = store._policy_integrity_secret_material(create=False)
    assert key is not None and key_id is not None
    material = {
        "missing": (None, None),
        "rotated_key": (bytes(byte ^ 0xFF for byte in key), key_id),
        "rotated_id": (key, "new-key-id"),
    }[change]
    calls = []

    def secret_material(*, create):
        calls.append(create)
        return material

    monkeypatch.setattr(store, "_policy_integrity_secret_material", secret_material)
    assert _lookup(store) is None
    assert calls == [False]


def test_deleted_consumed_authority_has_no_cached_fallback(tmp_path):
    store, approval_id, _ = _fixture(tmp_path)
    assert _lookup(store) is not None
    with store._connect() as connection:
        connection.execute("delete from guard_local_once_approvals where approval_id = ?", (approval_id,))
    assert _lookup(store) is None


def test_unsigned_consumption_timestamp_cannot_upgrade_an_unconsumed_mac(tmp_path):
    store, approval_id, _ = _fixture(tmp_path, consume=False)
    with store._connect() as connection:
        connection.execute(
            "update guard_local_once_approvals set claimed_at = ? where approval_id = ?", (CLAIMED, approval_id)
        )
    assert _lookup(store) is None
