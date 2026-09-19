"""Zero-row signed sources retain explicit authenticated local recency."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_materialization import (
    POLICY_BUNDLE_MATERIALIZATION_KEY,
    PolicyBundleMaterializationError,
    bind_policy_bundle_materialization,
    verified_policy_materialization_time,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_NOW = "2026-09-17T00:00:00Z"
_LATER = "2026-09-17T00:01:00Z"


def _source(*, version: int = 8) -> dict[str, object]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id="workspace-alpha")
    document: dict[str, object] = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.source", "name": "Synthetic source", "revision": version},
        "spec": {"defaults": {"mode": "enforce", "defaultAction": "block"}, "rules": []},
    }
    bundle = _signed_bundle(private_key, key, payload_base=document, bundle_version=version)
    validated, reason, _ = validate_synced_policy_bundle(
        bundle, stored_keyring=policy_bundle_keyring_payload((key,), workspace_id="workspace-alpha")
    )
    assert reason is None and validated == bundle
    return bundle


def _write(connection: sqlite3.Connection, payload: dict[str, object], now: str) -> None:
    connection.execute(
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) "
        "on conflict(state_key) do update set payload_json=excluded.payload_json, updated_at=excluded.updated_at",
        (POLICY_BUNDLE_MATERIALIZATION_KEY, json.dumps(payload), now),
    )


def _persist(store: GuardStore, bundle: dict[str, object], now: str = _NOW) -> dict[str, object]:
    with store._connect() as connection:
        rows, binding = bind_policy_bundle_materialization(
            store, connection, bundle=bundle, rows=[], now=now, require_source_binding=True
        )
        assert rows == [] and isinstance(binding, dict)
        _write(connection, binding, now)
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("policy_bundle_ack") is None
    return binding


def test_empty_rows_keep_legacy_default_without_materialization_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with store._connect() as connection:
        assert bind_policy_bundle_materialization(store, connection, bundle=_source(), rows=[], now=_NOW) == ([], None)
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
    assert store.list_policy_decisions() == []


def test_explicit_source_binding_survives_reopen_without_rows_or_ack(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    store = GuardStore(home)
    bundle = _source()
    first = _persist(store, bundle)
    reopened = GuardStore(home)
    assert reopened.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == first
    assert _persist(reopened, bundle, _LATER) == first
    key, key_id = reopened._policy_integrity_secret_material(create=False)
    assert (
        verified_policy_materialization_time(
            first, bundle=bundle, device_id=reopened.get_device_metadata()["installation_id"], key=key, key_id=key_id
        )
        == first["materializedAt"]
    )
    assert reopened.list_policy_decisions() == []
    assert reopened.get_sync_payload("policy_bundle_ack") is None


def test_changed_signed_source_gets_new_recency_and_cannot_reuse_old_commitment(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    original, replacement = _source(), _source(version=9)
    first = _persist(store, original)
    second = _persist(store, replacement, _LATER)
    assert second["materializedAt"] != first["materializedAt"]
    key, key_id = store._policy_integrity_secret_material(create=False)
    assert (
        verified_policy_materialization_time(
            first, bundle=replacement, device_id=store.get_device_metadata()["installation_id"], key=key, key_id=key_id
        )
        is None
    )


@pytest.mark.parametrize("mutation", ["mac", "missing-mac", "timestamp", "workspace", "hash", "version", "key-id"])
def test_zero_row_existing_binding_tampering_is_not_resigned(tmp_path: Path, mutation: str) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _source()
    binding = _persist(store, bundle)
    if mutation == "missing-mac":
        del binding["mac"]
    else:
        field, value = {
            "mac": ("mac", "0" * 64),
            "timestamp": ("materializedAt", "2026-09-17T00:00:02.000000+00:00"),
            "workspace": ("workspaceId", "workspace-other"),
            "hash": ("bundleHash", "sha256:" + "f" * 64),
            "version": ("bundleVersion", "8"),
            "key-id": ("keyId", "different-key"),
        }[mutation]
        binding[field] = value
    store.set_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY, binding, _NOW)
    with pytest.raises(PolicyBundleMaterializationError):
        _persist(store, bundle, _LATER)
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == binding
    assert store.list_policy_decisions() == []


@pytest.mark.parametrize("raw", ["null", "[]", "{invalid"])
def test_malformed_durable_source_binding_is_refused_without_replacement(tmp_path: Path, raw: str) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _source()
    _persist(store, bundle)
    with store._connect() as connection:
        connection.execute(
            "update sync_state set payload_json=? where state_key=?", (raw, POLICY_BUNDLE_MATERIALIZATION_KEY)
        )
    with pytest.raises(PolicyBundleMaterializationError):
        _persist(store, bundle, _LATER)
    with store._connect() as connection:
        assert (
            connection.execute(
                "select payload_json from sync_state where state_key=?", (POLICY_BUNDLE_MATERIALIZATION_KEY,)
            ).fetchone()[0]
            == raw
        )


def test_installation_change_cannot_rebind_existing_source(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _source()
    first = _persist(store, bundle)
    with store._connect() as connection:
        connection.execute(
            "update guard_devices set installation_id=? where device_key='local-device'",
            ("00000000-0000-4000-8000-000000000099",),
        )
    with pytest.raises(PolicyBundleMaterializationError):
        _persist(store, bundle, _LATER)
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == first


@pytest.mark.parametrize("material", [(None, None), (b"x" * 32, "replaced-integrity-key")])
def test_missing_or_replaced_integrity_key_preserves_durable_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, material: tuple[bytes | None, str | None]
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _source()
    first = _persist(store, bundle)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **_kwargs: material)
    with pytest.raises(PolicyBundleMaterializationError):
        _persist(store, bundle, _LATER)
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == first


def test_source_binding_rolls_back_with_the_actual_store_transaction(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = _persist(store, _source())
    with pytest.raises(RuntimeError, match="synthetic-write-failure"), store._connect() as connection:
        rows, replacement = bind_policy_bundle_materialization(
            store, connection, bundle=_source(version=9), rows=[], now=_LATER, require_source_binding=True
        )
        assert rows == [] and isinstance(replacement, dict)
        _write(connection, replacement, _LATER)
        raise RuntimeError("synthetic-write-failure")
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == first
    assert store.list_policy_decisions() == []
    assert store.get_sync_payload("policy_bundle_ack") is None


@pytest.mark.parametrize("flag", [None, 0, 1, "true", [], {}])
def test_source_binding_flag_requires_an_explicit_boolean(tmp_path: Path, flag: object) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with pytest.raises(PolicyBundleMaterializationError), store._connect() as connection:
        bind_policy_bundle_materialization(
            store, connection, bundle=_source(), rows=[], now=_NOW, require_source_binding=cast(bool, flag)
        )
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
