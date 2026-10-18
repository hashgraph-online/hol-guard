"""Publisher markers derive pack identity from the committed protected slot."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_store, activation_transition, preparation
from codex_plugin_scanner.guard.catalog_delivery.projection import require_current
from codex_plugin_scanner.guard.native_command_control_authority import PACK_AUTHORITY_SCHEMA
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_command_control_authority_store import (
    _key,
    commit_native_command_control_projection,
    read_command_control_authority,
    read_committed_projection_authority,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)
from tests.test_extension_pack_preparation import delivery as delivery


@pytest.fixture
def active(delivery):
    home = delivery.cache.parent / "publisher-device"
    home.mkdir(mode=0o700)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    store = SimpleNamespace(
        guard_home=home,
        _connect=lambda: connection,
        _authority_key=lambda *, required: b"a" * 32,
        _policy_integrity_secret_material=lambda *, create: (b"k" * 32, "test"),
    )
    ensure_extension_control_authority_schema(connection)
    connection.commit()
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        now=1500,
        fetch=delivery.fetch,
    )
    draft = activation_transition.stage(
        None, prepared, verifier_key=_key(store), installed_source=prepared.source_sha, now=1500
    )
    with hold_command_control_authority_lock(home), connection:
        activation_store.write_in_transaction(
            store, connection, draft, verifier_key=_key(store), recorded_at="unit", now=1500
        )
    binding = {name: getattr(prepared.metadata, name) for name in ("program_digest", "catalog_digest", "trust_digest")}
    binding["effective_digest"] = "e" * 64
    return store, connection, draft, binding


def test_publisher_commits_v2_and_never_authenticates_a_different_pack(active):
    store, _, draft, binding = active
    with hold_command_control_authority_lock(store.guard_home):
        authority = commit_native_command_control_projection(store, binding)
    marker = read_command_control_authority(store, _key(store))
    assert marker["schema"] == PACK_AUTHORITY_SCHEMA
    assert marker["pack_program_digest"] == binding["program_digest"]
    assert read_committed_projection_authority(store, binding) == authority
    with hold_command_control_authority_lock(store.guard_home, shared=True):
        require_current(store, _key(store), draft.digest)
        with pytest.raises(NativePolicySnapshotError, match="projection_changed"):
            require_current(store, _key(store), None)
    for field in ("program_digest", "catalog_digest", "trust_digest"):
        changed = {**binding, field: "f" * 64}
        with (
            hold_command_control_authority_lock(store.guard_home),
            pytest.raises(NativePolicySnapshotError, match="projection_mismatch"),
        ):
            commit_native_command_control_projection(store, changed)
        assert read_command_control_authority(store, _key(store)) == marker


def test_removed_activation_record_cannot_downgrade_a_v2_marker(active):
    store, connection, _, binding = active
    with hold_command_control_authority_lock(store.guard_home):
        commit_native_command_control_projection(store, binding)
        with connection:
            connection.execute("delete from extension_command_pack_activation")
        with pytest.raises(NativePolicySnapshotError, match="activation_missing"):
            commit_native_command_control_projection(store, binding)


def test_same_record_digest_does_not_skip_authentication(active):
    store, connection, draft, _ = active
    with connection:
        connection.execute("update extension_command_pack_activation set record_mac=?", ("f" * 64,))
    with (
        hold_command_control_authority_lock(store.guard_home, shared=True),
        pytest.raises(ExtensionControlAuthorityError, match="authentication failed"),
    ):
        require_current(store, _key(store), draft.digest)
