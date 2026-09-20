"""One authenticated SQL view is distinct from the later publication barrier."""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_authority_read as reader
from codex_plugin_scanner.guard import store_secret_policy_integrity as integrity
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_managed_source_support import managed_store
from tests.test_canonical_policy_row_authority import _NOW, _activated_store
from tests.test_guard_extension_control_authority import _commit
from tests.test_native_policy_authority_managed_read import _TIME


def test_reused_integrity_connection_observes_committed_marker_between_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(integrity, "_POLICY_INTEGRITY_CACHE_TTL_SECONDS", 3600.0)
    store = _activated_store(tmp_path)
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", artifact_id="synthetic-existing-marker", action="block"),
        _NOW,
    )
    other = GuardStore(store.guard_home)
    key = store._policy_integrity_secret_material(create=False)
    before = store._load_policy_integrity_control_state(create=False)
    assert before is not None and type(before["generation"]) is int
    with store._connect() as connection:
        assert store._policy_integrity_secret_material(create=False, connection=connection) == key
        assert not connection.in_transaction
        other.upsert_policy(
            PolicyDecision(harness="codex", scope="artifact", artifact_id="synthetic-existing-marker", action="allow"),
            _NOW,
        )
        current_generation = other.get_policy_integrity_status()["generation"]
        assert type(current_generation) is int and current_generation > before["generation"]
        observed = store._load_policy_integrity_control_state(create=False, connection=connection)
        assert not connection.in_transaction
    assert observed is not None and type(observed["generation"]) is int
    assert observed["generation"] > before["generation"]
    assert observed == other._load_policy_integrity_control_state(create=False)


def test_integrity_pairs_reuse_setup_but_keep_distinct_capture_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    original_material = store._policy_integrity_secret_material
    original_control = store._load_policy_integrity_control_state
    observed: list[tuple[str, sqlite3.Connection]] = []

    def material(*, create: bool, connection: sqlite3.Connection | None = None):
        assert not create and connection is not None and not connection.in_transaction
        observed.append(("material", connection))
        return original_material(create=create, connection=connection)

    def control(*, create: bool, connection: sqlite3.Connection | None = None):
        assert not create and connection is not None and not connection.in_transaction
        observed.append(("control", connection))
        return original_control(create=create, connection=connection)

    monkeypatch.setattr(store, "_policy_integrity_secret_material", material)
    monkeypatch.setattr(store, "_load_policy_integrity_control_state", control)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME).authority.rows
    assert [kind for kind, _ in observed] == ["material", "control", "material", "control"]
    assert observed[0][1] is observed[1][1]
    assert observed[2][1] is observed[3][1]
    assert observed[0][1] is not observed[2][1]


def test_integrity_observations_refuse_a_frozen_transaction(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    with store._connect() as connection:
        connection.execute("begin")
        connection.execute("select count(*) from sync_state").fetchone()
        for reader_method in (store._policy_integrity_secret_material, store._load_policy_integrity_control_state):
            with pytest.raises(RuntimeError, match="autocommit connection"):
                reader_method(create=False, connection=connection)


@pytest.mark.parametrize("cloud", [None, False, True])
def test_real_runtime_commit_during_captured_sql_view_preserves_complete_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cloud: bool | None
) -> None:
    if cloud is None:
        store = GuardStore(tmp_path / "empty-home")
        key, key_id = store._policy_integrity_secret_material(create=True)
        assert key is not None and key_id is not None
    else:
        store = managed_store(tmp_path, monkeypatch, cloud=cloud)
    before = reader.read_native_policy_authority_inputs(store, now=_TIME)
    original = store._read_captured_extension_control_authority
    observed = []

    def concurrent_runtime(connection, registry):
        assert connection.in_transaction
        assert connection.execute("pragma query_only").fetchone()[0] == 1
        store.upsert_runtime_state(
            session_id="synthetic-capture",
            daemon_host="localhost",
            daemon_port=0,
            started_at=_NOW,
            last_heartbeat_at=_NOW,
        )
        observed.append(True)
        return original(connection, registry)

    monkeypatch.setattr(store, "_read_captured_extension_control_authority", concurrent_runtime)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME) == before
    assert observed == [True]


def test_captured_view_cannot_write_or_prepare_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = managed_store(tmp_path, monkeypatch)
    original = store._read_captured_extension_control_authority
    observed = []

    def read_only(connection, registry):
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("delete from extension_control_catalog_manifest")
        observed.append(True)
        return original(connection, registry)

    monkeypatch.setattr(store, "_read_captured_extension_control_authority", read_only)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME).authority.managed is not None
    assert observed == [True]


def test_complete_managed_verifier_never_opens_a_second_sql_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch)
    original = store._read_captured_extension_control_authority
    observed = []

    def same_connection(connection, registry):
        def secondary_read():
            raise AssertionError("captured managed authority opened another SQL view")

        with monkeypatch.context() as scoped:
            scoped.setattr(store, "_connect", secondary_read)
            result = original(connection, registry)
        observed.append(True)
        return result

    monkeypatch.setattr(store, "_read_captured_extension_control_authority", same_connection)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME).authority.managed is not None
    assert observed == [True]


@pytest.mark.parametrize(
    "statement",
    [
        "update extension_control_authority_snapshot set snapshot_mac = 'invalid'",
        "update extension_control_authority_snapshot set snapshot_json = '{}'",
        "update extension_control_authority_snapshot set layers_json = '[]'",
        "update extension_control_authority_snapshot set previous_digest = 'invalid'",
        "update extension_control_authority_snapshot set catalog_digest = 'invalid'",
        "delete from extension_control_authority_transition",
        "update extension_control_authority_transition set transition_mac = 'invalid'",
        "update extension_control_authority_transition set snapshot_mac = 'invalid'",
        "update extension_control_authority_transition set previous_revision = 9",
        "update extension_control_catalog_manifest set record_mac = 'invalid'",
        "delete from extension_control_catalog_manifest",
        "update extension_control_schema_migration set checksum = 'invalid'",
        "delete from extension_control_schema_migration",
        "delete from extension_control_authority_snapshot",
        "update sync_state set payload_json = '{}' where state_key = 'managed_controls_revision'",
    ],
)
def test_complete_managed_verifier_refuses_mutation_after_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, statement: str
) -> None:
    store = managed_store(tmp_path, monkeypatch)
    original = reader._capture_native_policy_authority_inputs
    observed = []

    def mutate_before_snapshot(*args, **kwargs):
        with store._connect() as connection:
            cursor = connection.execute(statement)
            assert cursor.rowcount > 0
        observed.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", mutate_before_snapshot)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    assert observed == [True]


def test_local_logical_aba_advances_external_generation_and_refuses_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    blocked = PolicyDecision(harness="codex", scope="artifact", artifact_id="synthetic-local-aba", action="block")
    allowed = PolicyDecision(harness="codex", scope="artifact", artifact_id="synthetic-local-aba", action="allow")
    store.upsert_policy(blocked, _NOW)
    before = store._load_policy_integrity_control_state(create=False)
    assert isinstance(before, dict)
    generation = before["generation"]
    assert type(generation) is int
    original = store._read_captured_extension_control_authority

    def change_and_restore(connection, registry):
        store.upsert_policy(allowed, _NOW)
        store.upsert_policy(blocked, _NOW)
        return original(connection, registry)

    monkeypatch.setattr(store, "_read_captured_extension_control_authority", change_and_restore)
    with pytest.raises(NativePolicySnapshotError, match="changed_during_read"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    after = store._load_policy_integrity_control_state(create=False)
    assert isinstance(after, dict)
    assert after["generation"] == generation + 2


def test_managed_revision_cannot_revert_sql_beneath_new_authenticated_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=False)
    with store._connect() as connection:
        old_snapshot = dict(connection.execute("select * from extension_control_authority_snapshot").fetchone())
    original = store._read_captured_extension_control_authority

    def advance_and_restore(connection, registry):
        _commit(store, revision=1, key="synthetic-capture-next-revision")
        with store._connect() as writer:
            writer.execute("delete from extension_control_authority_snapshot")
            columns = ",".join(old_snapshot)
            placeholders = ",".join("?" for _ in old_snapshot)
            writer.execute(
                f"insert into extension_control_authority_snapshot ({columns}) values ({placeholders})",
                tuple(old_snapshot.values()),
            )
        return original(connection, registry)

    monkeypatch.setattr(store, "_read_captured_extension_control_authority", advance_and_restore)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    key = store._authority_key(required=True)
    assert key is not None
    anchor = store._read_anchor(key=key)
    assert anchor is not None and anchor.revision == 2


def test_snapshot_source_is_coherent_but_does_not_claim_latest_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=False)
    before = reader.read_native_policy_authority_inputs(store, now=_TIME)
    original = store._read_captured_extension_control_authority

    def withdraw_after_snapshot(connection, registry):
        store.delete_sync_payload("policy_bundle")
        return original(connection, registry)

    monkeypatch.setattr(store, "_read_captured_extension_control_authority", withdraw_after_snapshot)
    captured = reader.read_native_policy_authority_inputs(store, now=_TIME)
    assert captured == before
    monkeypatch.setattr(store, "_read_captured_extension_control_authority", original)
    with pytest.raises(NativePolicySnapshotError, match="bundle_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)


def test_new_unenrolled_anchor_after_sql_capture_refuses_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    original = reader._capture_native_policy_authority_inputs

    def add_anchor_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        store._secret_store().set_secret(store._anchor_ref(), "synthetic-unverified-anchor")
        return result

    monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", add_anchor_after_read)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)


def test_pending_transition_after_preparation_refuses_without_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch)
    original = reader._capture_native_policy_authority_inputs

    def add_pending(*args, **kwargs):
        with store._connect() as connection:
            row = dict(connection.execute("select * from extension_control_authority_transition").fetchone())
            row.update(
                revision=2,
                previous_revision=1,
                phase="prepared",
                idempotency_key_hash="a" * 64,
                nonce_hash="b" * 64,
                committed_at=None,
            )
            columns = ",".join(row)
            placeholders = ",".join("?" for _ in row)
            connection.execute(
                f"insert into extension_control_authority_transition ({columns}) values ({placeholders})",
                tuple(row.values()),
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", add_pending)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    with store._connect() as connection:
        assert (
            connection.execute(
                "select phase from extension_control_authority_transition where revision = 2"
            ).fetchone()[0]
            == "prepared"
        )


def test_preparation_required_schema_is_not_upgraded_inside_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.store_extension_control_authority_schema import _SCHEMA_CHECKSUM_V3

    store = managed_store(tmp_path, monkeypatch)
    original = reader._capture_native_policy_authority_inputs

    def old_schema(*args, **kwargs):
        with store._connect() as connection:
            connection.execute(
                "update extension_control_schema_migration set version = 3, checksum = ?",
                (_SCHEMA_CHECKSUM_V3,),
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", old_schema)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    with store._connect() as connection:
        assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 3


@pytest.mark.parametrize(
    "residue",
    [
        "extension_control_authority_transition",
        "extension_control_authority_proof",
        "extension_control_catalog_manifest",
        "extension_control_authority_recovery_archive",
        "managed_controls_active",
        "managed_controls_revision",
        "managed_controls_last_good",
    ],
)
def test_unenrolled_residue_added_after_preparation_refuses_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, residue: str
) -> None:
    store = _activated_store(tmp_path / "target")
    original = reader._capture_native_policy_authority_inputs
    template = None
    if residue in {
        "extension_control_authority_transition",
        "extension_control_authority_proof",
        "extension_control_catalog_manifest",
    }:
        enrolled = managed_store(tmp_path / "template", monkeypatch, cloud=False)
        with enrolled._connect() as connection:
            row = connection.execute(f"select * from {residue} limit 1").fetchone()
            assert row is not None
            template = dict(row)

    def add_residue(*args, **kwargs):
        with store._connect() as connection:
            if template is not None:
                columns = ",".join(template)
                placeholders = ",".join("?" for _ in template)
                connection.execute(
                    f"insert into {residue} ({columns}) values ({placeholders})", tuple(template.values())
                )
            elif residue == "extension_control_authority_recovery_archive":
                connection.execute(
                    "insert into extension_control_authority_recovery_archive "
                    "(archive_id, reason, archived_at, transition_rows_json, proof_rows_json) "
                    "values ('synthetic-archive', 'synthetic', ?, '[]', '[]')",
                    (_NOW,),
                )
            else:
                connection.execute(
                    "insert into sync_state (state_key, payload_json, updated_at) values (?, '{}', ?)",
                    (residue, _NOW),
                )
        return original(*args, **kwargs)

    monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", add_residue)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)


def test_query_only_capture_refuses_pending_outbox_finalizer_write_without_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_guard_review_event_outbox import _request

    store = managed_store(tmp_path, monkeypatch)
    store.add_approval_request(_request("synthetic-capture-outbox"), _NOW)
    original = store.hold_oauth_credential_lock
    injected = []

    @contextmanager
    def pending_finalizer():
        with original():
            with closing(sqlite3.connect(store.path)) as writer:
                cursor = writer.execute(
                    "update guard_review_outbox_events set payload_hash = '' where local_request_id = ?",
                    ("synthetic-capture-outbox",),
                )
                assert cursor.rowcount == 1
                writer.commit()
            injected.append(True)
            yield

    monkeypatch.setattr(store, "hold_oauth_credential_lock", pending_finalizer)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    assert injected == [True]
    with closing(sqlite3.connect(store.path)) as observer:
        assert (
            observer.execute(
                "select payload_hash from guard_review_outbox_events where local_request_id = ?",
                ("synthetic-capture-outbox",),
            ).fetchone()[0]
            == ""
        )
    # Ordinary preparation still owns finalization; the captured verifier did
    # not silently write, disable finalization, or change the event payload.
    monkeypatch.setattr(store, "hold_oauth_credential_lock", original)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME).authority.managed is not None


def test_unenrolled_capture_keeps_signed_authority_without_unused_catalog_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError

    store = _activated_store(tmp_path, action="block")
    before = reader.read_native_policy_authority_inputs(store, now=_TIME)
    assert before.authority.managed is None
    assert before.authority.rows

    def unavailable_catalog(_registry: object) -> dict[str, str]:
        raise ExtensionControlAuthorityError("synthetic catalog unavailable")

    monkeypatch.setattr(store, "_catalog_target_manifest", unavailable_catalog)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME) == before

    bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(bundle, dict)
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = "invalid"
    store.set_sync_payload("policy_bundle", bundle, _NOW)
    with pytest.raises(NativePolicySnapshotError):
        reader.read_native_policy_authority_inputs(store, now=_TIME)


@pytest.mark.parametrize("phase", ["preparation", "capture"])
def test_protected_authority_still_requires_catalog_in_each_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError

    store = managed_store(tmp_path, monkeypatch, cloud=False)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME).authority.managed is not None
    calls = []

    def unavailable_catalog(_registry: object) -> dict[str, str]:
        calls.append(True)
        raise ExtensionControlAuthorityError("synthetic catalog unavailable")

    if phase == "preparation":
        monkeypatch.setattr(store, "_catalog_target_manifest", unavailable_catalog)
    else:
        original = reader._capture_native_policy_authority_inputs

        def unavailable_after_preparation(*args, **kwargs):
            monkeypatch.setattr(store, "_catalog_target_manifest", unavailable_catalog)
            return original(*args, **kwargs)

        monkeypatch.setattr(reader, "_capture_native_policy_authority_inputs", unavailable_after_preparation)

    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    assert calls == [True]
