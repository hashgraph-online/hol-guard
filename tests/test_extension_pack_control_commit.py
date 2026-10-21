"""Pack journal integration with real control proofs and private anchors.

The transport/native compiler fixture is synthetic; these cases qualify the
transaction boundaries, independently of native matcher admission tests.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_store, activation_transition, preparation
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from tests.guard_extension_control_authority_fixtures import (
    MemorySecretStore,
    _proof,
    _store,
)
from tests.guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_preparation import delivery as delivery
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)


@pytest.mark.parametrize("failure", [None, "crash", "missing", "corrupt", "key-unavailable", "lineage-conflict"])
def test_approved_control_commit_and_anchored_retry_install_the_same_pack_record(
    delivery, tmp_path, monkeypatch, failure
):
    store = _store(tmp_path, MemorySecretStore())
    seed(store)
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        now=1500,
        fetch=delivery.fetch,
    )
    draft = activation_transition.stage(None, prepared, verifier_key=_key(store), store=store, now=1500)
    # Reuse the strict production target metadata in this transaction-only
    # fixture; no fabricated matcher is installed or evaluated by this test.
    registry = GeneratedCommandCatalog(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions, catalog_digest=prepared.metadata.catalog_digest
    )
    proof = _proof(
        store,
        (),
        revision=0,
        key="pack-transition",
        actor_id="unit-admin",
        nonce="pack-nonce",
        catalog_digest=registry.catalog_digest,
    )
    arguments = dict(
        catalog_digest=registry.catalog_digest,
        actor_id="unit-admin",
        expected_revision=0,
        idempotency_key="pack-transition",
        nonce="pack-nonce",
        proof=proof,
        migration_registry=registry,
        pack_activation=draft,
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.catalog_delivery.activation_journal.time.time", lambda: 1500)
    write_anchor = store._write_and_verify_anchor
    if failure is not None:

        def crash(anchor, *, key):
            write_anchor(anchor, key=key)
            if anchor.phase is AuthorityPhase.ANCHORED:
                raise RuntimeError("crash after private anchor")

        monkeypatch.setattr(store, "_write_and_verify_anchor", crash)
        with pytest.raises(ExtensionControlAuthorityError, match="anchor unavailable"):
            store.commit_extension_control_layers((), **arguments)
        assert activation_store.read(store) is None
        monkeypatch.setattr(store, "_write_and_verify_anchor", write_anchor)
        if failure in {"key-unavailable", "lineage-conflict"}:
            from codex_plugin_scanner.guard.catalog_delivery import activation_journal
            from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

            table_names = (
                "extension_control_authority_snapshot",
                "extension_control_authority_transition",
                "extension_command_pack_pending",
                "extension_control_pack_reservation_archive",
            )

            def retained_rows():
                with store._connect() as connection:
                    return {
                        name: [tuple(row) for row in connection.execute(f"select * from {name}")]
                        for name in table_names
                    }

            before = retained_rows()
            code = (
                "native_command_control_authority_key_unavailable"
                if failure == "key-unavailable"
                else "native_command_pack_activation_conflict"
            )

            def unavailable(*args, **kwargs):
                raise NativePolicySnapshotError(code)

            with monkeypatch.context() as transient:
                transient.setattr(
                    activation_journal, "_key" if failure == "key-unavailable" else "write_in_transaction", unavailable
                )
                with pytest.raises(NativePolicySnapshotError, match=code):
                    store.recover_extension_control_authority(
                        catalog_digest=registry.catalog_digest, migration_registry=registry
                    )
            assert retained_rows() == before
            recovered = store.recover_extension_control_authority(
                catalog_digest=registry.catalog_digest, migration_registry=registry
            )
            assert recovered.health is AuthorityHealth.PROTECTED
            assert recovered.revision == 1
        if failure in {"missing", "corrupt"}:
            with store._connect() as connection:
                if failure == "missing":
                    connection.execute("delete from extension_command_pack_pending")
                else:
                    connection.execute("update extension_command_pack_pending set record_mac=?", ("f" * 64,))
            recovered = store.recover_extension_control_authority(
                catalog_digest=registry.catalog_digest, migration_registry=registry
            )
            assert recovered.health is AuthorityHealth.PROTECTED
            assert recovered.revision == 0
            with store._connect() as connection:
                assert connection.execute("select count(*) from extension_command_pack_pending").fetchone()[0] == 0
                assert (
                    connection.execute("select count(*) from extension_control_pack_reservation_archive").fetchone()[0]
                    == 1
                )
            arguments["pack_activation"] = None
            arguments["proof"] = _proof(
                store,
                (),
                revision=0,
                key="after-reset",
                actor_id="unit-admin",
                nonce="after-reset-nonce",
                catalog_digest=registry.catalog_digest,
            )
            arguments["idempotency_key"] = "after-reset"
            arguments["nonce"] = "after-reset-nonce"
    view = (
        recovered
        if failure in {"key-unavailable", "lineage-conflict"}
        else store.commit_extension_control_layers((), **arguments)
    )
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1
    active = activation_store.read(store)
    if failure in {"missing", "corrupt"}:
        assert active is None
    else:
        assert active.record_digest == draft.digest
        assert active.metadata == prepared.metadata
    with store._connect() as connection:
        assert connection.execute("select count(*) from extension_command_pack_pending").fetchone()[0] == 0
        assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 6
