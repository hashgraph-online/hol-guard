"""Controls survive re-creation of guard.db through the authenticated last-good export."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_extension_control_last_good import LAST_GOOD_FILE_NAME

from .guard_extension_control_authority_fixtures import (
    MemorySecretStore,
    _allow_local_terminal_confirmation,  # noqa: F401
    _commit,
    _store,
)

_CATALOG = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest


def _recreate_database(tmp_path: Path, secrets: MemorySecretStore) -> GuardStore:
    for suffix in ("", "-wal", "-shm"):
        (tmp_path / f"guard.db{suffix}").unlink(missing_ok=True)
    fresh = GuardStore(tmp_path, prime_policy_integrity=False)
    fresh._extension_control_authority_secret_store = secrets
    return fresh


def test_recreated_database_restores_committed_controls(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    assert (tmp_path / LAST_GOOD_FILE_NAME).is_file()

    fresh = _recreate_database(tmp_path, secrets)
    view = fresh.read_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1
    local = next(layer for layer in view.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
    assert len(local.controls) == 1
    # A later change chains from the restored baseline.
    _commit(fresh, revision=1, key="change-2")
    assert fresh.read_extension_control_authority(catalog_digest=_CATALOG).revision == 2
    assert fresh.list_extension_control_authority_history(catalog_digest=_CATALOG)


def test_restore_rejects_export_that_does_not_match_the_anchor(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    export = tmp_path / LAST_GOOD_FILE_NAME
    stale = json.loads(export.read_text(encoding="utf-8"))
    _commit(store, revision=1, key="change-2")
    stale_text = json.dumps(stale)
    export.write_text(stale_text, encoding="utf-8")

    fresh = _recreate_database(tmp_path, secrets)
    view = fresh.read_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.TAMPERED
    assert view.layers == ()


def test_restore_rejects_edited_export(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    export = tmp_path / LAST_GOOD_FILE_NAME
    payload = json.loads(export.read_text(encoding="utf-8"))
    payload["layers_json"] = "[]"
    export.write_text(json.dumps(payload), encoding="utf-8")

    fresh = _recreate_database(tmp_path, secrets)

    assert fresh.read_extension_control_authority(catalog_digest=_CATALOG).health is AuthorityHealth.TAMPERED


def test_explicit_recovery_restores_before_resetting(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)

    fresh = _recreate_database(tmp_path, secrets)
    view = fresh.recover_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1
    assert fresh.extension_control_recovery_warnings == ()


def test_reset_keeps_unusable_export_aside_and_warns(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    # Losing the key makes the export unverifiable.
    secrets.values = {name: value for name, value in secrets.values.items() if ":authentication-key" not in name}

    fresh = _recreate_database(tmp_path, secrets)
    view = fresh.recover_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 0
    assert fresh.extension_control_recovery_warnings
    assert list(tmp_path.glob("extension-control-last-good.unapplied-*.json"))


def test_restore_at_a_later_revision_chains_further_changes(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    _commit(store, revision=1, key="change-2")

    fresh = _recreate_database(tmp_path, secrets)
    view = fresh.read_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 2
    _commit(fresh, revision=2, key="change-3")
    assert fresh.read_extension_control_authority(catalog_digest=_CATALOG).revision == 3


def test_recovery_survives_transition_rows_left_after_a_lost_snapshot_row(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _commit(store)
    with store._connect() as connection:
        connection.execute("delete from extension_control_authority_snapshot")

    view = store.recover_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.PROTECTED
