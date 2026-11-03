"""Abandoned prepared transitions and catalog flip-flops must not wedge or churn authority."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_extension_control_authority_transitions as transitions
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.store import GuardStore

from .guard_extension_control_authority_fixtures import (
    MemorySecretStore,
    _allow_local_terminal_confirmation,  # noqa: F401
    _commit,
    _disabled_layer,
    _store,
    _upgraded_registry,
)
from .test_guard_extension_control_api import _mutation_payload, _service

_CATALOG = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest


def _after_retry_window() -> str:
    """A rollback clock past the window in which a prepared row may be retried."""

    return (datetime.now(timezone.utc) + timedelta(seconds=301)).isoformat()


def _transition_count(store: GuardStore) -> int:
    with store._connect() as connection:
        return int(connection.execute("select count(*) from extension_control_authority_transition").fetchone()[0])


def _crash_after_prepare(store: GuardStore, secrets: MemorySecretStore, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail a save after its prepared row is written, as a process that died would.

    A save that fails in process takes its own row back; one that dies cannot,
    so the row is left for reads and later saves to deal with.
    """

    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1
    with monkeypatch.context() as patch:
        patch.setattr(store, "_roll_back_abandoned_transition", lambda *_args, **_kwargs: False)
        with pytest.raises(ExtensionControlAuthorityError, match="anchor"):
            _commit(store)


def test_catalog_flip_flop_with_no_layers_commits_no_revisions(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    other = _upgraded_registry()
    assert other.catalog_digest != _CATALOG

    for _ in range(3):
        for registry in (other, BUILT_IN_COMMAND_EXTENSION_REGISTRY):
            view = store.read_extension_control_authority_for_registry(registry)
            assert view.health is AuthorityHealth.PROTECTED
            assert view.revision == 0

    assert _transition_count(store) == 0


def test_commit_after_catalog_flip_flop_chains_normally(tmp_path: Path) -> None:
    store = _store(tmp_path, MemorySecretStore())
    store.read_extension_control_authority_for_registry(_upgraded_registry())

    _commit(store)

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1
    assert view.layers == (_disabled_layer(),)


def test_recent_prepared_transition_survives_reads_so_the_same_request_can_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _crash_after_prepare(store, secrets, monkeypatch)

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    # The row stays for its own retry, and the authority it never anchored
    # keeps enforcing in the meantime.
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 0
    assert _transition_count(store) == 1


def test_read_only_reads_keep_enforcing_while_a_prepared_row_waits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reader that cannot write must not turn an abandoned prepare into a global block.

    Hook-path reads take a shared lease, so they can never remove the row no
    matter how long it sits there. Reporting recovery to them would stop every
    command on the device, with no approval to offer, until a writer happened
    to run.
    """

    monkeypatch.setattr(transitions, "_now", _after_retry_window)
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _crash_after_prepare(store, secrets, monkeypatch)
    assert _transition_count(store) == 1
    # A reader under a shared lease asks for the rollback and gets nowhere,
    # however long the row has sat there.
    monkeypatch.setattr(store, "_roll_back_abandoned_transition", lambda *_args, **_kwargs: False)

    view = store.read_extension_control_authority_for_registry(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True
    )

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 0
    assert _transition_count(store) == 1


def test_abandoned_prepared_transition_is_rolled_back_on_next_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transitions, "_now", _after_retry_window)
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _crash_after_prepare(store, secrets, monkeypatch)
    assert _transition_count(store) == 1

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 0
    assert _transition_count(store) == 0
    _commit(store, key="change-2")
    assert store.read_extension_control_authority(catalog_digest=_CATALOG).revision == 1


def test_new_request_after_abandoned_transition_commits_without_manual_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transitions, "_now", _after_retry_window)
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    _crash_after_prepare(store, secrets, monkeypatch)

    _commit(store, key="change-2")

    view = store.read_extension_control_authority(catalog_digest=_CATALOG)
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1


def test_sealed_transition_is_finished_on_the_next_read(tmp_path: Path) -> None:
    """A prepared row is undecided; a sealed one is decided and only unrecorded.

    The save above dies before its anchor is written, so nothing says which
    revision was meant and the rollback window decides. This one dies on the
    final anchor write, after the row is committed and the proof consumed, so
    the revision it names is already authorised and verified. Holding that for
    a recovery verb blocks every command on the install for a bookkeeping flip
    nobody has to decide, so the next ordinary read finishes it instead.
    `test_read_finalizes_database_commit_when_final_anchor_write_failed` pins
    the rest of the resumed state.
    """

    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 2
    with pytest.raises(ExtensionControlAuthorityError, match="final anchor"):
        _commit(store)

    view = store.read_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1


def test_sealed_transition_under_another_catalog_answers_the_registry_that_asked(
    tmp_path: Path,
) -> None:
    """Finishing an interrupted commit must not hand the caller another catalog's controls.

    A registry read for a catalog the store is not on is answered by reading
    the catalog it is on first, so the resume that read asks for names the
    stored catalog's row. Returning the view it leaves would bind this
    registry to controls that were never composed for it.
    """

    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 2
    with pytest.raises(ExtensionControlAuthorityError, match="final anchor"):
        _commit(store)
    other = _upgraded_registry()
    assert other.catalog_digest != _CATALOG

    view = store.read_extension_control_authority_for_registry(other)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.catalog_digest == other.catalog_digest


def test_unexpected_apply_failure_returns_a_stable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(GuardStore(tmp_path / "guard-home"))

    def explode(_payload: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(service, "_apply_locked", explode)

    with pytest.raises(ExtensionControlApiError) as error:
        service.apply(_mutation_payload())
    assert error.value.status == 503
    assert error.value.code == "authority_apply_failed"
