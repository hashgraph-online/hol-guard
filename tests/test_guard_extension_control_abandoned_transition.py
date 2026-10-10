"""Abandoned prepared transitions and catalog flip-flops must not wedge or churn authority."""

from __future__ import annotations

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


def _transition_count(store: GuardStore) -> int:
    with store._connect() as connection:
        return int(connection.execute("select count(*) from extension_control_authority_transition").fetchone()[0])


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


def test_recent_prepared_transition_survives_reads_so_the_same_request_can_retry(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1
    with pytest.raises(ExtensionControlAuthorityError, match="anchor"):
        _commit(store)

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert view.health is AuthorityHealth.RECOVERY_REQUIRED
    assert _transition_count(store) == 1


def test_abandoned_prepared_transition_is_rolled_back_on_next_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transitions, "ABANDONED_TRANSITION_GRACE_SECONDS", 0.0)
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1
    with pytest.raises(ExtensionControlAuthorityError, match="anchor"):
        _commit(store)
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
    monkeypatch.setattr(transitions, "ABANDONED_TRANSITION_GRACE_SECONDS", 0.0)
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1
    with pytest.raises(ExtensionControlAuthorityError, match="anchor"):
        _commit(store)

    _commit(store, key="change-2")

    view = store.read_extension_control_authority(catalog_digest=_CATALOG)
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1


def test_anchored_transition_is_not_applied_without_explicit_recovery(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 2
    with pytest.raises(ExtensionControlAuthorityError, match="final anchor"):
        _commit(store)

    view = store.read_extension_control_authority(catalog_digest=_CATALOG)

    assert view.health is AuthorityHealth.RECOVERY_REQUIRED


def test_unexpected_apply_failure_returns_a_stable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(GuardStore(tmp_path / "guard-home"))

    def explode(_payload: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(service, "_apply_locked", explode)

    with pytest.raises(ExtensionControlApiError) as error:
        service.apply(_mutation_payload())
    assert error.value.status == 503
    assert error.value.code == "authority_apply_failed"
