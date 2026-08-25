from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.custom_extension_continuity import (
    CustomExtensionContinuityError,
    apply_verified_custom_extension_continuity,
    record_local_custom_extension_mutation,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_custom_extension_continuity import _NOW, _bundle, _identity, _observe


def test_local_authority_change_during_settings_planning_aborts_cloud_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    identity = _identity()
    _observe(store, identity)
    original_read_grant = store.read_local_cli_grant
    injected = False

    def _commit_local_block(cli_id: str):
        nonlocal injected
        if not injected:
            injected = True
            concurrent = GuardStore(guard_home)
            assert (
                concurrent.upsert_local_cli_grant(
                    identity=identity,
                    state="blocked",
                    expected_revision=0,
                    updated_at=_NOW,
                    command_states={"deploy": "block"},
                )
                == 1
            )
        return original_read_grant(cli_id)

    monkeypatch.setattr(store, "read_local_cli_grant", _commit_local_block)
    with pytest.raises(CustomExtensionContinuityError, match="authority changed"):
        apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)

    restarted = GuardStore(guard_home)
    assert restarted.read_local_cli_grant(identity.cli_id)["state"] == "blocked"
    assert restarted.read_local_cli_command_states(identity.cli_id) == {"deploy": "block"}
    assert restarted.get_sync_payload("custom_extension_continuity") is None


def test_concurrent_revision_two_cannot_be_overwritten_by_preflighted_revision_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    identity = _identity()
    original_transaction = store.apply_custom_extension_continuity_transaction
    injected = False

    def _commit_revision_two(**kwargs):
        nonlocal injected
        if not injected:
            injected = True
            concurrent = GuardStore(guard_home)
            result = apply_verified_custom_extension_continuity(concurrent, _bundle(identity, revision=2), now=_NOW)
            assert result["cloud_revision"] == 2
        return original_transaction(**kwargs)

    monkeypatch.setattr(store, "apply_custom_extension_continuity_transaction", _commit_revision_two)
    with pytest.raises(CustomExtensionContinuityError, match="authority changed"):
        apply_verified_custom_extension_continuity(store, _bundle(identity, revision=1), now=_NOW)

    restarted = GuardStore(guard_home)
    state = restarted.get_sync_payload("custom_extension_continuity")
    assert state["cloud_revision"] == 2
    assert state["items"][identity.cli_id]["status"] == "pending_observation"
    assert restarted.read_local_cli_revision() == 0
    assert restarted.read_local_cli_grant(identity.cli_id) is None


def test_concurrent_cloud_revision_wins_over_preflighted_local_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    identity = _identity()
    _observe(store, identity)
    apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    authority_revision = store.read_local_cli_revision()
    original_transaction = store.apply_custom_extension_continuity_transaction
    injected = False

    def _commit_cloud_revision_two(**kwargs):
        nonlocal injected
        if not injected:
            injected = True
            concurrent = GuardStore(guard_home)
            result = apply_verified_custom_extension_continuity(concurrent, _bundle(identity, revision=2), now=_NOW)
            assert result["cloud_revision"] == 2
            assert concurrent.read_local_cli_revision() == authority_revision
        return original_transaction(**kwargs)

    monkeypatch.setattr(store, "apply_custom_extension_continuity_transaction", _commit_cloud_revision_two)
    with pytest.raises(CustomExtensionContinuityError, match="local mutation"):
        record_local_custom_extension_mutation(
            store,
            identity=identity,
            state="unset",
            expected_revision=authority_revision,
            command_states={},
            now=_NOW,
        )

    restarted = GuardStore(guard_home)
    assert restarted.get_sync_payload("custom_extension_continuity")["cloud_revision"] == 2
    assert restarted.get_sync_payload("custom_extension_continuity_local_removals") in (None, {})
    assert restarted.read_local_cli_grant(identity.cli_id)["state"] == "allowed"

    record_local_custom_extension_mutation(
        restarted,
        identity=identity,
        state="unset",
        expected_revision=restarted.read_local_cli_revision(),
        command_states={},
        now=_NOW,
    )
    final = GuardStore(guard_home)
    result = apply_verified_custom_extension_continuity(final, _bundle(identity, revision=2), now=_NOW)
    assert result["items"][identity.cli_id]["status"] == "removed"
    assert final.read_local_cli_grant(identity.cli_id) is None


def test_concurrent_cloud_revision_cannot_be_overwritten_by_cloud_field_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    identity = _identity()
    _observe(store, identity)
    apply_verified_custom_extension_continuity(store, _bundle(identity), now=_NOW)
    authority_revision = store.read_local_cli_revision()
    original_transaction = store.apply_custom_extension_continuity_transaction
    injected = False

    def _commit_cloud_revision_two(**kwargs):
        nonlocal injected
        if not injected:
            injected = True
            concurrent = GuardStore(guard_home)
            apply_verified_custom_extension_continuity(concurrent, _bundle(identity, revision=2), now=_NOW)
            assert concurrent.read_local_cli_revision() == authority_revision
        return original_transaction(**kwargs)

    monkeypatch.setattr(store, "apply_custom_extension_continuity_transaction", _commit_cloud_revision_two)
    with pytest.raises(CustomExtensionContinuityError, match="Cloud removal"):
        apply_verified_custom_extension_continuity(store, {"payload": {}}, now=_NOW)

    restarted = GuardStore(guard_home)
    state = restarted.get_sync_payload("custom_extension_continuity")
    assert state["cloud_revision"] == 2
    assert state["items"][identity.cli_id]["status"] == "applied"
    assert restarted.read_local_cli_grant(identity.cli_id)["state"] == "allowed"
