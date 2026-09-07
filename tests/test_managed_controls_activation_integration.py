from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
    MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY,
)
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import CAPABILITIES as _CAPABILITIES
from tests.managed_controls_activation_support import activate_managed_bundle as _activate
from tests.managed_controls_activation_support import managed_bundle as _bundle
from tests.managed_controls_activation_support import parse_managed_bundle as _parsed


def test_atomic_activation_persists_complete_projection_and_runtime_composes_it(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()

    assert _activate(store, bundle) is True

    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    assert active["complete"] is True
    assert active["ruleTargets"] == [
        {
            "ruleId": "force-push-review",
            "extensionIds": ["command.git"],
            "permissionIds": ["command.git.permission.force-push"],
        }
    ]
    assert active["provenance"] == {
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": 7,
        "payloadHash": bundle["payloadHash"],
        "policyRevision": 7,
        "workspaceId": "workspace-managed-controls",
    }
    acknowledgement = active["acknowledgement"]
    assert isinstance(acknowledgement, dict)
    assert acknowledgement["extensionAuthorityRevision"] == 1
    assert acknowledgement["catalogDigest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert len(str(acknowledgement["effectiveProjectionDigest"])) == 64
    assert store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY) == active

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert view.managed_revision == 1
    signed_layer = next(layer for layer in view.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
    assert signed_layer.controls[0].state is ControlState.DISABLED


def test_failed_partial_activation_retains_prior_complete_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = _bundle()
    assert _activate(store, first) is True
    active_before = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    policy_before = store.get_sync_payload("policy_bundle")

    second = _bundle()
    second["bundleVersion"] = 8
    second["bundleHash"] = "sha256:" + "c" * 64
    original_replace = store._replace_remote_policy_rows_locked  # pyright: ignore[reportPrivateUsage]

    def replace_and_fail(
        connection: sqlite3.Connection,
        rows: Sequence[tuple[object, ...]],
    ) -> None:
        original_replace(connection, rows)
        _ = connection.execute(
            """
            create temp trigger fail_managed_activation
            before insert on sync_state
            when new.state_key = 'managed_controls_active'
            begin
              select raise(abort, 'injected managed activation failure');
            end
            """
        )

    monkeypatch.setattr(store, "_replace_remote_policy_rows_locked", replace_and_fail)

    with pytest.raises(sqlite3.IntegrityError, match="injected managed activation failure"):
        _ = _activate(store, second)

    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active_before
    assert store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY) == active_before
    assert store.get_sync_payload("policy_bundle") == policy_before


def test_runtime_composes_signed_cloud_restriction_with_local_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()
    assert _activate(store, bundle) is True
    local_layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(
                    ControlTargetKind.PERMISSION,
                    "command.git.permission.force-push",
                ),
                ControlState.ENABLED,
            ),
        ),
    )
    local_view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (local_layer,),
    )

    effective = store._with_managed_controls_activation(local_view)  # pyright: ignore[reportPrivateUsage]
    resolution = resolve_extension_controls(
        effective.layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=("command.git",),
        permission_ids=("command.git.permission.force-push",),
        surface=ControlSurface.COMMAND_EVALUATION,
    )

    assert effective.managed_revision == 1
    assert {layer.kind for layer in effective.layers} == {
        ControlLayerKind.LOCAL_ADMIN,
        ControlLayerKind.SIGNED_CLOUD,
    }
    assert resolution.blocked is True


def test_activation_requires_protected_local_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()

    activated = store.apply_policy_bundle_authority(
        [],
        "2026-08-23T12:00:00Z",
        policy_bundle=bundle,
        policy_bundle_keyring={"keys": []},
        cloud_exceptions=[],
        policy_bundle_ack={"bundleHash": bundle["bundleHash"], "status": "applied"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        managed_controls_policy=_parsed(bundle),
        managed_controls_negotiated_capabilities=_CAPABILITIES,
        remote_write_authorized=True,
    )

    assert activated is None
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is None


def test_tampered_authenticated_activation_fails_closed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()
    assert _activate(store, bundle) is True
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    active["signedCloudLayersJson"] = "[]"
    store.set_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY, active, "2026-08-23T12:01:00Z")

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert view.health is AuthorityHealth.TAMPERED
    assert all(layer.kind is not ControlLayerKind.SIGNED_CLOUD for layer in view.layers)


def test_clear_removes_active_and_negotiation_but_retains_lkg(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()
    assert _activate(store, bundle) is True
    lkg = store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY)
    runtime = ExtensionControlRuntime(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )

    store.clear_policy_bundle_authority(
        "2026-08-23T12:01:00Z",
        policy_bundle_last_error={"reason": "cleared"},
        managed_controls_publish=runtime.publish_after_commit,
    )

    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is None
    assert store.get_sync_payload(MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY) is None
    assert store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY) == lkg
    assert runtime.current().managed_revision == 2
    assert all(layer.kind is not ControlLayerKind.SIGNED_CLOUD for layer in runtime.current().layers)

    assert _activate(store, bundle) is True
    reactivated_lkg = store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY)
    store.clear_cloud_sync_state_for_reconnect()
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is None
    assert store.get_sync_payload(MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY) is None
    assert store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY) == reactivated_lkg


def test_non_v2_activation_clears_managed_state_but_retains_lkg(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = _bundle()
    assert _activate(store, bundle) is True
    lkg = store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY)
    runtime = ExtensionControlRuntime(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )

    assert store.apply_policy_bundle_authority(
        [],
        "2026-08-23T12:02:00Z",
        policy_bundle=bundle,
        policy_bundle_keyring={"keys": []},
        cloud_exceptions=[],
        policy_bundle_ack={"bundleHash": bundle["bundleHash"], "status": "applied"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=False,
        managed_controls_policy=None,
        managed_controls_publish=runtime.publish_after_commit,
        remote_write_authorized=True,
    )
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is None
    assert store.get_sync_payload(MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY) is None
    assert store.get_sync_payload(MANAGED_CONTROLS_LAST_GOOD_STATE_KEY) == lkg
    assert runtime.current().managed_revision == 2
    assert all(layer.kind is not ControlLayerKind.SIGNED_CLOUD for layer in runtime.current().layers)


def test_runtime_publish_failure_rolls_back_database_activation(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = _bundle()
    assert _activate(store, first) is True
    active_before = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    policy_before = store.get_sync_payload("policy_bundle")
    second = _bundle()
    second["bundleVersion"] = 8
    second["bundleHash"] = "sha256:" + "d" * 64

    def reject_publish(
        _view: ExtensionControlAuthorityView,
        _commit: object,
    ) -> object:
        raise ValueError("injected runtime publish failure")

    with pytest.raises(ValueError, match="injected runtime publish failure"):
        store.apply_policy_bundle_authority(
            [],
            "2026-08-23T12:02:00Z",
            policy_bundle=second,
            policy_bundle_keyring={"keys": []},
            cloud_exceptions=[],
            policy_bundle_ack={"bundleHash": second["bundleHash"], "status": "applied"},
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(second),
            update_last_good=True,
            managed_controls_policy=_parsed(second),
            managed_controls_negotiated_capabilities=_CAPABILITIES,
            managed_controls_publish=reject_publish,
            remote_write_authorized=True,
        )

    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active_before
    assert store.get_sync_payload("policy_bundle") == policy_before


def test_commit_failure_does_not_publish_staged_runtime(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = _bundle()
    assert _activate(store, first) is True
    active_before = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    policy_before = store.get_sync_payload("policy_bundle")
    runtime = ExtensionControlRuntime(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    runtime_before = runtime.current()
    second = _bundle()
    second["bundleVersion"] = 8
    second["bundleHash"] = "sha256:" + "f" * 64

    def fail_commit() -> None:
        raise sqlite3.OperationalError("injected commit failure")

    def publish_with_failed_commit(
        view: ExtensionControlAuthorityView,
        _commit: object,
    ) -> object:
        return runtime.publish_after_commit(view, fail_commit)

    with pytest.raises(sqlite3.OperationalError, match="injected commit failure"):
        store.apply_policy_bundle_authority(
            [],
            "2026-08-23T12:03:00Z",
            policy_bundle=second,
            policy_bundle_keyring={"keys": []},
            cloud_exceptions=[],
            policy_bundle_ack={"bundleHash": second["bundleHash"], "status": "applied"},
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(second),
            update_last_good=True,
            managed_controls_policy=_parsed(second),
            managed_controls_negotiated_capabilities=_CAPABILITIES,
            managed_controls_publish=publish_with_failed_commit,
            remote_write_authorized=True,
        )

    assert runtime.current() == runtime_before
    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) == active_before
    assert store.get_sync_payload("policy_bundle") == policy_before


def test_stale_refresh_cannot_undo_activation_or_resurrect_cleared_authority(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        key=None,
    )
    stale_base = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    runtime = ExtensionControlRuntime(stale_base)
    bundle = _bundle()

    assert _activate(
        store,
        bundle,
        managed_controls_publish=runtime.publish_after_commit,
    )
    stale_signed = runtime.current()
    assert stale_signed.managed_revision == 1
    with pytest.raises(ValueError, match="cannot move backwards"):
        runtime.refresh(stale_base)

    store.clear_policy_bundle_authority(
        "2026-08-23T12:04:00Z",
        policy_bundle_last_error={"reason": "cleared"},
        managed_controls_publish=runtime.publish_after_commit,
    )
    assert runtime.current().managed_revision == 2
    assert all(layer.kind is not ControlLayerKind.SIGNED_CLOUD for layer in runtime.current().layers)
    with pytest.raises(ValueError, match="cannot move backwards"):
        runtime.refresh(
            ExtensionControlAuthorityView(
                stale_signed.health,
                stale_signed.revision,
                stale_signed.catalog_digest,
                stale_signed.layers,
                stale_signed.managed_revision,
            )
        )


def test_reconnect_clear_publishes_before_failed_or_deferred_sync(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store._bootstrap_extension_control_authority(  # pyright: ignore[reportPrivateUsage]
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        key=None,
    )
    runtime = ExtensionControlRuntime(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    assert _activate(
        store,
        _bundle(),
        managed_controls_publish=runtime.publish_after_commit,
    )

    store.clear_cloud_sync_state_for_reconnect(
        now="2026-08-23T12:05:00Z",
        managed_controls_publish=runtime.publish_after_commit,
    )

    assert store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY) is None
    assert runtime.current().managed_revision == 2
    assert all(layer.kind is not ControlLayerKind.SIGNED_CLOUD for layer in runtime.current().layers)
    restarted = ExtensionControlRuntime(
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    )
    assert restarted.current() == runtime.current()


def test_replayed_authenticated_activation_cannot_rollback_durable_epoch(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = _bundle()
    assert _activate(store, first)
    saved_first = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(saved_first, dict)
    second = _bundle()
    second["bundleVersion"] = 8
    second["bundleHash"] = "sha256:" + "9" * 64
    assert _activate(store, second)

    store.set_sync_payload(
        MANAGED_CONTROLS_ACTIVE_STATE_KEY,
        saved_first,
        "2026-08-23T12:06:00Z",
    )

    restored = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert restored.health is AuthorityHealth.TAMPERED


def test_activation_and_epoch_are_read_from_one_sqlite_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    assert _activate(store, _bundle())

    def reject_independent_state_read(_state_key: str) -> object:
        raise AssertionError("managed activation state must use one SQLite snapshot")

    monkeypatch.setattr(store, "get_sync_payload", reject_independent_state_read)

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert view.health is AuthorityHealth.PROTECTED
    assert view.managed_revision == 1


def test_cleared_epoch_hides_legacy_raw_signed_layers_on_restart(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    assert _activate(store, _bundle())
    store.clear_policy_bundle_authority(
        "2026-08-23T12:07:00Z",
        policy_bundle_last_error={"reason": "cleared"},
    )
    raw = store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    legacy_signed = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.SIGNED_CLOUD,
        raw.catalog_digest,
        False,
        (),
    )
    projected = store._with_managed_controls_activation(  # pyright: ignore[reportPrivateUsage]
        ExtensionControlAuthorityView(
            raw.health,
            raw.revision,
            raw.catalog_digest,
            (*raw.layers, legacy_signed),
        )
    )

    assert projected.managed_revision == 2
    assert all(layer.kind is not ControlLayerKind.SIGNED_CLOUD for layer in projected.layers)
