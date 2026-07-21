from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntime,
    ExtensionControlRuntimeSnapshot,
    current_extension_control_binding_digest,
    current_extension_control_snapshot,
    extension_control_policy_version,
    use_extension_control_snapshot,
)
from codex_plugin_scanner.guard.store import GuardStore

_CATALOG_DIGEST = "a" * 64


def _view(
    revision: int,
    *,
    health: AuthorityHealth = AuthorityHealth.PROTECTED,
    state: ControlState | None = None,
) -> ExtensionControlAuthorityView:
    controls = ()
    if state is not None:
        controls = (
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.test"),
                state=state,
            ),
        )
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=_CATALOG_DIGEST,
        global_lockdown=False,
        controls=controls,
    )
    return ExtensionControlAuthorityView(health, revision, _CATALOG_DIGEST, (layer,))


def test_snapshot_is_immutable_stable_and_carries_private_revision_evidence() -> None:
    runtime = ExtensionControlRuntime(_view(3, state=ControlState.ENABLED))

    first = runtime.current()
    second = runtime.current()

    assert first is second
    assert first.revision == 3
    assert len(first.effective_digest) == 64
    assert first.private_evidence.revision == 3
    assert first.private_evidence.effective_digest == first.effective_digest
    assert repr(first.private_evidence) == "ExtensionControlDecisionEvidence(<private>)"
    with pytest.raises(AttributeError):
        first.revision = 4  # pyright: ignore[reportAttributeAccessIssue]


def test_refresh_swaps_atomically_and_rejects_rollback_or_equivocation() -> None:
    runtime = ExtensionControlRuntime(_view(3, state=ControlState.ENABLED))
    previous = runtime.current()

    replacement = runtime.refresh(_view(4, state=ControlState.DISABLED))

    assert runtime.current() is replacement
    assert replacement is not previous
    assert replacement.revision == 4
    assert replacement.effective_digest != previous.effective_digest
    with pytest.raises(ValueError, match="move backwards"):
        runtime.refresh(_view(3, state=ControlState.ENABLED))
    with pytest.raises(ValueError, match="cannot be replaced"):
        runtime.refresh(_view(4, state=ControlState.ENABLED))
    assert runtime.current() is replacement


def test_snapshot_digest_is_independent_of_layer_and_control_order() -> None:
    controls = (
        ExtensionControl(
            target=ControlTarget(ControlTargetKind.EXTENSION, "command.test"),
            state=ControlState.ENABLED,
        ),
        ExtensionControl(
            target=ControlTarget(ControlTargetKind.PERMISSION, "command.test.permission.write"),
            state=ControlState.DISABLED,
        ),
    )
    local = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.LOCAL_ADMIN,
        _CATALOG_DIGEST,
        False,
        controls,
    )
    cloud = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.SIGNED_CLOUD,
        _CATALOG_DIGEST,
        False,
        tuple(reversed(controls)),
    )

    first = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 8, _CATALOG_DIGEST, (local, cloud))
    )
    second = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 8, _CATALOG_DIGEST, (cloud, local))
    )

    assert first.effective_digest == second.effective_digest


def test_active_snapshot_is_request_local_and_restored_after_evaluation() -> None:
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(_view(7))
    inactive_digest = current_extension_control_binding_digest()

    assert current_extension_control_snapshot() is None
    with use_extension_control_snapshot(snapshot):
        assert current_extension_control_snapshot() is snapshot
        assert current_extension_control_binding_digest() == snapshot.effective_digest
        assert extension_control_policy_version("policy.v1") == f"policy.v1@{snapshot.effective_digest}"

    assert current_extension_control_snapshot() is None
    assert current_extension_control_binding_digest() == inactive_digest


def test_authority_health_maps_to_fail_closed_runtime_failure() -> None:
    unavailable = ExtensionControlRuntimeSnapshot.from_authority_view(_view(0, health=AuthorityHealth.UNENROLLED))
    tampered = ExtensionControlRuntimeSnapshot.from_authority_view(_view(1, health=AuthorityHealth.TAMPERED))

    assert unavailable.authority_failure is ResolverFailureCode.AUTHORITY_UNAVAILABLE
    assert tampered.authority_failure is ResolverFailureCode.AUTHORITY_TAMPERED


def test_daemon_refreshes_resident_snapshot_after_external_authority_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon._extension_control_refresh_interval_seconds = 0.01
    daemon.start()
    try:
        updated = ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            7,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (),
        )
        monkeypatch.setattr(
            store,
            "read_extension_control_authority",
            lambda *, catalog_digest: updated,
        )
        deadline = time.monotonic() + 1
        while daemon._server.extension_control_runtime.current().revision != 7:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert daemon._server.extension_control_runtime.current().revision == 7
    finally:
        daemon.stop()
