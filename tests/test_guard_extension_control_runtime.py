from __future__ import annotations

import threading
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
    assert first.private_evidence.managed_revision == 0
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
    degraded = runtime.refresh(_view(0, health=AuthorityHealth.TAMPERED))
    assert degraded.health is AuthorityHealth.TAMPERED
    assert runtime.current() is degraded
    with pytest.raises(ValueError, match="move backwards"):
        runtime.refresh(_view(3, state=ControlState.ENABLED))
    assert runtime.refresh(_view(5, state=ControlState.ENABLED)).revision == 5


def test_recovery_replacement_allows_rollback_only_from_recovery_state() -> None:
    runtime = ExtensionControlRuntime(_view(9, state=ControlState.DISABLED))
    with pytest.raises(ValueError, match="not awaiting recovery"):
        runtime.replace_after_recovery(_view(4, state=ControlState.ENABLED))

    runtime.refresh(_view(9, health=AuthorityHealth.RECOVERY_REQUIRED))
    with pytest.raises(ValueError, match="not protected"):
        runtime.replace_after_recovery(_view(4, health=AuthorityHealth.RECOVERY_REQUIRED))

    recovered = runtime.replace_after_recovery(_view(4, state=ControlState.ENABLED))

    assert recovered.health is AuthorityHealth.PROTECTED
    assert recovered.revision == 4
    with pytest.raises(ValueError, match="move backwards"):
        runtime.refresh(_view(3, state=ControlState.ENABLED))


def test_refresh_accepts_monotonic_managed_activation_without_local_revision_change() -> None:
    initial = _view(3, state=ControlState.ENABLED)
    runtime = ExtensionControlRuntime(initial)
    initial_digest = runtime.current().effective_digest
    managed = ExtensionControlAuthorityView(
        initial.health,
        initial.revision,
        initial.catalog_digest,
        initial.layers,
        1,
    )

    refreshed = runtime.refresh(managed)

    assert refreshed.revision == 3
    assert refreshed.managed_revision == 1
    assert refreshed.effective_digest != initial_digest
    assert runtime.current() is refreshed


def test_higher_local_revision_cannot_mask_managed_revision_rollback() -> None:
    initial = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
        2,
    )
    runtime = ExtensionControlRuntime(initial)

    with pytest.raises(ValueError, match="cannot move backwards"):
        runtime.refresh(
            ExtensionControlAuthorityView(
                AuthorityHealth.PROTECTED,
                5,
                BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
                (),
                1,
            )
        )


def test_current_waits_for_commit_and_atomic_snapshot_swap() -> None:
    initial = _view(3, state=ControlState.ENABLED)
    runtime = ExtensionControlRuntime(initial)
    candidate = ExtensionControlAuthorityView(
        initial.health,
        4,
        initial.catalog_digest,
        initial.layers,
    )
    commit_entered = threading.Event()
    allow_commit = threading.Event()
    reader_started = threading.Event()
    reader_finished = threading.Event()
    observed: list[int] = []

    def commit() -> None:
        commit_entered.set()
        assert allow_commit.wait(timeout=1)

    def publish() -> None:
        runtime.publish_after_commit(candidate, commit)

    def read_current() -> None:
        reader_started.set()
        observed.append(runtime.current().revision)
        reader_finished.set()

    publisher = threading.Thread(target=publish)
    publisher.start()
    assert commit_entered.wait(timeout=1)
    reader = threading.Thread(target=read_current)
    reader.start()
    assert reader_started.wait(timeout=1)
    assert not reader_finished.wait(timeout=0.05)

    allow_commit.set()
    publisher.join(timeout=1)
    reader.join(timeout=1)

    assert not publisher.is_alive()
    assert not reader.is_alive()
    assert observed == [4]


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


def test_daemon_starts_fail_closed_with_future_authority_schema(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.read_extension_control_authority(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    with store._connect() as connection:
        connection.execute("update extension_control_schema_migration set version = 99 where singleton = 1")

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        snapshot = daemon._server.extension_control_runtime.current()
        assert snapshot.health is AuthorityHealth.TAMPERED
        assert snapshot.authority_failure is ResolverFailureCode.AUTHORITY_TAMPERED
    finally:
        daemon.stop()


def test_daemon_refreshes_resident_snapshot_after_external_authority_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=0,
        extension_control_refresh_interval_seconds=0.01,
    )
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
            "read_extension_control_authority_for_registry",
            lambda registry: updated,
        )
        deadline = time.monotonic() + 1
        while daemon._server.extension_control_runtime.current().revision != 7:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert daemon._server.extension_control_runtime.current().revision == 7
    finally:
        daemon.stop()
