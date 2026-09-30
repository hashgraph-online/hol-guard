"""Verified publisher projection under the cross-process mutation fence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from .native_command_control_authority import ZERO_DIGEST, floor_link_digest
from .native_command_control_authority_io import NativeCommandControlMutationRequiredError
from .native_command_control_authority_store import (
    _key,
    commit_native_command_control_projection,
    read_committed_projection_authority,
    read_native_control_floor,
)
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .runtime.extension_control_authority import AuthorityHealth
from .runtime.extension_control_runtime import ExtensionControlRuntime, ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from .native_command_control_binding import NativeCommandProgramMetadata
    from .store import GuardStore


class NativeCommandControlRuntime(ExtensionControlRuntime):
    """Retain the protected epoch together with both ordinary revision floors."""

    authority: Mapping[str, object] | None = None


def _recoverable_epoch(
    store: GuardStore,
    previous: Mapping[str, object],
    candidate: Mapping[str, object],
    binding: Mapping[str, object],
) -> bool:
    epoch, revision = cast(int, candidate["epoch"]), cast(int, candidate["mutation_revision"])
    if epoch < cast(int, previous["epoch"]) or revision < cast(int, previous["mutation_revision"]):
        raise NativePolicySnapshotError("native_command_control_authority_regressed")
    if epoch == previous["epoch"]:
        if (
            previous["authority_key_id"] != ZERO_DIGEST
            and candidate["authority_key_id"] != previous["authority_key_id"]
        ) or candidate["recovery"] != previous["recovery"]:
            raise NativePolicySnapshotError("native_command_control_authority_reused")
        return False
    recovery = candidate["recovery"]
    if not isinstance(recovery, Mapping) or revision <= cast(int, previous["mutation_revision"]):
        raise NativePolicySnapshotError("native_command_control_recovery_invalid")
    floor = read_native_control_floor(store, _key(store))
    floor_authority = floor.get("authority") if floor else None
    context = floor_authority if isinstance(floor_authority, Mapping) else {}
    # Another publisher may already have installed this recovery while this
    # process still retains its previous epoch. The current MAC-authenticated
    # floor preserves the exact admitted recovery proof and its predecessor.
    if (
        floor is not None
        and context.get("epoch") == epoch
        and context.get("authority_key_id") == candidate["authority_key_id"]
        and context.get("recovery") == recovery
        and floor.get("previous_floor_digest") == recovery["previous_floor_digest"]
        and cast(int, context["mutation_revision"]) <= revision
    ):
        local, managed = cast(int, binding["revision"]), cast(int, binding["managed_revision"])
        if binding["health"] == "protected" and (
            local < cast(int, floor["revision"])
            or managed < cast(int, floor["managed_revision"])
            or (
                local == floor["revision"]
                and managed == floor["managed_revision"]
                and binding["effective_digest"] != floor["effective_digest"]
            )
        ):
            raise NativePolicySnapshotError("native_command_control_revision_regressed")
        return True
    if (
        recovery["previous_floor_digest"] != floor_link_digest(floor)
        or recovery["previous_epoch"] != context.get("epoch", 0)
        or recovery["previous_mutation_revision"] != context.get("mutation_revision", 0)
        or recovery["previous_authority_key_id"] != context.get("authority_key_id", ZERO_DIGEST)
    ):
        raise NativePolicySnapshotError("native_command_control_recovery_floor_mismatch")
    return True


def read_control_projection(
    store: GuardStore,
    metadata: NativeCommandProgramMetadata,
    runtime: ExtensionControlRuntime | None,
) -> tuple[dict[str, object], ExtensionControlRuntime]:
    from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    if registry.catalog_digest != metadata.catalog_digest:
        raise NativePolicySnapshotError("native_command_control_catalog_mismatch")
    # Compile the frozen trusted target manifest before excluding native readers.
    store._catalog_target_manifest(registry)
    try:
        return _read_control_projection_locked(store, metadata, runtime, read_only=True)
    except NativeCommandControlMutationRequiredError:
        # No upgrade is attempted while holding SH. Re-read all authenticated
        # authority under a new EX lease before any semantic mutation/marker write.
        return _read_control_projection_locked(store, metadata, runtime, read_only=False)


def _read_control_projection_locked(
    store: GuardStore,
    metadata: NativeCommandProgramMetadata,
    runtime: ExtensionControlRuntime | None,
    *,
    read_only: bool,
) -> tuple[dict[str, object], ExtensionControlRuntime]:
    from .native_command_control_binding import build_native_command_control_binding
    from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    # All leases are released before the caller performs resident push IPC.
    with store._extension_control_authority_lock(shared=read_only):
        view = store.read_extension_control_authority_for_registry(
            BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=read_only
        )
        snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(view)
        binding = build_native_command_control_binding(snapshot, metadata)
        authority = (
            read_committed_projection_authority(store, binding)
            if read_only
            else commit_native_command_control_projection(store, binding)
        )
        previous = runtime.authority if isinstance(runtime, NativeCommandControlRuntime) else None
        recover = previous is not None and _recoverable_epoch(store, previous, authority, binding)
        if runtime is None or (recover and view.health is AuthorityHealth.PROTECTED):
            runtime = NativeCommandControlRuntime(view)
        else:
            try:
                snapshot = runtime.refresh(view)
            except ValueError as error:
                raise NativePolicySnapshotError("native_command_control_revision_regressed") from error
        if isinstance(runtime, NativeCommandControlRuntime) and (
            view.health is AuthorityHealth.PROTECTED or runtime.authority is None
        ):
            runtime.authority = authority
        binding["authority"] = authority
        return binding, runtime
