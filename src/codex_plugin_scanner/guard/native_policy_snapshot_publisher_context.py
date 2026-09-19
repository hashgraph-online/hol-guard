"""Resolve native publisher context and provision its derived verifier key."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .native_policy_snapshot_constants import NativePolicySnapshotError

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def provision_verifier_key(
    publisher: NativePolicySnapshotPublisher,
    provision: Callable[[Path, bytes], Path],
) -> None:
    material_getter = getattr(publisher.store, "_policy_integrity_secret_material", None)
    if not callable(material_getter):
        raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
    material: object = None
    master_key: bytes | None = None
    try:
        material = material_getter(create=True)
        if (
            not isinstance(material, tuple)
            or len(material) != 2
            or not isinstance(material[0], bytes)
            or not isinstance(material[1], str)
        ):
            raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
        master_key = material[0]
        provision(publisher.guard_home, master_key)
    finally:
        # Keep the master key only for the derivation call.  The derived
        # verifier is the only value written to native runtime state.
        master_key = None
        material = None


def publication_context(
    publisher: NativePolicySnapshotPublisher,
    *,
    required_features: frozenset[str],
) -> tuple[Any, Any, bytes, Mapping[str, object], Mapping[str, object], Callable[..., bytes | None]] | None:
    status_provider = publisher._status_provider
    if status_provider is None:
        from .native_runtime import native_runtime_status

        status_provider = native_runtime_status
    status = status_provider()
    if getattr(status, "mode", None) not in {"auto", "force", "shadow"}:
        publisher._record_error("native_policy_snapshot_native_disabled")
        return None
    identity = getattr(status, "identity", None)
    capabilities = getattr(status, "capabilities", None)
    if (
        not getattr(status, "available", False)
        or not getattr(status, "compatible", False)
        or identity is None
        or capabilities is None
    ):
        publisher._record_error("native_policy_snapshot_runtime_unavailable")
        return None
    if not required_features.issubset(set(getattr(capabilities, "features", ()))):
        with publisher._condition:
            publisher._acked = False
        publisher._record_error("native_policy_snapshot_protocol_unsupported")
        return None
    material_getter = getattr(publisher.store, "_policy_integrity_secret_material", None)
    if not callable(material_getter):
        publisher._record_error("native_policy_snapshot_integrity_key_unavailable")
        return None
    material: object = None
    try:
        material = material_getter(create=True)
        if (
            not isinstance(material, tuple)
            or len(material) != 2
            or not isinstance(material[0], bytes)
            or not isinstance(material[1], str)
        ):
            publisher._record_error("native_policy_snapshot_integrity_key_unavailable")
            return None
        config = publisher._compiled_effective_policy()
        command_extensions = publisher._compiled_command_extensions()
        client = publisher._client_request
        if client is None:
            from .native_resident_client import native_resident_client_request

            client = native_resident_client_request
        return identity, capabilities, material[0], config, command_extensions, client
    finally:
        material = None
