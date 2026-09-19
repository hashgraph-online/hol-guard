"""Retain only a current source-free resident lease after a failed renewal."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from .mdm.policy import managed_policy_cache_read_only
from .native_policy_snapshot_constants import _REQUIRED_PUBLISH_FEATURES
from .native_policy_snapshot_publisher_context import CapturedV3PublicationInputs, _v3_inputs_from_capture
from .native_policy_snapshot_publisher_scoped import (
    _capture_metadata_equal,
    _policy_fingerprint,
    compiled_scoped_policy,
)
from .native_policy_snapshot_source_requirement import refresh_source_requirement

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def retain_source_free_v3_lease(
    publisher: NativePolicySnapshotPublisher, *, publish_epoch: int, renew_after_generation: int | None
) -> bool:
    """Observe the old accepted lease; never open a closed readiness barrier."""
    with publisher._condition:
        snapshot = publisher._snapshot
        inputs = publisher._published_cloud_inputs
        source_fingerprint = publisher._published_v3_source_fingerprint
        resident_generation = publisher._published_v3_resident_generation
        resident_fingerprint = publisher._published_v3_resident_fingerprint
        if (
            publisher._closed
            or not publisher._acked
            or publisher._epoch != publish_epoch
            or publisher._scoped_publication_enabled
            or publisher._source_authority_required
            or publisher._source_memory_required
            or snapshot is None
            or renew_after_generation != snapshot.get("generation")
            or source_fingerprint is None
            or resident_generation is None
            or resident_fingerprint is None
            or not isinstance(inputs, CapturedV3PublicationInputs)
            or inputs.source_identity is not None
            or inputs.defaults is not None
            or not _unexpired(publisher, snapshot.get("expires_at_ms"))
        ):
            return False
    try:
        if not _runtime_matches(publisher, snapshot):
            return False
        with managed_policy_cache_read_only(), publisher.store._connect() as observer:
            version = observer.execute("pragma data_version").fetchone()[0]
            before = publisher._current_input_fingerprint()
            refresh_source_requirement(publisher)
            command_extensions = publisher._compiled_command_extensions()
            if command_extensions != snapshot.get("command_extensions", {}):
                return False
            config, captured_inputs = compiled_scoped_policy(publisher)
            current_inputs = _v3_inputs_from_capture(
                publisher,
                captured_inputs,
                allow_signed_defaults=False,
                command_extensions=command_extensions,
            )
            after = publisher._current_input_fingerprint()
            directory = publisher._resident_directory_fingerprint()
            if (
                current_inputs != inputs
                or _policy_fingerprint(config) != (snapshot.get("config_digest"), snapshot.get("mode"))
                # Historical database journal metadata may change when a
                # connection closes. Its authoritative contents are bound by
                # the complete input digest and the current data-version fence.
                or _external_source_metadata(source_fingerprint, str(publisher.store.path))
                != _external_source_metadata(before[0], str(publisher.store.path))
                or not _capture_metadata_equal(before[0], after[0], str(publisher.store.path))
                or before[1] != resident_fingerprint
                or after[1] != resident_fingerprint
                or observer.execute("pragma data_version").fetchone()[0] != version
            ):
                return False
            with publisher._condition:
                if (
                    publisher._closed
                    or not publisher._acked
                    or publisher._epoch != publish_epoch
                    or publisher._snapshot is not snapshot
                    or publisher._scoped_publication_enabled
                    or publisher._source_authority_required
                    or publisher._source_memory_required
                ):
                    return False
                if (
                    publisher._confirm_resident_fingerprint(
                        resident_fingerprint, after[1], resident_generation, directory
                    )
                    is None
                ):
                    return False
                # Confirmation is an observation too: fence source, resident,
                # epoch and expiry again after its final filesystem reads.
                return (
                    _runtime_matches(publisher, snapshot)
                    and not publisher._closed
                    and publisher._acked
                    and publisher._epoch == publish_epoch
                    and publisher._snapshot is snapshot
                    and not publisher._source_authority_required
                    and not publisher._source_memory_required
                    and not publisher._scoped_publication_enabled
                    and publisher._current_input_fingerprint() == after
                    and observer.execute("pragma data_version").fetchone()[0] == version
                    and _unexpired(publisher, snapshot.get("expires_at_ms"))
                )
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error):
        return False


def _unexpired(publisher: NativePolicySnapshotPublisher, expires: object) -> bool:
    return type(expires) is int and expires > int(publisher._wall_clock() * 1_000)


def _runtime_matches(publisher: NativePolicySnapshotPublisher, snapshot: dict[str, object]) -> bool:
    status_provider = publisher._status_provider
    if status_provider is None:
        from .native_runtime import native_runtime_status

        status_provider = native_runtime_status
    status = status_provider()
    identity, capabilities = getattr(status, "identity", None), getattr(status, "capabilities", None)
    return bool(
        getattr(status, "mode", None) in {"auto", "force", "shadow"}
        and getattr(status, "available", False)
        and getattr(status, "compatible", False)
        and identity is not None
        and capabilities is not None
        and identity.sha256 == snapshot.get("runtime_identity")
        and capabilities.rule_digest == snapshot.get("rule_digest")
        and _REQUIRED_PUBLISH_FEATURES.issubset(frozenset(capabilities.features))
    )


def _external_source_metadata(
    fingerprint: tuple[tuple[str, tuple[int, int, int, int] | None], ...], database: str
) -> tuple[tuple[str, tuple[int, int, int, int] | None], ...]:
    database_paths = {database + suffix for suffix in ("", "-wal", "-shm", "-journal")}
    return tuple(item for item in fingerprint if item[0] not in database_paths)
