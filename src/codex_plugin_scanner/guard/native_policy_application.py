"""Read current native application without publishing or promoting an ACK."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import TYPE_CHECKING

from .mdm.policy import managed_policy_cache_read_only
from .native_mode import native_mode_requires_rust
from .native_policy_authority_contract import NativePolicyAuthorityCapabilities
from .native_policy_bundle_acceptance import (
    NativeAcceptedPolicyBundle,
    accepted_policy_bundle_locked,
    capture_accepted_policy_bundle,
)
from .native_policy_publication_lock import hold_policy_publication_mutation
from .native_policy_snapshot_constants import _REQUIRED_PUBLISH_FEATURES, NativePolicySnapshotError
from .native_policy_snapshot_publisher_scoped import (
    SCOPED_PUBLISH_FEATURES,
    _capture_metadata_equal,
    _policy_fingerprint,
    compiled_scoped_policy,
)
from .policy_canonical_rollout import canonical_policy_enforcement_enabled

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher

_REQUIRED_FEATURES = (
    (_REQUIRED_PUBLISH_FEATURES - {"policy-snapshot-v3", "policy-snapshot-push-v1"})
    | SCOPED_PUBLISH_FEATURES
    | {"pre-tool-generic-authority-v1"}
)


def _current_runtime(
    publisher: NativePolicySnapshotPublisher, acceptance: NativeAcceptedPolicyBundle
) -> tuple[str, frozenset[str], str | None] | None:
    from .native_runtime import native_runtime_status

    status = (publisher._status_provider or native_runtime_status)()
    identity, capabilities = status.identity, status.capabilities
    if (
        not native_mode_requires_rust()
        or status.mode not in {"auto", "force"}
        or not status.available
        or not status.compatible
        or identity is None
        or capabilities is None
        or identity.sha256 != acceptance.binding.runtime_identity
        or not _REQUIRED_FEATURES.issubset(capabilities.features)
    ):
        return None
    publication = publisher._v4_publication
    if publication is None or publication.candidate.snapshot.get("rule_digest") != capabilities.rule_digest:
        return None
    return capabilities.rule_digest, frozenset(capabilities.features), capabilities.extension_catalog_digest


def current_native_policy_application(
    publisher: NativePolicySnapshotPublisher,
    *,
    bundle: Mapping[str, object],
    installation_id: str,
) -> tuple[NativeAcceptedPolicyBundle | None, str | None]:
    """Observe current accepted authority without refreshing managed caches."""
    with managed_policy_cache_read_only():
        return _observe_current_native_policy_application(publisher, bundle=bundle, installation_id=installation_id)


def _observe_current_native_policy_application(
    publisher: NativePolicySnapshotPublisher,
    *,
    bundle: Mapping[str, object],
    installation_id: str,
) -> tuple[NativeAcceptedPolicyBundle | None, str | None]:
    """Observe exact current authority; stored ACKs never provide this evidence.

    This off-hook read repeats the publisher's authenticated source, complete
    configuration, native identity/capability and resident generation fences.
    SQL data_version detects intervening commits, including change-and-revert.
    The final source and epoch check follows resident/runtime confirmation.
    """
    try:
        workspace = bundle.get("workspaceId")

        def lane_selected() -> bool:
            return isinstance(workspace, str) and canonical_policy_enforcement_enabled(
                device_id=installation_id, workspace_id=workspace
            )

        if not lane_selected():
            return None, "canonical_enforcement_disabled"
        accepted = capture_accepted_policy_bundle(publisher, bundle=bundle, installation_id=installation_id)
        if accepted is None:
            return None, "native_policy_publication_pending"
        runtime = _current_runtime(publisher, accepted)
        if runtime is None:
            return None, "native_policy_consumer_unavailable"
        with hold_policy_publication_mutation(publisher.guard_home), publisher.store._connect() as connection:
            version = connection.execute("pragma data_version").fetchone()[0]
            before = publisher._current_input_fingerprint()
            config, inputs = compiled_scoped_policy(publisher)
            after = publisher._current_input_fingerprint()
            _ = inputs.authority.for_snapshot(NativePolicyAuthorityCapabilities(4, runtime[1], runtime[2]))
            if (
                not _capture_metadata_equal(before[0], after[0], str(publisher.store.path))
                or before[1] != after[1]
                or inputs.input_digest != accepted.binding.source_input_digest
                or accepted.source not in inputs.sources
                or _policy_fingerprint(config) != (publisher._published_config_digest, accepted.binding.mode)
                or connection.execute("pragma data_version").fetchone()[0] != version
            ):
                return None, "native_policy_authority_changed"
            directory = publisher._resident_directory_fingerprint()
            with publisher._condition:
                confirmed = publisher._confirm_resident_fingerprint(
                    after[1], after[1], accepted.binding.resident_generation, directory
                )
                generation_path = f"/generation-{accepted.binding.resident_generation:020d}.json"
                if (
                    confirmed is None
                    or not any(path.endswith(generation_path) for path, _, _ in confirmed)
                    or _current_runtime(publisher, accepted) != runtime
                ):
                    return None, "native_policy_consumer_unavailable"
                now_ms = int(publisher._wall_clock() * 1000)
                if (
                    publisher._current_input_fingerprint() != after
                    or connection.execute("pragma data_version").fetchone()[0] != version
                    or accepted_policy_bundle_locked(publisher, bundle=bundle, installation_id=installation_id)
                    != accepted
                    or accepted.expires_at_ms <= now_ms
                    or (inputs.expires_at_ms is not None and inputs.expires_at_ms <= now_ms)
                ):
                    return None, "native_policy_authority_changed"
                if not lane_selected():
                    return None, "canonical_enforcement_disabled"
                return accepted, None
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error, NativePolicySnapshotError):
        return None, "native_policy_authority_unavailable"
