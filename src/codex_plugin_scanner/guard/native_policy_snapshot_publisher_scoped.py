"""Commit scoped publication only after source, resident, and epoch fences."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from .mdm.policy import managed_policy_cache_read_only
from .native_managed_capture import bind_configuration_origin
from .native_policy_authority_contract import NativePolicyAuthorityCapabilities
from .native_policy_authority_read import NativeVerifiedPolicyInputs, read_native_policy_authority_inputs
from .native_policy_decision_context import NativePolicyDecisionContext, capture_native_policy_decision
from .native_policy_snapshot_codec import _digest_v3
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .native_policy_snapshot_policy import effective_native_policy_v3
from .native_policy_snapshot_v4_generation import NativeV4Candidate, reserve_snapshot_v4
from .native_policy_snapshot_v4_transport import publish_snapshot_v4

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from .native_policy_snapshot_publisher_context import PublicationContext
    from .native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs
    from .policy_rule_identity import PolicyRuleIdentity

SCOPED_PUBLISH_FEATURES = frozenset({"policy-snapshot-v4", "policy-scoped-authority-v1", "hook-envelope-v3"})


@dataclass(frozen=True, slots=True)
class ScopedSnapshotBinding:
    generation: int
    policy_digest: str
    source_input_digest: str
    runtime_identity: str
    resident_generation: int
    mode: str
    command_extensions_bound: bool = False

    def to_request_binding(self) -> dict[str, object]:
        binding: dict[str, object] = {
            "generation": self.generation,
            "policy_digest": self.policy_digest,
            "source_input_digest": self.source_input_digest,
            "runtime_identity": self.runtime_identity,
            "resident_generation": self.resident_generation,
            "mode": self.mode,
        }
        if self.command_extensions_bound:
            binding["command_extensions_bound"] = True
        return binding


def _policy_fingerprint(config: Mapping[str, object]) -> tuple[str, str]:
    policy = effective_native_policy_v3(config)
    mode = "observe" if config.get("mode") == "observe" or policy["protection_posture"] == "watch" else "enforce"
    return cast(str, _digest_v3(policy)), mode


def compiled_scoped_policy(
    publisher: NativePolicySnapshotPublisherInputs,
    *,
    command_extensions: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], NativeVerifiedPolicyInputs]:
    inputs = read_native_policy_authority_inputs(
        publisher.store, now=publisher._wall_clock(), command_extensions=command_extensions
    )
    config = publisher._compiled_effective_policy(cloud_defaults=inputs.defaults)
    return config, bind_configuration_origin(config, inputs)


def scoped_policy_input_changed(
    publisher: NativePolicySnapshotPublisherInputs,
    *,
    force_republish: bool,
    command_extensions: Mapping[str, object] | None = None,
) -> bool:
    """Observe semantic changes off-path; receipt-only writes do not revoke readiness."""
    try:
        config, inputs = compiled_scoped_policy(publisher, command_extensions=command_extensions)
        fingerprint = _policy_fingerprint(config)
        source_digest = inputs.input_digest
    except (OSError, NativePolicySnapshotError, TypeError, ValueError, RuntimeError, sqlite3.Error):
        fingerprint, source_digest = ("unavailable", ""), None
    previous = publisher._observed_policy_fingerprint
    previous_source = publisher._observed_scoped_digest
    publisher._observed_policy_fingerprint = fingerprint
    publisher._observed_scoped_digest = source_digest
    changed = force_republish or previous != fingerprint or previous_source != source_digest
    if changed or source_digest is None:
        with publisher._condition:
            publisher._acked = False
            publisher._condition.notify_all()
    return changed


def _capture_metadata_equal(
    before: tuple[tuple[str, tuple[int, int, int, int] | None], ...],
    after: tuple[tuple[str, tuple[int, int, int, int] | None], ...],
    database_path: str,
) -> bool:
    # GuardStore refreshes private database/journal permissions on each connection.
    # This changes ctime without writing data. The held SQLite data_version
    # fence below independently detects commits, including a change-and-revert.
    database_paths = {database_path + suffix for suffix in ("", "-wal", "-shm", "-journal")}

    def normalize(values: tuple[tuple[str, tuple[int, int, int, int] | None], ...]) -> dict[str, object]:
        return {path: metadata[:3] if path in database_paths and metadata else metadata for path, metadata in values}

    return normalize(before) == normalize(after)


def publish_scoped(
    publisher: NativePolicySnapshotPublisher,
    context: PublicationContext,
    publish_epoch: int,
    renew_after_generation: int | None,
) -> None:
    """An ACK alone never opens readiness or supplies canonical provenance."""
    identity, capabilities, master_key, config, client, inputs, command_extensions = context
    from .native_policy_snapshot_publisher_context import capture_for_reservation

    def fresh_candidate(minimum: int | None, deadline: float) -> NativeV4Candidate:
        with capture_for_reservation(
            publisher,
            expected=context,
            publish_epoch=publish_epoch,
            deadline_monotonic=deadline,
        ) as captured:
            fresh_identity, fresh_capabilities, fresh_key, fresh_config, _, fresh_inputs, fresh_extensions = captured
            if not isinstance(fresh_inputs, NativeVerifiedPolicyInputs):
                raise NativePolicySnapshotError("native_policy_snapshot_inputs_changed")
            try:
                return reserve_snapshot_v4(
                    config=fresh_config,
                    guard_home=publisher.guard_home,
                    runtime_identity=fresh_identity.sha256,
                    rule_digest=fresh_capabilities.rule_digest,
                    master_key=fresh_key,
                    inputs=fresh_inputs,
                    capabilities=NativePolicyAuthorityCapabilities(
                        4,
                        frozenset(fresh_capabilities.features),
                        fresh_capabilities.extension_catalog_digest,
                    ),
                    issued_at_ms=int(publisher._wall_clock() * 1_000),
                    command_extensions=fresh_extensions,
                    minimum_generation=minimum,
                    deadline_monotonic=deadline,
                )
            finally:
                fresh_key = b""

    if not isinstance(inputs, NativeVerifiedPolicyInputs):
        raise NativePolicySnapshotError("native_policy_authority_input_invalid")
    before_resident = publisher._current_resident_fingerprint()
    try:
        publication = publish_snapshot_v4(
            config=config,
            guard_home=publisher.guard_home,
            executable=identity.path,
            runtime_identity=identity.sha256,
            rule_digest=capabilities.rule_digest,
            master_key=master_key,
            inputs=inputs,
            capabilities=NativePolicyAuthorityCapabilities(
                4, frozenset(capabilities.features), capabilities.extension_catalog_digest
            ),
            client=client,
            command_extensions=command_extensions,
            wall_clock=publisher._wall_clock,
            monotonic_clock=publisher._monotonic_clock,
            minimum_generation=renew_after_generation,
            candidate_factory=fresh_candidate,
        )
    finally:
        master_key = b""
    inputs = publication.candidate.inputs
    snapshot = publication.candidate.snapshot
    observed_resident = publisher._current_resident_fingerprint()
    observed_directory = publisher._resident_directory_fingerprint()
    with managed_policy_cache_read_only(), publisher.store._connect() as connection:
        data_version = connection.execute("pragma data_version").fetchone()[0]
        before_inputs = publisher._current_input_fingerprint()[0]
        current_extensions = publisher._compiled_command_extensions()
        if current_extensions != snapshot.get("command_extensions", {}):
            raise NativePolicySnapshotError("native_command_control_binding_changed")
        current_config, current_inputs = compiled_scoped_policy(publisher, command_extensions=current_extensions)
        after_inputs = publisher._current_input_fingerprint()[0]
        fingerprint = _policy_fingerprint(current_config)
        if (
            not _capture_metadata_equal(before_inputs, after_inputs, str(publisher.guard_home / "guard.db"))
            or connection.execute("pragma data_version").fetchone()[0] != data_version
        ):
            raise NativePolicySnapshotError("native_policy_authority_capture_changed")
        if current_inputs.input_digest != inputs.input_digest:
            raise NativePolicySnapshotError("native_policy_authority_source_changed")
        if fingerprint != (snapshot["config_digest"], snapshot["mode"]):
            raise NativePolicySnapshotError("native_policy_authority_config_changed")
        with publisher._condition:
            if publisher._closed or publisher._epoch != publish_epoch:
                return
            confirmed = publisher._confirm_resident_fingerprint(
                before_resident,
                observed_resident,
                publication.resident_generation,
                observed_directory,
            )
            generation_path = f"/generation-{publication.resident_generation:020d}.json"
            if confirmed is None or not any(path.endswith(generation_path) for path, _, _ in confirmed):
                raise NativePolicySnapshotError("native_policy_snapshot_resident_changed")
            # Resident confirmation also performs filesystem reads. Recheck the
            # publication epoch and complete source after those reads, off hook.
            if publisher._closed or publisher._epoch != publish_epoch:
                return
            if (
                publisher._current_input_fingerprint()[0] != after_inputs
                or connection.execute("pragma data_version").fetchone()[0] != data_version
            ):
                raise NativePolicySnapshotError("native_policy_authority_changed_during_publish")
            now_ms = int(publisher._wall_clock() * 1000)
            if cast(int, snapshot["expires_at_ms"]) <= now_ms or (
                current_inputs.expires_at_ms is not None and current_inputs.expires_at_ms <= now_ms
            ):
                raise NativePolicySnapshotError("native_policy_snapshot_expired")
            publisher._snapshot = snapshot
            publisher._v4_publication = publication
            publisher._v4_epoch = publish_epoch
            publisher._v4_binding = ScopedSnapshotBinding(
                cast(int, snapshot["generation"]),
                cast(str, snapshot["policy_digest"]),
                inputs.input_digest,
                cast(str, snapshot["runtime_identity"]),
                publication.resident_generation,
                cast(str, snapshot["mode"]),
                "command_extensions" in snapshot,
            )
            publisher._published_config_digest = fingerprint[0]
            publisher._published_policy_fingerprint = fingerprint
            publisher._observed_policy_fingerprint = fingerprint
            publisher._published_command_control_digest = _digest_v3(current_extensions)
            publisher._observed_command_control_digest = publisher._published_command_control_digest
            publisher._observed_scoped_digest = inputs.input_digest
            publisher._input_fingerprint = after_inputs, confirmed
            publisher._acked = True
            publisher._last_error = None
            publisher._renewal_after_generation = None
            publisher._failure_count = 0
            publisher._retry_not_before_monotonic = None
            publisher._schedule_renewal_locked(snapshot)
            publisher._condition.notify_all()


def scoped_binding(publisher: NativePolicySnapshotPublisher) -> dict[str, object] | None:
    """Read only already committed immutable values with the condition held."""
    if (
        publisher._closed
        or not publisher._acked
        or publisher._v4_publication is None
        or publisher._v4_epoch != publisher._epoch
        or publisher._v4_binding is None
    ):
        return None
    return publisher._v4_binding.to_request_binding()


def scoped_result_is_current(publisher: NativePolicySnapshotPublisher, binding: Mapping[str, object]) -> bool:
    """Fence all results, including defaults with no selected policy row."""
    expected = scoped_binding(publisher)
    publication = publisher._v4_publication
    if expected is None or publication is None:
        return False
    _ = expected.pop("mode")
    expected.pop("command_extensions_bound", None)
    expected["policy_generation"] = expected.pop("generation")
    if set(binding) != {*expected, "selected_decision_id"}:
        return False
    if any(type(binding[key]) is not type(value) or binding[key] != value for key, value in expected.items()):
        return False
    selected = binding["selected_decision_id"]
    return selected is None or (
        type(selected) is int
        and selected > 0
        and any(row.decision_id == selected for row in publication.candidate.inputs.authority.rows)
    )


def scoped_rule_identity(
    publisher: NativePolicySnapshotPublisher,
    binding: Mapping[str, object],
) -> PolicyRuleIdentity | None:
    """Resolve a selected row only from the exact accepted frozen publication."""
    if not scoped_result_is_current(publisher, binding) or publisher._v4_publication is None:
        return None
    selected = binding["selected_decision_id"]
    return next(
        (identity for row, identity in publisher._v4_publication.candidate.inputs.rule_identities if row == selected),
        None,
    )


def capture_scoped_decision(
    publisher: NativePolicySnapshotPublisher, binding: Mapping[str, object], receipt: object
) -> tuple[bool, NativePolicyDecisionContext | None]:
    """Capture attribution and result currency under one publication barrier."""
    with publisher._condition:
        publisher._mark_expired_locked()
        if not scoped_result_is_current(publisher, binding):
            return False, None
        identity = scoped_rule_identity(publisher, binding)
        if identity is None:
            return True, None
        context = capture_native_policy_decision(binding=binding, receipt=receipt, identity=identity)
        return context is not None, context
