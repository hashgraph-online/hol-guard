"""Asynchronous publication, acknowledgement and retry of native snapshots."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, cast

from .native_command_control_authority_io import hold_command_control_authority_lock
from .native_policy_snapshot_codec import _strict_json_loads_v3
from .native_policy_snapshot_constants import (
    _PUBLISH_RETRY_MAX_SECONDS,
    _REQUIRED_PUBLISH_FEATURES,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_direct_lane import (
    contained_sink_command,
    direct_lane_binding,
    direct_lane_integrity_key,
    local_cli_block_rules_present,
    with_direct_hook_state,
)
from .native_policy_snapshot_direct_lane_review import (
    recheckable_review_facts,
    review_facts_bound,
    with_review_facts,
)
from .native_policy_snapshot_direct_lane_saved import refresh_integrity_state, with_saved_decision_state
from .native_policy_snapshot_direct_lane_structured import (
    bound_structured_output_view,
    with_structured_output_view,
)
from .native_policy_snapshot_harness_postures import (
    HARNESS_POSTURES_BINDING_KEY,
    valid_harness_postures,
    write_harness_postures_sidecar,
)

if TYPE_CHECKING:
    from pathlib import Path

    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def _local_cli_revision_or_none(publisher: NativePolicySnapshotPublisher) -> int | None:
    try:
        return publisher._current_local_cli_revision()
    except (NativePolicySnapshotError, OSError, RuntimeError, ValueError, sqlite3.Error):
        # -1 is never a bound revision, so an unreadable one closes the lane.
        return -1


def _publisher_api():
    from . import native_policy_snapshot_publisher

    return native_policy_snapshot_publisher


class NativePolicySnapshotPublicationMixin:
    def _run(self) -> None:
        publisher = cast("NativePolicySnapshotPublisher", self)
        # ContextVar bindings from the starting thread do not propagate here;
        # rebind so observed-identity digests resolve this store's resident.
        from .native_context import bind_context_digest_home

        bind_context_digest_home(publisher.guard_home)
        while True:
            with publisher._condition:
                if publisher._closed:
                    return
                publisher._mark_expired_locked()
            fingerprint = publisher._current_input_fingerprint()
            if publisher._input_fingerprint is None:
                publisher._input_fingerprint = fingerprint
            elif fingerprint[1] != publisher._input_fingerprint[1]:
                publisher._accept_resident_fingerprint(fingerprint)
            elif fingerprint[0] != publisher._input_fingerprint[0]:
                previous_inputs = dict(publisher._input_fingerprint[0])
                current_inputs = dict(fingerprint[0])
                changed_paths = {
                    path
                    for path in previous_inputs.keys() | current_inputs.keys()
                    if previous_inputs.get(path) != current_inputs.get(path)
                }
                publisher._input_fingerprint = fingerprint
                if publisher._policy_input_changed(changed_paths):
                    publisher._republish_preserving_watch()
            if publisher._monotonic_clock() >= publisher._reconcile_due_monotonic:
                publisher._reconcile_due_monotonic = publisher._monotonic_clock() + 1.0
                if publisher._policy_input_changed():
                    publisher._republish_preserving_watch()
                publisher._recheck_direct_lane_local_cli(_local_cli_revision_or_none(publisher))
                publisher._recheck_direct_lane_review_facts()
                publisher._recheck_direct_lane_structured_output()
                publisher._recheck_direct_lane_mcp_relay()
                publisher._recheck_direct_lane_saved_state()
            with publisher._condition:
                if publisher._closed:
                    return
                publisher._mark_expired_locked()
                publisher._renew_direct_lane_ack()
                now = publisher._monotonic_clock()
                wait_seconds = publisher._poll_interval_seconds
                if publisher._retry_not_before_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, publisher._retry_not_before_monotonic - now),
                    )
                if publisher._acked and publisher._renewal_due_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, publisher._renewal_due_monotonic - now),
                    )
            publisher._publish_event.wait(timeout=wait_seconds)
            publisher._publish_event.clear()
            with publisher._condition:
                if publisher._closed:
                    return
                publisher._mark_expired_locked()
                publisher._renew_direct_lane_ack()
                now = publisher._monotonic_clock()
                if (
                    publisher._acked
                    and publisher._renewal_due_monotonic is not None
                    and now >= publisher._renewal_due_monotonic
                ):
                    snapshot = publisher._snapshot
                    generation = snapshot.get("generation") if snapshot is not None else None
                    publisher._renewal_due_monotonic = None
                    publisher._renewal_after_generation = (
                        generation if isinstance(generation, int) and generation > 0 else None
                    )
                    publisher._retry_not_before_monotonic = now
                    publisher._failure_count = 0
                should_publish = (
                    not publisher._closed
                    and (not publisher._acked or publisher._renewal_after_generation is not None)
                    and (publisher._retry_not_before_monotonic is None or now >= publisher._retry_not_before_monotonic)
                )
                renewal_after_generation = publisher._renewal_after_generation
            if should_publish:
                publisher._publish_once(renew_after_generation=renewal_after_generation)

    def _recheck_direct_lane_review_facts(self) -> None:
        """Rebind the lane once a review fact no policy input covers moves.

        Config files carry the blocked-request mode and are watched inputs,
        and the store's source never changes. The approval center origin lives
        in the daemon's runtime state row and the working directory in this
        process, so they are compared here. A change closes the direct lane
        and queues a republish that keeps the daemon's own ACK.
        """

        publisher = cast("NativePolicySnapshotPublisher", self)
        bound = publisher._direct_lane_review_facts
        if bound is None or publisher._direct_lane_ack_target is None:
            return
        current = recheckable_review_facts(publisher.store)
        if current is None or current == bound:
            return
        # A lane published before the daemon recorded where it listens binds
        # no origin, so learning it moves nothing; the next publish binds it.
        if bound[0] is None and current[1] == bound[1]:
            return
        publisher._rebind_direct_lane()

    def _recheck_direct_lane_structured_output(self) -> None:
        """Rebind the lane once the managed-policy view it carries moves.

        Each reconcile compiles the configs again. A managed policy outside
        the watched files, such as one in the Windows registry, changes the
        view without changing an input, so it is compared here.
        """

        publisher = cast("NativePolicySnapshotPublisher", self)
        bound = publisher._direct_lane_structured_output
        if bound is None or publisher._direct_lane_ack_target is None:
            return
        if publisher._compiled_structured_output_view == bound:
            return
        publisher._rebind_direct_lane()

    def _rebind_direct_lane(self) -> None:
        """Close the direct lane and queue a republish under the daemon's ACK."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        publisher._close_direct_lane_ack()
        with publisher._condition:
            publisher._direct_lane_review_facts = None
            publisher._direct_lane_structured_output = None
            publisher._direct_lane_mcp_relay = None
            snapshot = publisher._snapshot
            generation = snapshot.get("generation") if snapshot is not None else None
            if publisher._closed or not publisher._acked or not isinstance(generation, int) or generation <= 0:
                return
            publisher._renewal_after_generation = generation
            publisher._retry_not_before_monotonic = publisher._monotonic_clock()
            publisher._failure_count = 0
        publisher._publish_event.set()

    def _record_error(self, error: str) -> None:
        publisher = cast("NativePolicySnapshotPublisher", self)
        safe = error.strip().lower()
        if not safe or len(safe) > 128 or not all(character.isalnum() or character in "_-=,:?" for character in safe):
            safe = "native_policy_snapshot_publish_failed"
        with publisher._condition:
            publisher._last_error = safe
            expires = publisher._snapshot.get("expires_at_ms") if publisher._snapshot else None
            if not (publisher._acked and isinstance(expires, int) and expires > int(publisher._wall_clock() * 1_000)):
                publisher._acked = False
            publisher._failure_count += 1
            delay = min(
                _PUBLISH_RETRY_MAX_SECONDS,
                publisher._poll_interval_seconds * (2 ** min(publisher._failure_count - 1, 5)),
            )
            retry_seed = hashlib.sha256(f"{publisher._failure_count}:{safe}".encode("ascii")).digest()
            retry_fraction = int.from_bytes(retry_seed[:2], "big") / float(1 << 16)
            publisher._retry_not_before_monotonic = (
                publisher._monotonic_clock()
                + delay
                + min(
                    0.1,
                    publisher._poll_interval_seconds * 0.25,
                )
                * retry_fraction
            )
            publisher._condition.notify_all()

    def _publish_once(self, *, renew_after_generation: int | None = None) -> None:
        publisher = cast("NativePolicySnapshotPublisher", self)
        with publisher._condition:
            if publisher._closed:
                return
            if renew_after_generation is None:
                renew_after_generation = publisher._renewal_after_generation
            publish_epoch = publisher._epoch
        try:
            # A cold verified read may itself migrate authenticated catalog
            # state and close the mutation barrier. Recapture once before IPC;
            # accepting its previous epoch would also hide concurrent changes.
            for attempt in range(2):
                with publisher._condition:
                    publish_epoch = publisher._epoch
                    # Compile exactly this set. A later workspace stays pending:
                    # compiling its overlay now would make the ACKed digest disagree
                    # with the settled-only reconcile and withdraw readiness home-wide.
                    compiled_workspaces = frozenset(publisher._workspace_paths)
                refresh_integrity_state(publisher.store)
                # Observe inputs before compiling: a later change leaves the resident
                # a stat mismatch, never a stale pass. The binding is optional, so an
                # observation failure only keeps the lane closed.
                try:
                    direct_lane = direct_lane_binding(
                        inputs=publisher._current_policy_input_stats(),
                        workspaces=compiled_workspaces,
                    )
                except (OSError, RuntimeError, ValueError, sqlite3.Error):
                    direct_lane = None
                local_cli_revision = publisher._current_local_cli_revision()
                # Probed after the revision: a rule saved in between fails the
                # revision recheck below rather than escaping the binding.
                local_cli_block_rules = local_cli_block_rules_present(publisher.store)
                provider_reader = getattr(publisher.store, "read_mcp_provider_authority_hash", None)
                provider_authority_hash = provider_reader() if callable(provider_reader) else None
                context = publisher._publication_context(workspaces=compiled_workspaces)
                if context is None:
                    return
                # The context may mint the integrity key, which moves the state
                # without a database write. Recapture so inputs follow the state.
                if attempt == 0 and refresh_integrity_state(publisher.store):
                    context = None
                    continue
                with publisher._condition:
                    if publisher._closed:
                        return
                    if publisher._epoch == publish_epoch:
                        break
                context = None
            else:
                return
            identity, capabilities, master_key, config, command_extensions, client = context
            bound_postures = valid_harness_postures(config.get(HARNESS_POSTURES_BINDING_KEY))
            resident_features = tuple(getattr(capabilities, "features", ()))
            direct_lane = with_direct_hook_state(
                direct_lane,
                home_dir=publisher._direct_lane_home_dir(),
                harness_postures=bound_postures,
                local_cli_block_rules=local_cli_block_rules,
                evidence_drain=publisher.direct_evidence_bound(resident_features),
                contained_sink_command=contained_sink_command(resident_features),
                integrity_key=direct_lane_integrity_key(publisher.store, resident_features),
            )
            direct_lane = with_saved_decision_state(direct_lane, store=publisher.store, features=resident_features)
            direct_lane = with_review_facts(
                direct_lane,
                store=publisher.store,
                features=resident_features,
                blocked_request_mode=publisher._compiled_blocked_request_mode,
            )
            direct_lane = with_structured_output_view(
                direct_lane,
                features=resident_features,
                view=publisher._compiled_structured_output_view,
            )
            direct_lane = publisher._with_mcp_relay_view(direct_lane, resident_features)
            resident_fingerprint_before = publisher._current_input_fingerprint()[1]
            try:
                business_source = publisher._compiled_business_source()
                snapshot, resident_generation = _publisher_api()._publish_snapshot_v3(
                    publisher=publisher,
                    identity=identity,
                    capabilities=capabilities,
                    config=config,
                    command_extensions=command_extensions,
                    master_key=master_key,
                    client=client,
                    renew_after_generation=renew_after_generation,
                    direct_lane=direct_lane,
                    **(
                        {
                            "business_policy": cast(
                                Mapping[str, object], _strict_json_loads_v3(business_source.binding_bytes)
                            )
                        }
                        if business_source is not None
                        else {}
                    ),
                )
            finally:
                # The master is only an ephemeral input to derivation/signing;
                # never retain it in publisher state or an exception context.
                master_key = None
            resident_fingerprint = publisher._current_input_fingerprint()[1]
            resident_directory_fingerprint = publisher._resident_directory_fingerprint()
            # A separate process may commit authority while the resident is
            # acknowledging this candidate. Re-read verified authority outside
            # the hook barrier and reject an ACK for the earlier controls.
            if publisher._compiled_command_extensions() != command_extensions and snapshot.get("mode") != "observe":
                with publisher._condition:
                    publisher._acked = False
                raise NativePolicySnapshotError("native_command_control_binding_changed")
            if publisher._compiled_business_source() != business_source:
                with publisher._condition:
                    publisher._acked = False
                raise NativePolicySnapshotError("native_business_source_binding_changed")
            if publisher._current_local_cli_revision() != local_cli_revision:
                with publisher._condition:
                    publisher._acked = False
                raise NativePolicySnapshotError("native_local_cli_revision_changed")
            if callable(provider_reader) and provider_reader() != provider_authority_hash:
                with publisher._condition:
                    publisher._acked = False
                raise NativePolicySnapshotError("native_provider_catalog_changed")
            with hold_command_control_authority_lock(publisher.guard_home, shared=True):
                source_matches = publisher._compiled_business_source() == business_source
                with publisher._condition:
                    # A mutation may have invalidated the barrier in flight; an
                    # older ACK must not make that newer policy appear ready.
                    if publisher._closed or publisher._epoch != publish_epoch:
                        return
                    if not source_matches:
                        publisher._acked = False
                        raise NativePolicySnapshotError("native_business_source_binding_changed")
                    # Bind the ACK to the resident observed before publication,
                    # after publication, and at the barrier commit point.
                    resident_fingerprint_confirmed = publisher._confirm_resident_fingerprint(
                        resident_fingerprint_before,
                        resident_fingerprint,
                        resident_generation,
                        resident_directory_fingerprint,
                    )
                    if (
                        resident_fingerprint_confirmed is None
                        and snapshot.get("mode") == "observe"
                        and _publisher_api()._same_resident_paths(resident_fingerprint_before, resident_fingerprint)
                        and publisher._resident_fingerprint_matches_generation(
                            resident_fingerprint, resident_generation
                        )
                    ):
                        # Hook reviews touch resident generation files in flight; Watch
                        # still matches the resident that ACKed, so do not drop it.
                        resident_fingerprint_confirmed = resident_fingerprint
                    if resident_fingerprint_confirmed is None:
                        publisher._acked = False
                        raise NativePolicySnapshotError("native_policy_snapshot_resident_changed")
                    # The first client request may create the resident generation
                    # state files. Treat those files as the state of this ACK,
                    # otherwise the observer loop immediately mistakes its own
                    # startup for a resident restart and withdraws the barrier
                    # under a concurrent hook. Keep the policy-input half from
                    # before publication so a config change observed during the
                    # request still forces a republish on the next poll.
                    if publisher._input_fingerprint is not None:
                        publisher._input_fingerprint = (publisher._input_fingerprint[0], resident_fingerprint_confirmed)
                    publisher._snapshot = snapshot
                    publisher._resident_startup_required = False
                    publisher._published_config_digest = cast(str, snapshot["config_digest"])
                    publisher._published_local_cli_revision = local_cli_revision
                    publisher._published_policy_fingerprint = (
                        cast(str, snapshot["config_digest"]),
                        cast(str, snapshot["mode"]),
                        publisher._source_control_fingerprint(command_extensions, business_source),
                    )
                    publisher._observed_policy_fingerprint = publisher._published_policy_fingerprint
                    # Per-harness posture rides this same ACK: capture the
                    # overrides compiled into the snapshot being acknowledged,
                    # never a later re-read of config.toml.
                    # Bind only what the sidecar write persisted, so daemon hooks
                    # and readers of the signed file never disagree.
                    publisher._harness_postures = write_harness_postures_sidecar(
                        publisher.store,
                        generation=cast(int, snapshot["generation"]),
                        policy_digest=cast(str, snapshot["policy_digest"]),
                        postures=bound_postures,
                    )
                    publisher._acked = True
                    if publisher._harness_postures == bound_postures:
                        publisher._direct_lane_local_cli_revision = local_cli_revision
                        publisher._direct_lane_review_facts = (
                            (direct_lane.get("approval_center_origin"), direct_lane.get("review_host_cwd"))
                            if isinstance(direct_lane, Mapping) and review_facts_bound(resident_features)
                            else None
                        )
                        publisher._direct_lane_structured_output = bound_structured_output_view(
                            direct_lane, resident_features
                        )
                        publisher._bind_relay_and_saved_state(direct_lane, resident_features)
                        evidence_drain = isinstance(direct_lane, Mapping) and direct_lane.get("evidence_drain") is True
                        publisher._publish_direct_lane_ack(snapshot, evidence_drain=evidence_drain)
                    else:
                        # Daemon hooks read the persisted postures; a direct
                        # hook must never see a different Watch decision.
                        publisher._close_direct_lane_ack()
                    publisher._last_error = None
                    publisher._renewal_after_generation = None
                    publisher._failure_count = 0
                    publisher._retry_not_before_monotonic = None
                    publisher._schedule_renewal_locked(snapshot)
                    publisher._commit_workspace_readiness_locked(compiled_workspaces)
                    publisher._condition.notify_all()
        except NativePolicySnapshotError as error:
            publisher._record_error(str(error))
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error) as error:
            publisher._record_error(type(error).__name__)

    def _publication_context(
        self,
        *,
        workspaces: frozenset[Path] | None = None,
    ) -> tuple[Any, Any, bytes, Mapping[str, object], Mapping[str, object], Callable[..., bytes | None]] | None:
        publisher = cast("NativePolicySnapshotPublisher", self)
        status_provider = publisher._status_provider
        if status_provider is None:
            from .native_runtime import native_runtime_status

            status_provider = native_runtime_status
        status = status_provider()
        with publisher._condition:
            publisher._last_runtime_status = status
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
        if not _REQUIRED_PUBLISH_FEATURES.issubset(set(getattr(capabilities, "features", ()))):
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
            config = publisher._compiled_effective_policy(workspaces=workspaces)
            command_extensions = publisher._compiled_command_extensions()
            client = publisher._client_request
            if client is None:
                from .native_resident_client import native_resident_client_request

                client = native_resident_client_request
            return identity, capabilities, material[0], config, command_extensions, client
        finally:
            material = None
