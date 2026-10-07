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

if TYPE_CHECKING:
    from pathlib import Path

    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


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
            with publisher._condition:
                if publisher._closed:
                    return
                publisher._mark_expired_locked()
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
            for _ in range(2):
                with publisher._condition:
                    publish_epoch = publisher._epoch
                    # Compile exactly this set. A workspace registered later
                    # stays pending for the next publish; compiling its overlay
                    # now would make the ACKed digest disagree with the
                    # settled-only reconcile and withdraw readiness home-wide.
                    compiled_workspaces = frozenset(publisher._workspace_paths)
                local_cli_revision = publisher._current_local_cli_revision()
                provider_reader = getattr(publisher.store, "read_mcp_provider_authority_hash", None)
                provider_authority_hash = provider_reader() if callable(provider_reader) else None
                context = publisher._publication_context(workspaces=compiled_workspaces)
                if context is None:
                    return
                with publisher._condition:
                    if publisher._closed:
                        return
                    if publisher._epoch == publish_epoch:
                        break
                context = None
            else:
                return
            identity, capabilities, master_key, config, command_extensions, client = context
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
                    # A mutation may have invalidated the barrier while this
                    # request was in flight. Do not let an older ACK make that
                    # newer policy appear ready.
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
                        # Hook reviews touch resident generation files while this
                        # publish is in flight. Watch still matches the resident
                        # that acknowledged the snapshot; do not drop it and pause.
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
                    publisher._acked = True
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

    @staticmethod
    def _decode_ack(output: bytes | None) -> dict[str, object] | None:
        return _publisher_api()._decode_ack_v3(output)
