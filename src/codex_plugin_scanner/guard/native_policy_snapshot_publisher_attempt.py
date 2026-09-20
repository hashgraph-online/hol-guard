"""One complete attempt through the current native publication barrier."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .native_policy_snapshot_publisher_context import NativePolicyCaptureChangedError

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def publish_once(self: NativePolicySnapshotPublisher, *, renew_after_generation: int | None = None) -> None:
    # Resolve existing globals at call time to retain the publisher's test patches.
    from . import native_policy_snapshot_publisher as api

    with self._condition:
        if self._closed:
            return
        if renew_after_generation is None:
            renew_after_generation = self._renewal_after_generation
        publish_epoch = self._epoch
        unready_at_entry = not self._acked
    v3_capture_active = False
    v3_transport_active = False
    v3_postack_database_race = False
    try:
        prepared_command_extensions = None
        # Prepare initial authenticated catalog state before choosing the
        # attempt's epoch. Subsequent mutations invalidate this attempt;
        # they never authorize it to restart under a newer barrier.
        if self._command_control_runtime is None:
            prepared_command_extensions = self._compiled_command_extensions()
            with self._condition:
                if self._closed:
                    return
                publish_epoch = self._epoch
        context = (
            self._publication_context(publish_epoch=publish_epoch)
            if prepared_command_extensions is None
            else self._publication_context(
                publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions
            )
        )
        prepared_command_extensions = None
        if context is None:
            return
        cloud_inputs = context[5]
        v3_capture_active = isinstance(cloud_inputs, api.CapturedV3PublicationInputs)
        if isinstance(cloud_inputs, api.NativeVerifiedPolicyInputs):
            try:
                api.publish_scoped(self, context, publish_epoch, renew_after_generation)
            finally:
                context = None
            return
        resident_fingerprint_before = self._current_input_fingerprint()[1]
        try:
            v3_transport_active = True
            snapshot, resident_generation, cloud_inputs = api._publish_snapshot_v3(
                publisher=self,
                context=context,
                publish_epoch=publish_epoch,
                renew_after_generation=renew_after_generation,
            )
            v3_transport_active = False
        finally:
            # The master is only an ephemeral input to derivation/signing;
            # never retain it in publisher state or an exception context.
            context = None
        resident_fingerprint = self._current_input_fingerprint()[1]
        resident_directory_fingerprint = self._resident_directory_fingerprint()
        with api.managed_policy_cache_read_only(), api.ExitStack() as capture:
            source_observer = None
            source_version = None
            source_fingerprint = None
            if isinstance(cloud_inputs, api.CapturedV3PublicationInputs):
                source_observer = capture.enter_context(self.store._connect())
                source_version = source_observer.execute("pragma data_version").fetchone()[0]
                before_source = self._current_input_fingerprint()[0]
                current_command_extensions = self._compiled_command_extensions()
                if current_command_extensions != snapshot.get("command_extensions", {}):
                    raise api.NativePolicySnapshotError("native_command_control_binding_changed")
                current_config, current_cloud_inputs = api.compiled_v3_compatible_policy(
                    self,
                    allow_signed_defaults=cloud_inputs.source_identity is not None,
                    command_extensions=current_command_extensions,
                )
                source_fingerprint = self._current_input_fingerprint()[0]
                if current_cloud_inputs.source_identity != cloud_inputs.source_identity:
                    raise api.NativePolicySnapshotError("native_cloud_policy_changed_during_publish")
                if (
                    current_cloud_inputs.input_digest != cloud_inputs.input_digest
                    or api._policy_fingerprint(current_config) != (snapshot["config_digest"], snapshot["mode"])
                    or not api._capture_metadata_equal(
                        before_source, source_fingerprint, str(self.guard_home / "guard.db")
                    )
                    or source_observer.execute("pragma data_version").fetchone()[0] != source_version
                ):
                    # Discard this ACK even when the captured policy matches
                    # and only database observations changed. A fresh publication may retry;
                    # these equalities never make the old attempt ready.
                    database = str(self.store.path)
                    v3_postack_database_race = (
                        current_cloud_inputs.input_digest == cloud_inputs.input_digest
                        and api._policy_fingerprint(current_config) == (snapshot["config_digest"], snapshot["mode"])
                        and api._external_source_metadata(before_source, database)
                        == api._external_source_metadata(source_fingerprint, database)
                    )
                    raise api.NativePolicySnapshotError("native_policy_authority_changed_during_publish")
            else:
                if self._compiled_command_extensions() != snapshot.get("command_extensions", {}):
                    raise api.NativePolicySnapshotError("native_command_control_binding_changed")
                current_cloud_inputs = api.read_native_cloud_policy_inputs(self.store, now=self._wall_clock())
                if current_cloud_inputs.source_identity != cloud_inputs.source_identity:
                    raise api.NativePolicySnapshotError("native_cloud_policy_changed_during_publish")
            with self._condition:
                # A mutation may have invalidated the barrier while this
                # request was in flight. Do not let an older ACK make that
                # newer policy appear ready.
                if self._closed or self._epoch != publish_epoch:
                    return
                # Bind the ACK to the resident observed before publication,
                # after publication, and at the barrier commit point.
                resident_fingerprint_confirmed = self._confirm_resident_fingerprint(
                    resident_fingerprint_before,
                    resident_fingerprint,
                    resident_generation,
                    resident_directory_fingerprint,
                )
                if resident_fingerprint_confirmed is None:
                    self._acked = False
                    raise api.NativePolicySnapshotError("native_policy_snapshot_resident_changed")
                # Resident confirmation performs filesystem reads. Source
                # authority must still match after that observation completes.
                if self._closed or self._epoch != publish_epoch:
                    return
                if source_observer is not None and (
                    self._current_input_fingerprint()[0] != source_fingerprint
                    or source_observer.execute("pragma data_version").fetchone()[0] != source_version
                ):
                    self._acked = False
                    raise api.NativePolicySnapshotError("native_policy_authority_changed_during_publish")
                # The first client request may create the resident generation
                # state files. Treat those files as the state of this ACK,
                # otherwise the observer loop immediately mistakes its own
                # startup for a resident restart and withdraws the barrier
                # under a concurrent hook. Keep the policy-input half from
                # before publication so a config change observed during the
                # request still forces a republish on the next poll.
                if self._input_fingerprint is not None:
                    self._input_fingerprint = (self._input_fingerprint[0], resident_fingerprint_confirmed)
                self._v4_publication = None
                self._v4_epoch = None
                self._v4_binding = None
                self._snapshot = snapshot
                self._published_v3_source_fingerprint = source_fingerprint
                self._published_v3_resident_generation = resident_generation
                self._published_v3_resident_fingerprint = resident_fingerprint_confirmed
                self._published_config_digest = api.cast(str, snapshot["config_digest"])
                self._published_policy_fingerprint = (
                    api.cast(str, snapshot["config_digest"]),
                    api.cast(str, snapshot["mode"]),
                )
                self._observed_policy_fingerprint = self._published_policy_fingerprint
                self._published_command_control_digest = api._digest_v3(snapshot.get("command_extensions", {}))
                self._observed_command_control_digest = self._published_command_control_digest
                self._published_cloud_inputs = cloud_inputs
                self._observed_cloud_inputs = cloud_inputs
                if isinstance(cloud_inputs, api.CapturedV3PublicationInputs):
                    self._observed_scoped_digest = cloud_inputs.input_digest
                self._acked = True
                self._last_error = None
                self._renewal_after_generation = None
                self._failure_count = 0
                self._retry_not_before_monotonic = None
                self._schedule_renewal_locked(snapshot)
                self._condition.notify_all()
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError, api.sqlite3.Error) as error:
        api.record_publication_error(
            self,
            error=error,
            publish_epoch=publish_epoch,
            renew_after_generation=renew_after_generation,
            v3_capture_active=v3_capture_active,
            v3_transport_active=v3_transport_active,
        )
        initial_capture_race = (
            isinstance(error, NativePolicyCaptureChangedError)
            and v3_capture_active
            and v3_transport_active
            and renew_after_generation is None
        )
        if unready_at_entry and (v3_postack_database_race or initial_capture_race):
            self._schedule_initial_database_capture_retry(publish_epoch=publish_epoch)
