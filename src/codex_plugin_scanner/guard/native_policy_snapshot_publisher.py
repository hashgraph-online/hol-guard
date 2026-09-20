"""Asynchronous native policy snapshot publication barrier."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack as ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .mdm.policy import managed_policy_cache_read_only as managed_policy_cache_read_only
from .native_cloud_policy_inputs import NativeCloudPolicyInputs
from .native_cloud_policy_inputs import read_native_cloud_policy_inputs as read_native_cloud_policy_inputs
from .native_policy_authority_read import NativeVerifiedPolicyInputs as NativeVerifiedPolicyInputs
from .native_policy_decision_context import NativePolicyDecisionContext
from .native_policy_snapshot_codec import _digest_v3 as _digest_v3
from .native_policy_snapshot_constants import (
    _PUBLISH_RETRY_SECONDS,
    _PUBLISH_TIMEOUT_SECONDS,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_publisher_context import CapturedV3PublicationInputs as CapturedV3PublicationInputs
from .native_policy_snapshot_publisher_context import PublicationContext, publication_context
from .native_policy_snapshot_publisher_context import compiled_v3_compatible_policy as compiled_v3_compatible_policy
from .native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs
from .native_policy_snapshot_publisher_scheduling import (
    mark_expired_locked,
    record_error,
    renewal_jitter_seconds,
    schedule_renewal_locked,
)
from .native_policy_snapshot_publisher_scheduling import record_publication_error as record_publication_error
from .native_policy_snapshot_publisher_scoped import (
    ScopedSnapshotBinding,
    capture_scoped_decision,
    scoped_binding,
    scoped_result_is_current,
    scoped_rule_identity,
)
from .native_policy_snapshot_publisher_scoped import _capture_metadata_equal as _capture_metadata_equal
from .native_policy_snapshot_publisher_scoped import _policy_fingerprint as _policy_fingerprint
from .native_policy_snapshot_publisher_scoped import publish_scoped as publish_scoped
from .native_policy_snapshot_publisher_transport import _decode_ack_v3
from .native_policy_snapshot_publisher_transport import _publish_snapshot_v3 as _publish_snapshot_v3
from .native_policy_snapshot_source_requirement import refresh_source_requirement
from .native_policy_snapshot_v3_renewal import _external_source_metadata as _external_source_metadata
from .native_policy_snapshot_v4_transport import NativeV4Publication
from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key

if TYPE_CHECKING:
    from .policy_rule_identity import PolicyRuleIdentity
    from .store import GuardStore


def _snapshot_api() -> Any:
    """Resolve the façade lazily so compatibility monkeypatches remain live."""

    from . import native_policy_snapshot

    return native_policy_snapshot


class NativePolicySnapshotPublisher(NativePolicySnapshotPublisherInputs):
    """Asynchronously publish an authenticated snapshot and expose its barrier."""

    def __init__(
        self,
        *,
        store: GuardStore,
        status_provider: Callable[[], Any] | None = None,
        client_request: Callable[..., bytes | None] | None = None,
        poll_interval_seconds: float = _PUBLISH_RETRY_SECONDS,
        wall_clock: Callable[[], float] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.guard_home = Path(store.guard_home)
        self._status_provider = status_provider
        self._client_request = client_request
        self._poll_interval_seconds = max(0.05, min(5.0, poll_interval_seconds))
        self._wall_clock = wall_clock or time.time
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._condition = threading.Condition()
        self._publish_event = threading.Event()
        self._closed = False
        self._started = False
        self._thread: threading.Thread | None = None
        self._snapshot: dict[str, object] | None = None
        self._acked = False
        self._published_v3_source_fingerprint: tuple[tuple[str, tuple[int, int, int, int] | None], ...] | None = None
        self._published_v3_resident_generation: int | None = None
        self._published_v3_resident_fingerprint: tuple[tuple[str, int, int], ...] | None = None
        self._scoped_publication_enabled = False
        self._source_authority_required = True
        self._source_memory_required = True
        self._v4_publication: NativeV4Publication | None = None
        self._v4_epoch: int | None = None
        self._v4_binding: ScopedSnapshotBinding | None = None
        self._observed_scoped_digest: str | None = None
        self._epoch = 0
        self._last_error: str | None = None
        self._published_config_digest: str | None = None
        self._published_policy_fingerprint: tuple[str, str] | None = None
        self._observed_policy_fingerprint: tuple[str, str] | None = None
        self._published_command_control_digest: str | None = None
        self._observed_command_control_digest: str | None = None
        self._command_control_runtime = None
        self._reconcile_due_monotonic = self._monotonic_clock() + 1.0
        self._published_cloud_inputs = NativeCloudPolicyInputs()
        self._observed_cloud_inputs = NativeCloudPolicyInputs()
        self._renewal_due_monotonic: float | None = None
        self._renewal_after_generation: int | None = None
        self._retry_not_before_monotonic: float | None = None
        self._failure_count = 0
        self._initial_database_capture_retry_used = False
        self._initial_database_capture_retry_epoch: int | None = None
        self._workspace_paths: set[Path] = set()
        self._input_fingerprint: (
            tuple[tuple[tuple[str, tuple[int, int, int, int] | None], ...], tuple[tuple[str, int, int], ...]] | None
        ) = None
        api = _snapshot_api()
        with api._PUBLISHER_LOCK:
            api._PUBLISHERS.setdefault(api._publisher_key(self.guard_home), set()).add(self)
        refresh_source_requirement(self)

    def start(self) -> None:
        with self._condition:
            if self._started or self._closed:
                return
            self._started = True
        # Provision the verifier before the worker can publish.  GuardStore has
        # completed its schema setup by the time a publisher is constructed;
        # keeping this one-time key bootstrap synchronous prevents the worker
        # from racing a partially initialized ``sync_state`` table.  Effective
        # policy compilation and resident publication remain asynchronous.
        try:
            self._provision_verifier_key()
        except NativePolicySnapshotError as error:
            self._record_error(str(error))
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error) as error:
            self._record_error(type(error).__name__)
        with self._condition:
            if self._closed:
                return
            # Commit the initial invalidation before a registered workspace's
            # pending event can let the new worker capture an older epoch.
            self.request_publish()
            self._thread = threading.Thread(
                target=self._run,
                name="hol-guard-native-policy-publisher",
                daemon=True,
            )
            self._thread.start()

    def close(self, *, timeout_seconds: float = 1.0) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._acked = False
            self._condition.notify_all()
        self._publish_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout_seconds))
        api = _snapshot_api()
        with api._PUBLISHER_LOCK:
            publishers = api._PUBLISHERS.get(api._publisher_key(self.guard_home))
            if publishers is not None:
                publishers.discard(self)
                if not publishers:
                    api._PUBLISHERS.pop(api._publisher_key(self.guard_home), None)

    def request_publish(self, *, require_source_authority: bool = False) -> None:
        with self._condition:
            if self._closed:
                return
            self._source_authority_required |= require_source_authority
            self._epoch += 1
            self._acked = False
            self._last_error = None
            self._initial_database_capture_retry_epoch = None
            self._renewal_due_monotonic = None
            self._renewal_after_generation = None
            self._retry_not_before_monotonic = None
            self._failure_count = 0
            self._condition.notify_all()
        self._publish_event.set()

    def request_publish_before_deadline(
        self, *, deadline_monotonic: float, require_source_authority: bool = False
    ) -> None:
        """Bound off-hook admission to the existing reentrant condition."""
        from .native_policy_snapshot_mutation import _mutation_wait_seconds, _require_mutation_time

        if not self._condition.acquire(timeout=_mutation_wait_seconds(deadline_monotonic)):
            raise NativePolicySnapshotError("native_policy_snapshot_control_deadline_exceeded")
        try:
            # The constructor owns a standard reentrant Condition. Reuse the
            # unchanged invalidation operation while retaining that ownership.
            self.request_publish(require_source_authority=require_source_authority)
        finally:
            self._condition.release()
        _require_mutation_time(deadline_monotonic)

    notify_policy_changed = request_publish

    def register_workspace(self, workspace: Path | None) -> bool:
        """Track workspace override files without reading them on a hook."""

        if workspace is None:
            return False
        candidate = self._resolved_workspace(workspace)
        with self._condition:
            if candidate in self._workspace_paths:
                return False
            self._workspace_paths.add(candidate)
            # A newly observed workspace can add a stricter local overlay.
            # Invalidate the barrier immediately so no request can continue
            # on a home-only snapshot while the overlay is being compiled.
            self._input_fingerprint = None
        self.request_publish()
        return True

    def _provision_verifier_key(self) -> None:
        material_getter = getattr(self.store, "_policy_integrity_secret_material", None)
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
            provision_native_policy_verifier_key(self.guard_home, master_key)
        finally:
            # Keep the master key only for the derivation call.  The derived
            # verifier is the only value written to native runtime state.
            master_key = None
            material = None

    def _mark_expired_locked(self) -> None:
        mark_expired_locked(self)

    @staticmethod
    def _renewal_jitter_seconds(snapshot: Mapping[str, object], remaining_seconds: float) -> float:
        return renewal_jitter_seconds(snapshot, remaining_seconds)

    def _schedule_renewal_locked(self, snapshot: Mapping[str, object]) -> None:
        schedule_renewal_locked(self, snapshot)

    def is_ready(self) -> bool:
        with self._condition:
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    @property
    def requires_scoped_authority(self) -> bool:
        """A scoped negotiation failure must not become availability fallback."""
        with self._condition:
            return self._scoped_publication_enabled

    @property
    def requires_policy_authority(self) -> bool:
        with self._condition:
            return self._source_authority_required or self._scoped_publication_enabled

    def current_snapshot(self) -> dict[str, object] | None:
        with self._condition:
            self._mark_expired_locked()
            if not self._acked or self._snapshot is None or self._closed:
                return None
            return cast(dict[str, object], json.loads(json.dumps(self._snapshot)))

    def current_snapshot_binding(self) -> dict[str, object] | None:
        """Return the small immutable request binding for the hot hook path.

        The resident owns the authenticated full snapshot after publication.
        Hook requests only need the values that bind them to that resident
        snapshot; avoid serializing and copying policy rules on every hook.
        """
        with self._condition:
            self._mark_expired_locked()
            if not self._acked or self._snapshot is None or self._closed:
                return None
            snapshot = self._snapshot
            if self._v4_publication is not None:
                return scoped_binding(self)
            binding = {
                "generation": snapshot.get("generation"),
                "policy_digest": snapshot.get("policy_digest"),
                "runtime_identity": snapshot.get("runtime_identity"),
                "mode": snapshot.get("mode"),
            }
            if "command_extensions" in snapshot:
                binding["command_extensions_bound"] = True
            return binding

    def result_binding_is_current(self, binding: Mapping[str, object]) -> bool:
        """Fence a V4 response before exposing its decision or receipt."""
        with self._condition:
            self._mark_expired_locked()
            return scoped_result_is_current(self, binding)

    def policy_rule_identity_for_result(self, binding: Mapping[str, object]) -> PolicyRuleIdentity | None:
        """Resolve only the accepted snapshot's captured canonical identity."""
        with self._condition:
            self._mark_expired_locked()
            return scoped_rule_identity(self, binding)

    def capture_policy_decision_context(
        self, binding: Mapping[str, object], receipt: object
    ) -> tuple[bool, NativePolicyDecisionContext | None]:
        return capture_scoped_decision(self, binding, receipt)

    @property
    def last_error(self) -> str | None:
        with self._condition:
            return self._last_error

    def wait_until_ready(self, deadline_monotonic: float | None = None) -> bool:
        deadline = (
            deadline_monotonic if deadline_monotonic is not None else self._monotonic_clock() + _PUBLISH_TIMEOUT_SECONDS
        )
        with self._condition:
            while not self._closed:
                self._mark_expired_locked()
                if self._acked and self._snapshot is not None:
                    return True
                remaining = deadline - self._monotonic_clock()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed

    def _run(self) -> None:
        while True:
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
            fingerprint = self._current_input_fingerprint()
            if self._publish_due_initial_retry(fingerprint):
                continue
            if self._input_fingerprint is None:
                self._input_fingerprint = fingerprint
            elif fingerprint[1] != self._input_fingerprint[1]:
                # Resident generation files are created on every managed
                # restart. Re-push the last snapshot before a hook can rely
                # on the replacement resident's in-memory policy.
                self._input_fingerprint = fingerprint
                self.request_publish()
            elif fingerprint[0] != self._input_fingerprint[0]:
                previous_inputs = dict(self._input_fingerprint[0])
                current_inputs = dict(fingerprint[0])
                changed_paths = {
                    path
                    for path in previous_inputs.keys() | current_inputs.keys()
                    if previous_inputs.get(path) != current_inputs.get(path)
                }
                self._input_fingerprint = fingerprint
                if self._policy_input_changed(changed_paths):
                    self.request_publish()
            if self._monotonic_clock() >= self._reconcile_due_monotonic:
                self._reconcile_due_monotonic = self._monotonic_clock() + 1.0
                if self._policy_input_changed():
                    self.request_publish()
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
                now = self._monotonic_clock()
                wait_seconds = self._poll_interval_seconds
                if self._retry_not_before_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, self._retry_not_before_monotonic - now),
                    )
                if self._acked and self._renewal_due_monotonic is not None:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, self._renewal_due_monotonic - now),
                    )
            self._publish_event.wait(timeout=wait_seconds)
            self._publish_event.clear()
            with self._condition:
                if self._closed:
                    return
                self._mark_expired_locked()
                now = self._monotonic_clock()
                if self._acked and self._renewal_due_monotonic is not None and now >= self._renewal_due_monotonic:
                    snapshot = self._snapshot
                    generation = snapshot.get("generation") if snapshot is not None else None
                    self._renewal_due_monotonic = None
                    self._renewal_after_generation = (
                        generation if isinstance(generation, int) and generation > 0 else None
                    )
                    self._retry_not_before_monotonic = now
                    self._failure_count = 0
                should_publish = (
                    not self._closed
                    and (not self._acked or self._renewal_after_generation is not None)
                    and (self._retry_not_before_monotonic is None or now >= self._retry_not_before_monotonic)
                )
                renewal_after_generation = self._renewal_after_generation
            if should_publish:
                self._publish_once(renew_after_generation=renewal_after_generation)

    def _publish_due_initial_retry(
        self,
        fingerprint: tuple[tuple[tuple[str, tuple[int, int, int, int] | None], ...], tuple[tuple[str, int, int], ...]],
    ) -> bool:
        """Take the already scheduled fresh attempt before duplicate observation."""
        with self._condition:
            previous = self._input_fingerprint
            if (
                self._closed
                or self._acked
                or self._renewal_after_generation is not None
                or self._initial_database_capture_retry_epoch != self._epoch
                or not self._initial_database_capture_retry_used
                or self._retry_not_before_monotonic is None
                or self._monotonic_clock() < self._retry_not_before_monotonic
                or not self._publish_event.is_set()
                or previous is None
                or fingerprint[1] != previous[1]
            ):
                return False
            database = str(self.guard_home / "guard.db")
            if _external_source_metadata(previous[0], database) != _external_source_metadata(fingerprint[0], database):
                return False
            self._initial_database_capture_retry_epoch = None
            self._publish_event.clear()
        # Keep the source half of the previous fingerprint. The following
        # ordinary iteration must observe changes after success or refusal.
        self._publish_once()
        return True

    def _record_error(self, error: str) -> None:
        record_error(self, error)

    def _publish_once(self, *, renew_after_generation: int | None = None) -> None:
        from .native_policy_snapshot_publisher_attempt import publish_once

        with self._condition:
            self._initial_database_capture_retry_epoch = None
        publish_once(self, renew_after_generation=renew_after_generation)

    def _schedule_initial_database_capture_retry(self, *, publish_epoch: int) -> None:
        """Allow one fresh full attempt without opening the failed barrier.

        This lifetime allowance is not reset by workspace admission, policy
        observation, or resident startup files. Later failures retain backoff.
        The caller's readiness deadline and each publication budget are unchanged.
        """
        with self._condition:
            if (
                self._closed
                or self._epoch != publish_epoch
                or self._acked
                or self._initial_database_capture_retry_used
                or self._last_error
                not in {
                    "native_policy_authority_changed_during_publish",
                    "native_policy_authority_capture_changed",
                }
            ):
                return
            self._initial_database_capture_retry_used = True
            self._initial_database_capture_retry_epoch = publish_epoch
            self._retry_not_before_monotonic = self._monotonic_clock()
            self._condition.notify_all()
        self._publish_event.set()

    def _publication_context(
        self,
        *,
        publish_epoch: int | None = None,
        prepared_command_extensions: Mapping[str, object] | None = None,
    ) -> PublicationContext | None:
        return publication_context(
            self,
            publish_epoch=publish_epoch,
            prepared_command_extensions=prepared_command_extensions,
        )

    @staticmethod
    def _decode_ack(output: bytes | None) -> dict[str, object] | None:
        return _decode_ack_v3(output)
