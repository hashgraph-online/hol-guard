"""Asynchronous native policy snapshot publication barrier."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .native_policy_snapshot_constants import (
    _PUBLISH_RETRY_SECONDS,
    _PUBLISH_TIMEOUT_SECONDS,
    _RENEWAL_JITTER_MAX_SECONDS,
    _RENEWAL_LEAD_SECONDS,
    POLICY_SNAPSHOT_UNAVAILABLE_ERRORS,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_publication import NativePolicySnapshotPublicationMixin
from .native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs
from .native_policy_snapshot_publisher_transport import (
    _decode_ack_v3 as _decode_ack_v3,
)
from .native_policy_snapshot_publisher_transport import (
    _publish_snapshot_v3 as _publish_snapshot_v3,
)
from .native_policy_snapshot_windows_key import provision_native_policy_verifier_key

if TYPE_CHECKING:
    from .store import GuardStore


def _snapshot_api() -> Any:
    """Resolve the façade lazily so compatibility monkeypatches remain live."""

    from . import native_policy_snapshot

    return native_policy_snapshot


def _same_resident_paths(left, right) -> bool:
    """True when the resident file set is unchanged.

    Matching paths with new mtimes are hook traffic, not a new resident.
    A restart adds or removes a generation path and must withdraw Watch.
    """

    return {path for path, _mtime, _size in left} == {path for path, _mtime, _size in right}


def provision_native_verifier_key_for_store(store: GuardStore) -> None:
    """Provision the resident verifier key for a store's Guard home.

    The Rust resident refuses to serve until this owner-private derived key
    exists.  Publishers provision it at ``start()``; standalone native
    decision callers must establish the same prerequisite or every request
    fails closed on ``native_resident_start_timeout``.
    """

    material_getter = getattr(store, "_policy_integrity_secret_material", None)
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
        provision_native_policy_verifier_key(Path(store.guard_home), master_key)
    finally:
        # Keep the master key only for the derivation call.  The derived
        # verifier is the only value written to native runtime state.
        master_key = None
        material = None


class NativePolicySnapshotPublisher(NativePolicySnapshotPublicationMixin, NativePolicySnapshotPublisherInputs):
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
        self._last_runtime_status: Any | None = None
        self._resident_startup_required = True
        self._acked = False
        self._epoch = 0
        self._last_error: str | None = None
        self._published_config_digest: str | None = None
        self._published_local_cli_revision: int | None = None
        self._published_policy_fingerprint: tuple[str, str, str] | None = None
        self._observed_policy_fingerprint: tuple[str, str, str] | None = None
        self._observe_extension_refresh = False
        self._renewal_due_monotonic: float | None = None
        self._renewal_after_generation: int | None = None
        self._retry_not_before_monotonic: float | None = None
        self._failure_count = 0
        self._workspace_paths: set[Path] = set()
        self._command_control_runtime = None
        self._reconcile_due_monotonic = self._monotonic_clock() + 1.0
        self._input_fingerprint: (
            tuple[tuple[tuple[str, tuple[int, int, int, int] | None], ...], tuple[tuple[str, int, int], ...]] | None
        ) = None
        api = _snapshot_api()
        with api._PUBLISHER_LOCK:
            api._PUBLISHERS.setdefault(api._publisher_key(self.guard_home), set()).add(self)

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
            self._thread = threading.Thread(
                target=self._run,
                name="hol-guard-native-policy-publisher",
                daemon=True,
            )
            self._thread.start()
        self.request_publish()

    def close(self, *, timeout_seconds: float = 1.0, deadline_monotonic: float | None = None) -> bool:
        return self.close_contained(timeout_seconds=timeout_seconds, deadline_monotonic=deadline_monotonic)

    def close_contained(self, *, timeout_seconds: float = 1.0, deadline_monotonic: float | None = None) -> bool:
        """Retain publication ownership until the publisher thread exits."""
        deadline = self._monotonic_clock() + max(0.0, timeout_seconds)
        if deadline_monotonic is not None:
            deadline = min(deadline, deadline_monotonic)

        def remaining() -> float:
            return max(0.0, deadline - self._monotonic_clock())

        # Retire before waiting for a contended condition. A failed bounded
        # close must not permit another publication or a new start.
        self._closed = True
        self._publish_event.set()
        if not self._condition.acquire(timeout=remaining()):
            return False
        try:
            self._acked = False
            self._condition.notify_all()
        finally:
            self._condition.release()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=remaining())
        if thread is not None and thread.is_alive():
            # Keep the registry and thread handles until a recovery close
            # confirms retirement; callers must retain the isolated home.
            return False
        api = _snapshot_api()
        if not api._PUBLISHER_LOCK.acquire(timeout=remaining()):
            return False
        try:
            publishers = api._PUBLISHERS.get(api._publisher_key(self.guard_home))
            if publishers is not None:
                publishers.discard(self)
                if not publishers:
                    api._PUBLISHERS.pop(api._publisher_key(self.guard_home), None)
            self._thread = None
            return True
        finally:
            api._PUBLISHER_LOCK.release()

    def request_publish(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._epoch += 1
            self._acked = False
            self._last_error = None
            self._renewal_due_monotonic = None
            self._renewal_after_generation = None
            self._retry_not_before_monotonic = None
            self._failure_count = 0
            self._condition.notify_all()
        self._publish_event.set()

    def request_control_binding_refresh(self, rejected_generation: int | None) -> None:
        """Coalesce rejected admission refreshes without withdrawing a newer ACK."""
        with self._condition:
            if self._closed or not self._acked:
                return
            generation = self._snapshot.get("generation") if self._snapshot is not None else None
            if rejected_generation is not None and isinstance(generation, int) and generation > rejected_generation:
                return
            self._epoch += 1
            self._acked = False
            self._last_error = None
            self._renewal_due_monotonic = None
            self._renewal_after_generation = None
            self._retry_not_before_monotonic = None
            self._failure_count = 0
            self._condition.notify_all()
        self._publish_event.set()

    def _queue_observe_republish(self) -> bool:
        """Refresh an acknowledged Watch snapshot without opening a pause window.

        ``request_publish`` drops readiness first. That is required when
        enforcement might strengthen, and it is how a hook storm turns Watch
        into a fresh-approval deadlock: each resident-file or command-control
        update withdraws the snapshot, the next review pauses, and the pause
        updates the same files again. Watch does not stop those reviews, so
        keep serving the resident-validated observe snapshot until the refresh
        commits.
        """

        with self._condition:
            snapshot = self._snapshot
            if self._closed or not self._acked or snapshot is None or snapshot.get("mode") != "observe":
                return False
            generation = snapshot.get("generation")
            if not isinstance(generation, int) or generation <= 0:
                return False
            self._renewal_after_generation = generation
            self._retry_not_before_monotonic = self._monotonic_clock()
            self._failure_count = 0
        self._publish_event.set()
        return True

    def _republish_preserving_watch(self) -> None:
        if not self._queue_observe_republish():
            self.request_publish()

    def _accept_resident_fingerprint(self, fingerprint) -> None:
        """Handle resident metadata changes without hiding a policy edit.

        Resident mtime churn and a config change can land in one poll. Keeping
        the old observe snapshot in that case would let hooks run under Watch
        after the installed policy moved to enforce. Policy-input changes that
        are not an observe command-control refresh withdraw readiness first.
        """

        if self._input_fingerprint is None:
            self._input_fingerprint = fingerprint
            return
        same_resident = _same_resident_paths(self._input_fingerprint[1], fingerprint[1])
        if not same_resident:
            with self._condition:
                self._resident_startup_required = True
        previous_inputs = dict(self._input_fingerprint[0])
        current_inputs = dict(fingerprint[0])
        changed_paths = {
            path
            for path in previous_inputs.keys() | current_inputs.keys()
            if previous_inputs.get(path) != current_inputs.get(path)
        }
        self._input_fingerprint = fingerprint
        if changed_paths and self._policy_input_changed(changed_paths) and not self._observe_extension_refresh:
            self.request_publish()
            return
        if same_resident:
            with self._condition:
                if self._acked and self._snapshot is not None and self._snapshot.get("mode") == "enforce":
                    # Metadata churn is not a new policy or resident generation.
                    # Requests still carry the acknowledged generation and digest;
                    # Rust rejects stale bindings independently on every review.
                    # Revoking here makes ordinary hook traffic pause every harness.
                    return
            self._republish_preserving_watch()
            return
        self.request_publish()

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
        provision_native_verifier_key_for_store(self.store)

    def _mark_expired_locked(self) -> None:
        snapshot = self._snapshot
        if not self._acked or snapshot is None:
            return
        expires_at_ms = snapshot.get("expires_at_ms")
        if not isinstance(expires_at_ms, int) or expires_at_ms > int(self._wall_clock() * 1_000):
            return
        generation = snapshot.get("generation")
        self._acked = False
        self._last_error = "native_policy_snapshot_expired"
        self._renewal_due_monotonic = None
        self._renewal_after_generation = generation if isinstance(generation, int) and generation > 0 else None
        self._retry_not_before_monotonic = self._monotonic_clock()
        self._condition.notify_all()
        self._publish_event.set()

    @staticmethod
    def _renewal_jitter_seconds(snapshot: Mapping[str, object], remaining_seconds: float) -> float:
        digest = snapshot.get("policy_digest")
        generation = snapshot.get("generation")
        if not isinstance(digest, str) or not isinstance(generation, int) or remaining_seconds <= 0:
            return 0.0
        seed = hashlib.sha256(f"{generation}:{digest}".encode("ascii")).digest()
        fraction = int.from_bytes(seed[:4], "big") / float(1 << 32)
        return min(_RENEWAL_JITTER_MAX_SECONDS, remaining_seconds * 0.05) * fraction

    def _schedule_renewal_locked(self, snapshot: Mapping[str, object]) -> None:
        expires_at_ms = snapshot.get("expires_at_ms")
        if not isinstance(expires_at_ms, int):
            self._renewal_due_monotonic = self._monotonic_clock()
            return
        remaining_seconds = expires_at_ms / 1_000 - self._wall_clock()
        if remaining_seconds <= 0:
            self._renewal_due_monotonic = self._monotonic_clock()
            return
        lead_seconds = min(_RENEWAL_LEAD_SECONDS, max(1.0, remaining_seconds * 0.1))
        jitter_seconds = self._renewal_jitter_seconds(snapshot, remaining_seconds)
        due_in = max(0.0, remaining_seconds - lead_seconds - jitter_seconds)
        self._renewal_due_monotonic = self._monotonic_clock() + due_in

    def is_ready(self) -> bool:
        with self._condition:
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

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
            binding = {
                "generation": snapshot.get("generation"),
                "policy_digest": snapshot.get("policy_digest"),
                "runtime_identity": snapshot.get("runtime_identity"),
                "mode": snapshot.get("mode"),
            }
            if "command_extensions" in snapshot:
                binding["command_extensions_bound"] = True
            return binding

    def current_runtime_status(self) -> Any | None:
        """Return the verified runtime status bound to the acknowledged snapshot."""

        with self._condition:
            self._mark_expired_locked()
            if not self._acked or self._snapshot is None or self._closed:
                return None
            status = self._last_runtime_status
            identity = getattr(status, "identity", None)
            if identity is None or self._snapshot.get("runtime_identity") != getattr(identity, "sha256", None):
                return None
            return status

    def local_cli_publication_receipt(self, revision: int) -> dict[str, object] | None:
        """Bind control-plane status to an ACK for this exact saved revision."""
        with self._condition:
            self._mark_expired_locked()
            if (
                not self._acked
                or self._closed
                or self._snapshot is None
                or self._published_local_cli_revision != revision
            ):
                return None
            return {
                "revision": revision,
                "generation": self._snapshot["generation"],
                "policy_digest": self._snapshot["policy_digest"],
            }

    def _current_local_cli_revision(self) -> int | None:
        reader = getattr(self.store, "read_local_cli_revision", None)
        if not callable(reader):
            return None
        revision = reader()
        if type(revision) is not int or revision < 0:
            raise NativePolicySnapshotError("native_local_cli_revision_invalid")
        return revision

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
                # Known unavailable authority wakes the caller promptly. Keep
                # bounded retries for lost ACKs and resident recovery.
                if self._last_error in POLICY_SNAPSHOT_UNAVAILABLE_ERRORS:
                    return False
                remaining = deadline - self._monotonic_clock()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
            self._mark_expired_locked()
            return self._acked and self._snapshot is not None and not self._closed
