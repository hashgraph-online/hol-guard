"""Retire previous native authority before one supported installation mutation.

One bounded worker owns the publication lock, native control, and Store cleanup.
Its caller can time out without releasing that serialization. A started native
request or committed SQL can have an ambiguous outcome; neither is rolled back
by timeout, and no late result authorizes a following phase.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from uuid import uuid4

from .native_policy_control_runtime import _native_policy_control_runtime_status_owned
from .native_policy_control_transport import _native_policy_control_request_owned
from .native_policy_publication_maintenance import (
    _active,
    _check_binding,
    capture_publication_mutation_binding,
    hold_bound_policy_publication_mutation,
)
from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .native_policy_snapshot_constants import (
    _LOCK_NAME,
    _STATE_NAME,
    _V3_GENERATION_LOCK_NAME,
    _V3_GENERATION_STATE_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotError,
)
from .native_policy_snapshot_control import observe_native_authority, withdraw_native_authority
from .native_policy_snapshot_mutation import NativePublisherLookup, notify_native_policy_mutation_before_deadline
from .native_policy_snapshot_retirement import reserve_native_policy_retirement
from .store_maintenance import capture_store_maintenance_lookup, store_maintenance_scope


@dataclass(frozen=True, slots=True)
class _RotationInputs:
    guard_home: Path
    database_path: Path
    read_existing_key: Callable[[], tuple[bytes | None, str | None]]


def _no_native_history(guard_home: Path, cancelled: threading.Event, deadline: float) -> bool:
    # An existing runtime directory, including an empty or malformed one, is
    # history. Never create/read through it to infer a cold absence shortcut.
    for name in (
        NATIVE_RUNTIME_STATE_DIRECTORY,
        _STATE_NAME,
        _LOCK_NAME,
        _V3_GENERATION_STATE_NAME,
        _V3_GENERATION_LOCK_NAME,
    ):
        _active(cancelled, deadline)
        try:
            (guard_home / name).lstat()
        except FileNotFoundError:
            continue
        except OSError:
            raise NativePolicySnapshotError("native_policy_snapshot_control_history_unavailable") from None
        return False
    _active(cancelled, deadline)
    return True


def _retire_existing_authority(
    store: _RotationInputs,
    *,
    new_installation_id: str,
    cancelled: threading.Event,
    deadline: float,
    before_reservation: Callable[[], None],
) -> None:
    _active(cancelled, deadline)
    status = _native_policy_control_runtime_status_owned(cancelled=cancelled, deadline_monotonic=deadline)
    _active(cancelled, deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or "policy-snapshot-control-v1" not in status.capabilities.features
    ):
        raise NativePolicySnapshotError("native_policy_snapshot_control_runtime_unavailable")
    master, _key_id = store.read_existing_key()
    _active(cancelled, deadline)
    if type(master) is not bytes or len(master) != 32:
        raise NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
    try:
        verifier = derive_native_policy_verifier_key(master)
        client = partial(_native_policy_control_request_owned, cancelled=cancelled)
        observation = observe_native_authority(
            executable=status.identity.path,
            guard_home=store.guard_home,
            runtime_identity=status.identity.sha256,
            verifier_key=verifier,
            deadline_monotonic=deadline,
            client=client,
        )
        _active(cancelled, deadline)
        digest = hashlib.sha256(
            b"hol-guard-installation-retirement-v1\0" + new_installation_id.encode("ascii")
        ).hexdigest()
        # Reservation can write before a later error. Cleanup must invalidate
        # process-local readiness even when no completed reservation returns.
        before_reservation()
        generation = reserve_native_policy_retirement(
            guard_home=store.guard_home,
            runtime_identity=status.identity.sha256,
            policy_integrity_key=master,
            observation=observation,
            retirement_policy_digest=digest,
            deadline_monotonic=deadline,
        )
        _active(cancelled, deadline)
        withdraw_native_authority(
            executable=status.identity.path,
            guard_home=store.guard_home,
            observation=observation,
            retirement_generation=generation,
            retirement_policy_digest=digest,
            verifier_key=verifier,
            deadline_monotonic=deadline,
            client=client,
        )
        _active(cancelled, deadline)
    finally:
        master = b""


def _rotate_owned(
    store: _RotationInputs,
    mutation: Callable[[str], dict[str, str]],
    *,
    cancelled: threading.Event,
    deadline: float,
) -> dict[str, str]:
    _active(cancelled, deadline)
    binding = capture_publication_mutation_binding(store.guard_home, cancelled=cancelled, deadline_monotonic=deadline)
    lookup = capture_store_maintenance_lookup(store.database_path, cancelled=cancelled, deadline_monotonic=deadline)
    publisher_lookup = NativePublisherLookup(store.guard_home, str(binding.canonical_home))
    _active(cancelled, deadline)
    new_installation_id = uuid4().hex
    _active(cancelled, deadline)
    with hold_bound_policy_publication_mutation(
        binding,
        guard_home=store.guard_home,
        cancelled=cancelled,
        deadline_monotonic=deadline,
    ):
        invalidate = False

        def mark_mutation() -> None:
            nonlocal invalidate
            invalidate = True

        def notify() -> None:
            notify_native_policy_mutation_before_deadline(
                publisher_lookup,
                guard_home=store.guard_home,
                deadline_monotonic=deadline,
                require_source_authority=True,
            )

        try:
            with store_maintenance_scope(store.database_path, lookup, deadline_monotonic=deadline):
                if not _no_native_history(store.guard_home, cancelled, deadline):
                    _retire_existing_authority(
                        store,
                        new_installation_id=new_installation_id,
                        cancelled=cancelled,
                        deadline=deadline,
                        before_reservation=mark_mutation,
                    )
                _active(cancelled, deadline)
                _check_binding(binding, store.guard_home)
                _active(cancelled, deadline)
                mark_mutation()
                result = mutation(new_installation_id)
                _active(cancelled, deadline)
        except BaseException:
            if invalidate:
                # Preserve the original failure. A cleanup failure cannot
                # restore authority or convert this failed operation to success.
                with suppress(Exception):
                    notify()
            raise
        notify()
        _active(cancelled, deadline)
        return result
