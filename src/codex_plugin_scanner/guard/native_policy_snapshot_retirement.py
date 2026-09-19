"""Reserve retirement above authenticated observation and existing local work."""

from __future__ import annotations

from pathlib import Path

from .native_policy_publication_lock import hold_policy_publication_mutation
from .native_policy_snapshot_codec import derive_native_policy_verifier_key
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .native_policy_snapshot_control import (
    NativeAuthorityObservation,
    _digest,
    _generation,
    _reference_value,
    _remaining,
)
from .native_policy_snapshot_generation import _private_guard_home, _v3_generation_for_policy
from .native_policy_snapshot_policy import _scope_digest_v3
from .native_policy_snapshot_storage import (
    _read_v3_generation_state,
    _read_v3_snapshot_cache,
    _recover_v3_snapshot_transaction,
    _v3_generation_lock,
    _write_v3_generation_state,
)


def reserve_native_policy_retirement(
    *,
    guard_home: Path,
    runtime_identity: str,
    policy_integrity_key: bytes,
    observation: NativeAuthorityObservation,
    retirement_policy_digest: str,
    deadline_monotonic: float,
) -> int:
    """Reserve only; neither native withdrawal nor SQL success is implied.

    The caller retains the publication mutation lock across authenticated
    observation, this reservation, withdrawal, and its SQL mutation. Reentry
    here enforces the same lock order. The generation lock is always released
    before returning, so no control transport executes while it is held.

    Recovery or an atomic reservation may complete before a later deadline
    failure. An exception supplies no native or SQL success and does not imply
    unchanged local state. Every later attempt rereads the journal and counter;
    it must never reuse a generation on the assumption that this call failed.
    """
    _remaining(deadline_monotonic)
    if type(observation) is not NativeAuthorityObservation:
        raise NativePolicySnapshotError("native_policy_snapshot_control_invalid")
    runtime = _digest(runtime_identity)
    scope = _digest(observation.scope_digest)
    _generation(observation.resident_generation)
    _reference_value(observation.authority)
    if observation.runtime_identity != runtime or scope != _scope_digest_v3(guard_home):
        raise NativePolicySnapshotError("native_policy_snapshot_control_subject_changed")
    digest = _digest(retirement_policy_digest)
    minimum = None if observation.authority is None else observation.authority.generation_floor
    verifier_key: bytes | None = None
    try:
        verifier_key = derive_native_policy_verifier_key(policy_integrity_key)
        with hold_policy_publication_mutation(guard_home, timeout_seconds=min(5.0, _remaining(deadline_monotonic))):
            _private_guard_home(guard_home)
            with _v3_generation_lock(guard_home, deadline_monotonic=deadline_monotonic) as descriptor:
                _recover_v3_snapshot_transaction(guard_home, verifier_key)
                # Never discard a damaged cache or infer a missing/rolled-back
                # counter from a reservation request. A valid older cache is
                # retained for a subsequent fresh-source publication attempt.
                cached = _read_v3_snapshot_cache(guard_home, verifier_key=verifier_key)
                current = _read_v3_generation_state(guard_home)
                if cached is not None:
                    cached_generation = _generation(cached[0].get("generation"))
                    if (
                        current is None
                        or current[0] < cached_generation
                        or (current[0] == cached_generation and current[1] != cached[0].get("policy_digest"))
                    ):
                        raise NativePolicySnapshotError("native_policy_snapshot_generation_state_invalid")
                generation = _v3_generation_for_policy(
                    guard_home,
                    digest,
                    force_increment=True,
                    minimum_generation=minimum,
                    deadline_monotonic=deadline_monotonic,
                    lock_descriptor=descriptor,
                    persist_state=False,
                )
                _remaining(deadline_monotonic)
                _write_v3_generation_state(guard_home, generation=generation, policy_digest=digest)
            _remaining(deadline_monotonic)
            return generation
    finally:
        verifier_key = None
        policy_integrity_key = b""
