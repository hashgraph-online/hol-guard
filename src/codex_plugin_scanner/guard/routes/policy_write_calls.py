"""The policy-integrity steps the daemon's own policy writes still need.

The daemon answers ``POST /v1/policy/decisions`` and ``/v1/policy/clear``
itself: it checks the approval gate, holds the generation lock and writes the
rows through the resident store, which signs them. The key store and the
trusted control state stay here, so the daemon asks for the key and the
generation it advances from before the write, and hands back the state the
resident advanced to after it.

The daemon holds ``policy-integrity-generation.lock`` across both calls, so
neither takes it here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from ..native_store_policy import encode_key
from ..store import GuardStore
from ..store_base import _canonical_utc_timestamp


def _invalid() -> Exception:
    from ..library_calls import LibraryCallError

    return LibraryCallError("invalid_arguments")


def integrity_begin(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Refresh the integrity state and, when ``sign`` asks, begin a generation.

    Answers the integrity mode and, when the store is protected and the key
    exists, the key, its id and the generation the write advances from.
    """

    now = args.get("now")
    sign = args.get("sign")
    if not isinstance(now, str) or not isinstance(sign, bool):
        raise _invalid()
    now = _canonical_utc_timestamp(now)
    material = store._policy_integrity_secret_material(create=True)
    with store._connect() as connection:
        state = store._refresh_policy_integrity_state(
            connection,
            now=now,
            create_key=True,
            secret_material=material,
            allow_cutover_resign=False,
        )
    mode = state.get("mode")
    key, key_id = material
    if sign and mode == "protected" and key is not None and key_id is not None:
        trusted_state = store._load_policy_integrity_control_state(create=True)
        if trusted_state is not None:
            return {
                "mode": mode,
                "current_generation": store._begin_policy_integrity_generation(trusted_state),
                "integrity_key_b64": encode_key(key),
                "integrity_key_id": key_id,
            }
    return {"mode": mode}


def integrity_finalize(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Adopt the generation the resident advanced to."""

    next_control_state = args.get("next_control_state")
    if not isinstance(next_control_state, dict):
        raise _invalid()
    # A state that does not persist leaves the rows signed past the trusted
    # generation, so the daemon must not report the write as done.
    if not store._store_policy_integrity_control_state(next_control_state):
        from ..library_calls import LibraryCallError

        raise LibraryCallError("policy_integrity_finalize_failed")
    return {"ok": True}


POLICY_WRITE_CALLS = {
    "policy.integrity_begin": cast(Any, integrity_begin),
    "policy.integrity_finalize": cast(Any, integrity_finalize),
}
