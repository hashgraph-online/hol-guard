"""Host secret-store handoff for a native writer holding the generation lock."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .native_store_policy import encode_key
from .store_base import _canonical_utc_timestamp

if TYPE_CHECKING:
    from .store import GuardStore


def prepare_policy_integrity_write(store: GuardStore, *, now: str, sign: bool) -> dict[str, object]:
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


def persist_policy_integrity_write(store: GuardStore, state: Mapping[str, object]) -> bool:
    return store._store_policy_integrity_control_state(state)
