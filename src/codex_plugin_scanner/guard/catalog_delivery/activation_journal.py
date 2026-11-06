"""What the resident needs to reserve a staged pack with a control transition.

The resident authenticates, reserves and installs the pack itself; this
module hands it the staged draft.
"""

from __future__ import annotations

import json
import time

from ..native_command_control_authority_io import require_exclusive_command_control_mutation_lease
from ..native_command_control_authority_store import _key
from ..native_policy_snapshot_constants import NativePolicySnapshotError
from . import activation_baseline, lifecycle_store
from .activation_record import SCHEMA_V2
from .activation_store import directory_for_store
from .activation_transition import ActivationDraft


class UnverifiablePackTransitionError(NativePolicySnapshotError):
    """Pending pack bytes cannot authenticate against their approved transition."""


def reserve_request(store, connection, draft, *, recorded_at, now=None):
    """The ``pack_reserve`` the resident checks ``draft`` against and reserves.

    The schema marker is upgraded here. The resident retains the legacy
    baseline in an empty slot, authenticates the draft and checks it against
    the protected floor, the active security scope and the active slot it
    extends.
    """
    require_exclusive_command_control_mutation_lease(store.guard_home)
    if type(draft) is not ActivationDraft or draft.directory != directory_for_store(store):
        raise NativePolicySnapshotError("native_command_pack_draft_invalid")
    key = _key(store)
    baseline = None
    if draft.previous_digest is None:
        if draft.baseline_metadata is None:
            raise NativePolicySnapshotError("native_command_pack_baseline_missing")
        baseline = activation_baseline.baseline_request(connection, draft.baseline_metadata, recorded_at=recorded_at)
    try:
        format_v2 = json.loads(draft.data).get("schema") == SCHEMA_V2
    except (AttributeError, ValueError):
        raise NativePolicySnapshotError("native_command_pack_draft_invalid") from None
    from ..native_store_policy import encode_key
    from ..store_extension_control_authority_schema import ensure_extension_control_authority_schema
    from .active_security import read as read_security

    ensure_extension_control_authority_schema(connection, activate_packs=True, activation_format_v2=format_v2)
    fields = {
        "key_b64": encode_key(key),
        "floor": lifecycle_store.read(store),
        "security": read_security(store),
        "record_json": draft.data,
        "record_digest": draft.digest,
        "record_mac": draft.mac,
        "previous_digest": draft.previous_digest,
        "lifecycle_before": draft.lifecycle_before,
        "lifecycle_after": draft.lifecycle_after,
        "security_digest": draft.security_digest,
        "admitted_at": int(time.time()) if now is None else now,
        "baseline": baseline,
    }
    return {name: value for name, value in fields.items() if value is not None}
