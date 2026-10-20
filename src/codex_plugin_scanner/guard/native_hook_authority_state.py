"""Resident bridge for the ``hook_authority_state`` op.

Rust owns the signed Claude and Cursor hook authority state that lives in the
``sync_state`` table: it signs, stores, verifies, expires and deletes the
pending-permission notices, their per-session indexes, the Cursor pending shell
states and the Cursor native allowances, and it writes the integrity audit
events. This module only ships the request, the integrity key material and the
clock, binds the reply by ``request_id`` plus ``request_sha256`` and decodes
it. Nothing is verified or signed in Python; a resident that cannot answer
yields ``None`` and every caller fails closed (no state is trusted).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload, encode_key

if TYPE_CHECKING:
    from .store import GuardStore

HOOK_AUTHORITY_STATE_FEATURE = "hook-authority-state-v1"
HOOK_AUTHORITY_STATE_SESSION_OPS_FEATURE = "hook-authority-state-session-ops-v1"
_REQUEST_SCHEMA = "guard-hook-authority-state-request.v1"
_RESULT_SCHEMA = "guard-hook-authority-state-result.v1"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 512 * 1024


def hook_authority_state(
    store: GuardStore,
    op: str,
    *,
    now: str,
    create_key: bool = False,
    required_feature: str = HOOK_AUTHORITY_STATE_FEATURE,
    **fields: object,
) -> dict[str, object] | None:
    """The resident's ``ok`` payload for ``op``, or ``None`` when it cannot answer.

    ``create_key`` lets the store ops mint the integrity key on first use, as
    the retired signing path did; every read path only uses an existing key.
    Fields set to ``None`` are omitted from the request.
    """

    home = Path(store.guard_home)
    try:
        if not ensure_resident_prerequisite(home):
            return None
        key, key_id = store._policy_integrity_secret_material(create=create_key)
    except (OSError, RuntimeError, ValueError):
        return None
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"hook-authority-state-{uuid4().hex}",
        "store_path": str(store.path),
        "guard_home": str(home),
        "op": op,
        "now": now,
    }
    if key is not None and key_id is not None:
        wire["integrity_key_b64"] = encode_key(key)
        wire["integrity_key_id"] = key_id
    wire.update({name: value for name, value in fields.items() if value is not None})
    try:
        response = _resident_request(
            operation="hook_authority_state",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=required_feature,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError):
        return None
    return _payload(response, wire, home)


def object_field(payload: dict[str, object] | None, name: str) -> dict[str, object] | None:
    """A dict-valued reply field, else ``None``."""

    value = payload.get(name) if payload is not None else None
    return value if isinstance(value, dict) else None


def text_field(payload: dict[str, object] | None, name: str) -> str | None:
    """A non-empty string reply field, else ``None``."""

    value = payload.get(name) if payload is not None else None
    return value if isinstance(value, str) and value else None


def flag_field(payload: dict[str, object] | None, name: str) -> bool:
    """Whether a reply field is exactly ``true``."""

    return payload is not None and payload.get(name) is True


def keys_field(payload: dict[str, object] | None, name: str) -> list[str]:
    """A list-of-strings reply field; anything else is no keys."""

    value = payload.get(name) if payload is not None else None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return []
