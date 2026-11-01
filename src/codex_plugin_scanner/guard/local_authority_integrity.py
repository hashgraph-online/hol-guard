"""Domain-separated integrity for local approval authority outside policy rows.

The native runtime signs and verifies these columns
(`local-authority-integrity --stdin`) with the code its own approval gate and
continuation grants use. Without a runtime that offers it, nothing is signed
and nothing verifies.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import cast

from .policy_integrity import PolicyIntegrityStatus, PolicyIntegrityVerificationResult

LOCAL_AUTHORITY_INTEGRITY_VERSION = 1
LOCAL_AUTHORITY_INTEGRITY_MAC_ALGORITHM = "hmac-sha256"
_FEATURE = "native-local-authority-integrity-v1"
_SCHEMA = "local-authority-integrity.v1"
_STATUSES = frozenset({"valid", "missing_integrity", "tampered", "unknown_key"})
_TIMEOUT_SECONDS = 10.0
# The verification message when no runtime answered: nothing was compared.
LOCAL_AUTHORITY_INTEGRITY_UNAVAILABLE = "local_authority_integrity_runtime_unavailable"


def sign_local_authority_payload(
    payload: Mapping[str, object],
    *,
    key: bytes,
    key_id: str,
    purpose: str,
    signed_at: str,
    deadline: float | None = None,
) -> dict[str, object]:
    """Sign a local authority payload with a purpose-specific derived key.

    `deadline` (monotonic) bounds the runtime call along with any active hook
    validation deadline.
    """

    answer = _ask(
        {
            "op": "sign",
            "payload": _json_object(payload),
            "purpose": purpose,
            "key_hex": key.hex(),
            "key_id": key_id,
            "signed_at": signed_at,
        },
        deadline,
    )
    if answer is None or answer.get("integrity_key_id") != key_id:
        raise RuntimeError("local authority signing requires the native runtime")
    return answer


def verify_local_authority_payload(
    payload: Mapping[str, object],
    integrity: Mapping[str, object],
    *,
    key: bytes | None,
    key_id: str | None,
    purpose: str,
) -> PolicyIntegrityVerificationResult:
    """Verify purpose-bound local authority without creating key material."""

    try:
        request: dict[str, object] = {
            "op": "verify",
            "payload": _json_object(payload),
            "purpose": purpose,
            "key_hex": None if key is None else key.hex(),
            "key_id": key_id,
            "integrity": _json_object(integrity),
        }
    except (TypeError, ValueError):
        return PolicyIntegrityVerificationResult(
            status="tampered",
            message="local_authority_integrity_payload_invalid",
        )
    answer = _ask(request)
    status = None if answer is None else answer.get("status")
    if answer is None or status not in _STATUSES:
        return PolicyIntegrityVerificationResult(
            status="unknown_key",
            message=LOCAL_AUTHORITY_INTEGRITY_UNAVAILABLE,
        )
    return PolicyIntegrityVerificationResult(
        status=cast(PolicyIntegrityStatus, status),
        payload_hash=_text(answer.get("payload_hash")),
        key_id=_text(answer.get("key_id")),
        message=_text(answer.get("message")),
    )


def _json_object(value: Mapping[str, object]) -> dict[str, object]:
    return cast(dict[str, object], json.loads(json.dumps(dict(value), allow_nan=False)))


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _ask(request: dict[str, object], deadline: float | None = None) -> dict[str, object] | None:
    """One runtime answer, bounded by `deadline` and any active hook validation deadline."""

    from .codex_hook_file_integrity import active_hook_validation_deadline
    from .mdm.runtime_request import runtime_answer

    bounds = [time.monotonic() + _TIMEOUT_SECONDS, deadline, active_hook_validation_deadline()]
    return runtime_answer(
        _FEATURE,
        "local-authority-integrity",
        {"schema": _SCHEMA, **request},
        output_limit=4096,
        deadline=min(bound for bound in bounds if bound is not None),
    )
