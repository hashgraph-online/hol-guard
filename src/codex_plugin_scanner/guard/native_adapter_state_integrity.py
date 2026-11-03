"""Resident bridge for the ``adapter_state_integrity`` op.

Rust owns the MAC over an adapter's durable lifecycle state. That state names
the configuration file Guard took over and the backup it will restore, so the
MAC is what stands between an edited manifest and a file Guard overwrites
during install, repair or uninstall. This module ships the manifest and the
caller's copy of the adapter state key, binds the reply by ``request_id`` plus
``request_sha256`` and hands the answer back. Nothing is signed, compared or
digested here, so an unavailable resident can neither stamp a manifest nor
accept one.

The binding digest deliberately excludes the key: the wire carries the real
``integrity_key_b64`` while both sides digest a copy whose value is null, so a
reply, log or diagnostic quoting ``request_sha256`` reveals nothing about the
secret.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

ADAPTER_STATE_INTEGRITY_FEATURE = "adapter-state-integrity-v1"
_REQUEST_SCHEMA = "guard-adapter-state-integrity-request.v1"
_RESULT_SCHEMA = "guard-adapter-state-integrity-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


class AdapterStateIntegrityUnavailableError(RuntimeError):
    """The resident gave no answer, so no stored adapter path may be trusted."""

    reason: str = "native_adapter_state_integrity_unavailable"


def native_adapter_state_integrity(
    *,
    action: str,
    harness: str,
    payload: object,
    field: str | None = None,
    integrity_key_b64: str | None,
    integrity_key_id: str | None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Authenticate, verify or read one adapter state manifest in the runtime.

    ``action`` is ``authenticate``, ``verify`` or ``authenticated_field``. The
    answer is the stamped manifest, ``{"authenticated": bool}``, or that plus
    ``value`` holding the requested field when the manifest authenticates and
    the field holds a usable absolute path.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise AdapterStateIntegrityUnavailableError
    wire: dict[str, Any] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"adapter-state-integrity-{uuid4().hex}",
        "action": action,
        "harness": harness,
        "payload": payload,
        "field": field,
        "integrity_key_b64": integrity_key_b64,
        "integrity_key_id": integrity_key_id,
    }
    try:
        response = _resident_request(
            operation="adapter_state_integrity",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=ADAPTER_STATE_INTEGRITY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise AdapterStateIntegrityUnavailableError from None
    answer = _payload(response, {**wire, "integrity_key_b64": None}, home)
    if not isinstance(answer, dict):
        raise AdapterStateIntegrityUnavailableError
    return answer


_PROBE_HARNESS = "adapter-state-runtime-probe"


def adapter_state_runtime_available(guard_home: Path | None = None) -> bool:
    """Whether a resident that can stamp adapter state answers right now.

    Lifecycle work calls this before its first write. Authentication is the
    last step of an install, so a resident that is already gone when the
    install starts would otherwise leave the harness configuration rewritten
    and no manifest to uninstall from.

    Only the resident can answer that. The on-disk prerequisite says the
    owner-private verifier key exists, which stays true across a restart, a
    crash and a binary this feature was never compiled into, so it cannot
    stand in for a reply. This sends a real ``verify`` instead and takes any
    bound answer as reachable: the request travels the same transport, feature
    gate and reply binding a stamp would, and an unsigned empty payload simply
    authenticates as false. It carries no key, so the probe has no secret to
    leak and no manifest to change.
    """

    try:
        native_adapter_state_integrity(
            action="verify",
            harness=_PROBE_HARNESS,
            payload={},
            integrity_key_b64=None,
            integrity_key_id=None,
            guard_home=guard_home,
        )
    except AdapterStateIntegrityUnavailableError:
        return False
    return True
