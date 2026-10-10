"""Local CLI grant decision from the native runtime.

The resident reads ``guard.db`` and decides whether an unlisted CLI command is
covered by a this-device allow or block. Python sends the verified identity
material and the command id it resolved from the command model, and presents
the answer. Anything other than a bound ``ok`` decision is a
``NativeLocalCliGrantFailure`` carrying a reason code, which callers must treat
as "no authoritative answer", never as an allow.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request

LOCAL_CLI_GRANT_FEATURE = "local-cli-grant-v1"
_REQUEST_SCHEMA = "guard-local-cli-grant-request.v1"
_RESULT_SCHEMA = "guard-local-cli-grant-result.v1"
_PAYLOAD_KEYS = frozenset({"state", "cli_id", "identity_hash"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESIDENT_CODE = re.compile(r"^native_local_cli_grant_[a-z_]{1,64}$")
_UNAVAILABLE = "native_local_cli_grant_unavailable"

NativeGrantState = Literal["allowed", "blocked", "none"]


@dataclass(frozen=True, slots=True)
class NativeLocalCliGrant:
    state: NativeGrantState
    cli_id: str | None
    identity_hash: str | None


@dataclass(frozen=True, slots=True)
class NativeLocalCliGrantFailure:
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    code: str


def native_local_cli_grant(
    *,
    store_path: Path,
    guard_home: Path,
    current_action: str,
    source: Mapping[str, object],
    command_id: str | None,
) -> NativeLocalCliGrant | NativeLocalCliGrantFailure:
    """Return the resident's grant decision, or why there is none."""

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"local-cli-grant-{uuid4().hex}",
        "store_path": str(store_path),
        "guard_home": str(guard_home),
        "current_action": current_action,
        "source": dict(source),
        "command_id": command_id,
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return NativeLocalCliGrantFailure("native_local_cli_grant_request_invalid")
    if not ensure_resident_prerequisite(guard_home):
        return NativeLocalCliGrantFailure("native_local_cli_grant_prerequisite_unavailable")
    response = _resident_request(
        operation="local_cli_grant_decide",
        request=request,
        guard_home=guard_home,
        timeout_seconds=10.0,
        required_feature=LOCAL_CLI_GRANT_FEATURE,
        response_schema=_RESULT_SCHEMA,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        return NativeLocalCliGrantFailure(_UNAVAILABLE)
    status, code = response.get("status"), response.get("code")
    if status == "error":
        # A bound refusal names its reason. Keep only codes in the resident's
        # own namespace so arbitrary text never reaches diagnostics.
        reason = code if isinstance(code, str) and _RESIDENT_CODE.fullmatch(code) else _UNAVAILABLE
        return NativeLocalCliGrantFailure(reason)
    if status != "ok" or code != "ok":
        return NativeLocalCliGrantFailure(_UNAVAILABLE)
    decoded = _decode_payload(response.get("payload"))
    return decoded if decoded is not None else NativeLocalCliGrantFailure("native_local_cli_grant_payload_invalid")


def _decode_payload(payload: object) -> NativeLocalCliGrant | None:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        return None
    state = payload["state"]
    cli_id = payload["cli_id"]
    identity_hash = payload["identity_hash"]
    if state not in {"allowed", "blocked", "none"}:
        return None
    if cli_id is not None and not isinstance(cli_id, str):
        return None
    if identity_hash is not None and (not isinstance(identity_hash, str) or _SHA256.fullmatch(identity_hash) is None):
        return None
    if state != "none" and (cli_id is None or identity_hash is None):
        return None
    return NativeLocalCliGrant(state, cli_id, identity_hash)


__all__ = [
    "LOCAL_CLI_GRANT_FEATURE",
    "NativeLocalCliGrant",
    "NativeLocalCliGrantFailure",
    "native_local_cli_grant",
]
