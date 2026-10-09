"""Local CLI grant decision from the native runtime.

The resident reads ``guard.db`` and decides whether an unlisted CLI command is
covered by a this-device allow or block. Python sends the verified identity
material and the command id it resolved from the command model, and presents
the answer. A missing, malformed, or unbound reply is ``None``, which callers
must treat as "no authoritative answer", never as an allow.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .native_execution import _resident_request

LOCAL_CLI_GRANT_FEATURE = "local-cli-grant-v1"
_REQUEST_SCHEMA = "guard-local-cli-grant-request.v1"
_RESULT_SCHEMA = "guard-local-cli-grant-result.v1"
_PAYLOAD_KEYS = frozenset({"state", "cli_id", "identity_hash"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

NativeGrantState = Literal["allowed", "blocked", "none"]


@dataclass(frozen=True, slots=True)
class NativeLocalCliGrant:
    state: NativeGrantState
    cli_id: str | None
    identity_hash: str | None


def native_local_cli_grant(
    *,
    store_path: Path,
    guard_home: Path,
    current_action: str,
    source: Mapping[str, object],
    command_id: str | None,
) -> NativeLocalCliGrant | None:
    """Return the resident's grant decision, or ``None`` without an answer."""

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
        digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            ).hexdigest()
        )
    except (TypeError, ValueError):
        return None
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
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        return None
    return _decode_payload(response.get("payload"))


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


__all__ = ["LOCAL_CLI_GRANT_FEATURE", "NativeLocalCliGrant", "native_local_cli_grant"]
