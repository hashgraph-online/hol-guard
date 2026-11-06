"""Transport for the native MCP tool-call identity owner.

Rust builds the runtime MCP artifact (server identity, tool identity, the
tool-definition authority binding and firewall evidence) and its approval
digest or context token in one call. Python ships the session and call facts as
data, binds the reply to the request digest and fails closed on anything else.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import GuardArtifact
from .native_context import _canonical_request_sha256, _is_sha256_digest, _resolve_digest_home
from .native_execution import _resident_request

NATIVE_MCP_TOOL_CALL_IDENTITY_FEATURE = "mcp-tool-call-identity-v1"
_REQUEST_SCHEMA = "guard-mcp-tool-call-identity-request.v1"
_RESULT_SCHEMA = "guard-mcp-tool-call-identity-result.v1"
_OPERATION = "mcp_tool_call_identity"
_UNAVAILABLE = "native_mcp_tool_approval_hash_unavailable"
_PROVIDER_HASH_CODE = "native_mcp_tool_call_identity_provider_hash_invalid"
# The largest envelope this bridge will frame. It is not
# ``MCP_TOOL_CALL_IDENTITY_MAX_BYTES``: the op measures its own canonical
# request and this measures the envelope carrying it, which is the larger of
# the two, so holding the envelope to the op's number would refuse calls the op
# would have accepted -- and refuse them as a bare unavailable, with none of the
# reason the op would have given. Held under the transport's frame limit so a
# request past it is refused for its size rather than as a malformed frame.
_MAX_REQUEST_BYTES = 6 * 1024 * 1024 - 64 * 1024
_TIMEOUT_SECONDS = 5.0
_TOKEN_PREFIX = "guard-approval-context:v1:"
_ARTIFACT_KEYS = frozenset(
    {
        "artifact_id",
        "name",
        "harness",
        "source_scope",
        "config_path",
        "command",
        "transport",
        "publisher",
        "metadata",
    }
)
_CODE = re.compile(r"^native_mcp_tool_call_identity_[a-z_]{1,64}$")


@dataclass(frozen=True, slots=True)
class NativeToolCallIdentity:
    """The built artifact, its approval hash (when asked for) and risk categories."""

    artifact: GuardArtifact
    artifact_hash: str | None
    risk_categories: tuple[str, ...]


def server_identity_dto(identity: Any) -> dict[str, object] | None:
    return None if identity is None else asdict(identity)


def artifact_dto(artifact: GuardArtifact) -> dict[str, object]:
    dto: dict[str, object] = {key: getattr(artifact, key) for key in _ARTIFACT_KEYS if key != "metadata"}
    dto["metadata"] = dict(artifact.metadata)
    return dto


def native_tool_call_identity(
    *,
    build: Mapping[str, object] | None = None,
    artifact: GuardArtifact | None = None,
    hash_input: Mapping[str, object] | None = None,
    guard_home: Path | None = None,
) -> NativeToolCallIdentity:
    """Build (``build``) or re-hash (``artifact``) one tool-call identity natively."""

    if (build is None) is (artifact is None):
        raise ValueError(_UNAVAILABLE)
    home = _resolve_digest_home(guard_home)
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"mcp-tool-call-identity-{uuid.uuid4().hex}",
        "build": None if build is None else dict(build),
        "artifact": None if artifact is None else artifact_dto(artifact),
        "hash": None if hash_input is None else dict(hash_input),
    }
    try:
        # Plain JSON types only: the worker owns canonicalization, so nothing
        # is coerced here that would change a persisted digest.
        request = json.loads(json.dumps(request))
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        raise ValueError(_UNAVAILABLE) from None
    response = _resident_request(
        operation=_OPERATION,
        request=request,
        guard_home=home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=NATIVE_MCP_TOOL_CALL_IDENTITY_FEATURE,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
    )
    if (
        response is None
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
    ):
        raise ValueError(_UNAVAILABLE)
    code = response.get("code")
    # An error carries no authority and an oversized request is refused before
    # the worker can hash it, so only an `ok` answer must echo the digest.
    if response.get("status") == "error":
        if code == _PROVIDER_HASH_CODE:
            raise ValueError("invalid provider catalog authority hash")
        raise ValueError(f"{_UNAVAILABLE}:{code}" if isinstance(code, str) and _CODE.fullmatch(code) else _UNAVAILABLE)
    if response.get("status") != "ok" or code != "ok" or response.get("request_sha256") != digest:
        raise ValueError(_UNAVAILABLE)
    return _decode(response.get("payload"), expect_hash=hash_input is not None, token=_expects_token(hash_input))


def _expects_token(hash_input: Mapping[str, object] | None) -> bool:
    return hash_input is not None and hash_input.get("config") is not None


def _decode(payload: object, *, expect_hash: bool, token: bool) -> NativeToolCallIdentity:
    if (
        not isinstance(payload, dict)
        or set(payload) != {"artifact", "runtime_private_metadata", "artifact_hash", "risk_categories"}
        or not isinstance(payload["artifact"], dict)
        or set(payload["artifact"]) != _ARTIFACT_KEYS
        or not isinstance(payload["artifact"]["metadata"], dict)
        or not isinstance(payload["runtime_private_metadata"], dict)
        or not isinstance(payload["risk_categories"], list)
        or not all(isinstance(item, str) for item in payload["risk_categories"])
    ):
        raise ValueError(_UNAVAILABLE)
    artifact_hash = payload["artifact_hash"]
    if expect_hash:
        valid = isinstance(artifact_hash, str) and (
            artifact_hash.startswith(_TOKEN_PREFIX) if token else _is_sha256_digest(artifact_hash)
        )
        if not valid:
            raise ValueError(_UNAVAILABLE)
    elif artifact_hash is not None:
        raise ValueError(_UNAVAILABLE)
    wire = payload["artifact"]
    return NativeToolCallIdentity(
        artifact=GuardArtifact(
            artifact_id=wire["artifact_id"],
            name=wire["name"],
            harness=wire["harness"],
            artifact_type="tool_call",
            source_scope=wire["source_scope"],
            config_path=wire["config_path"],
            command=wire["command"],
            transport=wire["transport"],
            publisher=wire["publisher"],
            metadata=wire["metadata"],
            runtime_private_metadata=payload["runtime_private_metadata"],
        ),
        artifact_hash=artifact_hash,
        risk_categories=tuple(payload["risk_categories"]),
    )


__all__ = [
    "NATIVE_MCP_TOOL_CALL_IDENTITY_FEATURE",
    "NativeToolCallIdentity",
    "artifact_dto",
    "native_tool_call_identity",
    "server_identity_dto",
]
