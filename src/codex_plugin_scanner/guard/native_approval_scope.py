"""Resident bridge for the ``approval_scope`` op.

Rust owns the action-aware scope contract of an approval request: which scopes
an allow or a block may use, the restrictions that bind them, the contract
digest a client must echo back, the exact-action eligibility and the
exact-action token. This module only narrows requests to the fields the
contract reads, binds the reply by ``request_id`` plus ``request_sha256`` and
decodes it. A missing, malformed or mismatched reply raises; nothing is ever
recomputed in Python, so an unavailable resident can never widen a scope.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NamedTuple
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

APPROVAL_SCOPE_FEATURE = "approval-scope-v1"
_REQUEST_SCHEMA = "guard-approval-scope-request.v1"
_RESULT_SCHEMA = "guard-approval-scope-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_ITEMS = 1024
UNAVAILABLE = "native_approval_scope_unavailable"
# Every field is sent, null when absent: the reply digest binds to the
# resident's own serialization of the typed request.
REQUEST_FIELDS = (
    "artifact_id",
    "artifact_type",
    "artifact_hash",
    "artifact_name",
    "policy_action",
    "harness",
    "publisher",
    "source_scope",
    "config_path",
    "wrapper_chain",
    "action_identity",
    "raw_command_text",
    "action_envelope_json",
    "scanner_evidence",
)


class ApprovalScopeUnavailableError(ValueError):
    """The resident could not derive the scope contract; nothing was recomputed."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


class NativeScope(NamedTuple):
    """One request's contract in the shape the resident replied with."""

    contract: dict[str, object]
    exact_context_token: str | None


def native_approval_scopes(
    items: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> list[NativeScope]:
    """Derive scope contracts in the resident; raise when it cannot.

    Each item carries every name in ``REQUEST_FIELDS`` plus ``workspace_target``, the
    workspace the caller resolved on its own filesystem.
    """

    if not items:
        return []
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise ApprovalScopeUnavailableError
    results: list[NativeScope] = []
    for start in range(0, len(items), _MAX_ITEMS):
        chunk = items[start : start + _MAX_ITEMS]
        wire: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "request_id": f"approval-scope-{uuid4().hex}",
            "items": [dict(item) for item in chunk],
        }
        try:
            response = _resident_request(
                operation="approval_scope",
                request=wire,
                guard_home=home,
                timeout_seconds=_TIMEOUT_SECONDS,
                required_feature=APPROVAL_SCOPE_FEATURE,
                response_schema=_RESULT_SCHEMA,
                max_request_bytes=_MAX_REQUEST_BYTES,
                record_success=False,
            )
        except (TypeError, ValueError, OSError, RuntimeError):
            raise ApprovalScopeUnavailableError from None
        payload = _payload(response, wire, home)
        reply = payload.get("items") if payload is not None else None
        if not isinstance(reply, list) or len(reply) != len(chunk):
            raise ApprovalScopeUnavailableError
        for entry in reply:
            if not isinstance(entry, dict):
                raise ApprovalScopeUnavailableError
            contract = dict(entry)
            token = contract.pop("exact_context_token", None)
            if token is not None and not isinstance(token, str):
                raise ApprovalScopeUnavailableError
            results.append(NativeScope(contract, token))
    return results
