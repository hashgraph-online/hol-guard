"""Resident bridge for the ``approval_scope_select`` op.

Rust owns what an approval resolution actually covers: whether the scope a
client chose is one the request offers for that action, whether a client
resolving against a superseded contract is still heard, and whether a legacy
client's wider choice is narrowed to the artifact or refused outright. This
module only narrows the request to the fields the contract reads, ships the
contract version and digest the client echoed back, binds the reply by
``request_id`` plus ``request_sha256`` and hands the answer back. Nothing is
recomputed here, so an unavailable resident can never honour a scope the
request does not offer.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_approval_scope import ApprovalScopeUnavailableError, _prepared_item
from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

APPROVAL_SCOPE_SELECT_FEATURE = "approval-scope-select-v1"
_REQUEST_SCHEMA = "guard-approval-scope-select-request.v1"
_RESULT_SCHEMA = "guard-approval-scope-select-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


def native_approval_scope_selection(
    item: Mapping[str, object],
    *,
    action: str,
    requested_scope: str,
    contract_version: str | None,
    contract_digest: str | None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Resolve one approval selection in the resident; raise when it cannot.

    ``item`` carries every name in ``REQUEST_FIELDS`` plus ``workspace_target``,
    exactly as the ``approval_scope`` op takes it. The answer is the resident's
    payload: a selection with the scope it applied, or a refusal naming the
    condition, each with the contract the resident derived.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise ApprovalScopeUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"approval-scope-select-{uuid4().hex}",
        "item": _prepared_item(item),
        "action": action,
        "requested_scope": requested_scope,
        "contract_version": contract_version,
        "contract_digest": contract_digest,
    }
    try:
        response = _resident_request(
            operation="approval_scope_select",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=APPROVAL_SCOPE_SELECT_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise ApprovalScopeUnavailableError from None
    payload = _payload(response, wire, home)
    if not isinstance(payload, dict):
        raise ApprovalScopeUnavailableError
    return payload
