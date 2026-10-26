"""Resident bridge for the ``approval_persist_select`` op.

Rust owns whether an approval may be remembered and whether the action it
allows can reach an execution at all: a narrowed selection is never saved, a
remembered artifact decision needs the request to be exact-action persistable,
and an allow with no binding is refused rather than recorded. This module only
narrows the request to the fields the contract reads, ships what the client
echoed back, binds the reply by ``request_id`` plus ``request_sha256`` and
hands the answer back. Nothing is recomputed here, so an unavailable resident
can never save a decision the request does not support.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_approval_scope import ApprovalScopeUnavailableError, _prepared_item
from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

APPROVAL_PERSIST_SELECT_FEATURE = "approval-persist-select-v1"
_REQUEST_SCHEMA = "guard-approval-persist-select-request.v1"
_RESULT_SCHEMA = "guard-approval-persist-select-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024


def native_approval_persist_selection(
    item: Mapping[str, object],
    *,
    action: str,
    applied_scope: str,
    persist_policy: bool | None,
    scope_narrowed: bool,
    contract_version: str | None,
    contract_digest: str | None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Resolve one approval's persistence in the resident; raise when it cannot.

    ``item`` carries every name in ``REQUEST_FIELDS`` plus ``workspace_target``,
    exactly as the ``approval_scope`` op takes it. The answer is the resident's
    payload: the persistence mode it selected, or a refusal naming the
    condition, each with the contract the resident derived.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise ApprovalScopeUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"approval-persist-select-{uuid4().hex}",
        "item": _prepared_item(item),
        "action": action,
        "applied_scope": applied_scope,
        "persist_policy": persist_policy,
        "scope_narrowed": scope_narrowed,
        "contract_version": contract_version,
        "contract_digest": contract_digest,
    }
    try:
        response = _resident_request(
            operation="approval_persist_select",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=APPROVAL_PERSIST_SELECT_FEATURE,
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
