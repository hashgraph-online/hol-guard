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

import json
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
# Matches the keys `approval_scope_material` digests, plus the envelope fields
# the contract reads beside that digest. Anything else in the stored envelope
# (tool bodies, file contents) is not authorization material.
_ENVELOPE_KEYS = (
    "schema_version",
    "harness",
    "event_name",
    "action_type",
    "workspace_hash",
    "tool_name",
    "command",
    "raw_command_text",
    "command_text",
    "commandText",
    "prompt_excerpt",
    "target_paths",
    "network_hosts",
    "mcp_server",
    "mcp_tool",
    "package_manager",
    "package_name",
    "command_category",
    "package_intent_kind",
    "package_targets",
    "script_name",
    "wrapper_chain",
    "once_only_reason",
    "exact_context_token",
    "exact_identity_kind",
)
_RAW_PAYLOAD_KEYS = ("permission_mode", "permissionMode")


class ApprovalScopeUnavailableError(ValueError):
    """The resident could not derive the scope contract; nothing was recomputed."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


class NativeScope(NamedTuple):
    """One request's contract in the shape the resident replied with."""

    contract: dict[str, object]
    exact_context_token: str | None


def _narrow_envelope(value: object) -> object:
    """Drop envelope fields the resident does not read."""

    if not isinstance(value, dict):
        return value
    narrowed = {key: value[key] for key in _ENVELOPE_KEYS if key in value}
    raw_payload = value.get("raw_payload_redacted")
    if isinstance(raw_payload, dict):
        narrowed["raw_payload_redacted"] = {
            key: raw_payload[key] for key in _RAW_PAYLOAD_KEYS if key in raw_payload
        }
    return narrowed


def _prepared_item(item: Mapping[str, object]) -> dict[str, object]:
    prepared = dict(item)
    if "action_envelope_json" in prepared:
        prepared["action_envelope_json"] = _narrow_envelope(prepared["action_envelope_json"])
    return prepared


def _request_byte_length(items: Sequence[Mapping[str, object]]) -> int:
    """Byte length of the envelope `_resident_request` actually sends."""

    envelope = {
        "operation": "approval_scope",
        "request": {
            "schema": _REQUEST_SCHEMA,
            "request_id": "approval-scope-" + ("0" * 32),
            "items": [dict(item) for item in items],
        },
        "deadline_budget_ms": max(1, int(_TIMEOUT_SECONDS * 1000)),
    }
    try:
        encoded = json.dumps(envelope).encode("utf-8")
    except (TypeError, ValueError):
        raise ApprovalScopeUnavailableError from None
    return len(encoded)


def _item_chunks(items: Sequence[Mapping[str, object]]) -> list[list[Mapping[str, object]]]:
    """Split items before a chunk would exceed the count or byte cap.

    A single item that cannot fit is fail-closed: the caller gets no partial
    contract list and nothing is recomputed in Python.
    """

    chunks: list[list[Mapping[str, object]]] = []
    current: list[Mapping[str, object]] = []
    for item in items:
        if not current:
            if _request_byte_length([item]) > _MAX_REQUEST_BYTES:
                raise ApprovalScopeUnavailableError
            current = [item]
            continue
        proposed = [*current, item]
        over_count = len(proposed) > _MAX_ITEMS
        over_bytes = _request_byte_length(proposed) > _MAX_REQUEST_BYTES
        if over_count or over_bytes:
            chunks.append(current)
            if _request_byte_length([item]) > _MAX_REQUEST_BYTES:
                raise ApprovalScopeUnavailableError
            current = [item]
        else:
            current = proposed
    if current:
        chunks.append(current)
    return chunks


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
    for chunk in _item_chunks([_prepared_item(item) for item in items]):
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
