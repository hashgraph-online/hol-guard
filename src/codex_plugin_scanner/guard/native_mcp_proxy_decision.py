"""Transport for the native MCP proxy decision owner.

The resident decides the authoritative outcomes of the MCP proxy: the
``tools/list`` catalog state machine, how one ``tools/call`` is routed, the
execution-boundary revalidation after a saved approval was claimed, and how a
package policy composes with the tool policy that carries it. Python frames the
stream, gathers facts from its collaborators (stores, claims, prompts) and
renders the answer. It never recomputes or overrides a verdict.

Facts only a collaborator can supply are requested lazily: the resident replies
``{"need": <name>}``, the caller supplies exactly that fact, and the identical
request is repeated. A supplier receives the resident's ``need`` reply. Anything but a bound, well-formed answer raises
``NativeMcpProxyDecisionError`` so callers fail closed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_resident_prerequisite_reason import prerequisite_unavailable_code
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure, native_record_resident_success

MCP_PROXY_DECISION_FEATURE = "mcp-proxy-decision-v1"
MCP_PROXY_ARCHIVE_VERIFY_FEATURE = "mcp-proxy-archive-verify-v1"
MCP_PROXY_ARCHIVE_BINDING_REQUIRED_FEATURE = "mcp-proxy-archive-binding-required-v1"
# The resident also classifies the answer to an inline approval prompt. An older
# resident rejects that query as an unknown check, so a caller asks for it by name.
MCP_PROXY_INLINE_APPROVAL_REPLY_FEATURE = "mcp-proxy-inline-approval-reply-v1"
# The resident spells the sensitive read's artifact content hash itself, from
# the artifact fields the context query carries. An older resident rejects
# those fields as unknown, so a caller asks for it by name.
MCP_SENSITIVE_READ_ARTIFACT_FEATURE = "mcp-sensitive-read-artifact-v1"
# The resident also writes the text and payload a stopped package-lane call
# answers with. An older resident rejects that query as an unknown check, so a
# caller asks for it by name.
MCP_PROXY_PACKAGE_ANSWER_FEATURE = "mcp-proxy-package-answer-v1"
_REQUEST_SCHEMA = "guard-mcp-proxy-decision-request.v1"
_RESULT_SCHEMA = "guard-mcp-proxy-decision-result.v1"
_OPERATION = "mcp_proxy_decide"
_MAX_REQUEST_BYTES = 5 * 1024 * 1024
_MAX_NEED_ROUNDS = 4
_TIMEOUT_SECONDS = 10.0

Supplier = Callable[[Mapping[str, Any]], Mapping[str, object]]


class NativeMcpProxyDecisionError(ValueError):
    """No authoritative native answer; callers must fail closed."""


def _fail(code: str) -> NativeMcpProxyDecisionError:
    return NativeMcpProxyDecisionError(code)


def _round_trip(
    query: Mapping[str, object], guard_home: Path, required_feature: str
) -> tuple[dict[str, Any], str, str]:
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"mcp-proxy-decision-{uuid4().hex}",
        "query": dict(query),
    }
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise _fail("native_mcp_proxy_decision_request_invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        raise _fail(prerequisite_unavailable_code("native_mcp_proxy_decision_prerequisite_unavailable", guard_home))
    response = _resident_request(
        operation=_OPERATION,
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        required_feature=required_feature,
        response_schema=_RESULT_SCHEMA,
        max_request_bytes=_MAX_REQUEST_BYTES,
        record_success=False,
    )
    if response is None:
        # ``_resident_request`` already recorded the transport, malformed, status or
        # schema failure; recording it again would double-count one outage.
        raise _fail("native_mcp_proxy_decision_unavailable")
    if (
        response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != digest
    ):
        _record_failure(guard_home, "native_mcp_proxy_decision_binding_mismatch")
        raise _fail("native_mcp_proxy_decision_unavailable")
    if response.get("status") != "ok" or response.get("code") != "ok":
        # A bound refusal is the resident's answer for this exact request, not
        # an outage: it must not count toward the shared availability circuit.
        _record_success(guard_home)
        raise _fail("native_mcp_proxy_decision_refused")
    payload = response.get("payload")
    if not isinstance(payload, dict):
        _record_failure(guard_home, "native_mcp_proxy_decision_payload_invalid")
        raise _fail("native_mcp_proxy_decision_payload_invalid")
    return payload, digest, str(request["request_id"])


def native_mcp_proxy_decide(
    query: Mapping[str, object],
    *,
    guard_home: Path,
    supply: Mapping[str, Supplier] | None = None,
    required_feature: str = MCP_PROXY_DECISION_FEATURE,
) -> dict[str, Any]:
    """Return the resident's payload for ``query``, resolving ``need`` replies."""

    current = dict(query)
    for _ in range(_MAX_NEED_ROUNDS):
        payload, _digest, _request_id = _round_trip(current, guard_home, required_feature)
        need = payload.get("need")
        if need is None:
            _record_success(guard_home)
            return payload
        supplier = (supply or {}).get(need) if isinstance(need, str) else None
        if supplier is None:
            # A caller-side gap, not a resident failure: it never trips the circuit.
            raise _fail("native_mcp_proxy_decision_need_unsupplied")
        current = {**current, **supplier(payload)}
    raise _fail("native_mcp_proxy_decision_need_loop")


def _record_success(guard_home: Path) -> None:
    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_success(status.identity.sha256, guard_home)


def _record_failure(guard_home: Path, reason: str) -> None:
    status = native_runtime_status()
    if status.identity is not None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=reason)


def tool_facts(decision: Any) -> dict[str, object]:
    """The decision-relevant facts of one ``ToolCallDecision``."""

    return {
        "action": decision.action,
        "source": decision.source,
        "current_action": decision.current_action,
        "saved_action": decision.saved_action,
        "approval_reuse_status": decision.approval_reuse_status,
        "approval_reuse_reason_code": decision.approval_reuse_reason_code,
        "has_pending": decision.pending_approval_reuse_decision is not None,
    }


def package_facts(resolution: Any) -> dict[str, object]:
    """The decision-relevant facts of one package policy resolution."""

    return {
        "saved_policy_blocks": bool(resolution.saved_policy_blocks),
        "current_action": resolution.current_action,
        "policy_action": resolution.evaluation.policy_action,
        "has_pending": resolution.pending_approval_reuse_decision is not None,
    }


def cursor_fact(cursor: object) -> dict[str, object]:
    if cursor is None:
        return {"kind": "none"}
    if isinstance(cursor, str):
        return {"kind": "string", "value": cursor}
    return {"kind": "other"}


def native_external_archive_bind(
    params: Any,
    downloads: Sequence[Any],
    *,
    requires_binding: bool,
    guard_home: Path,
) -> Any | None:
    """``params`` (request params or a launch argv) bound to verified local archives.

    The resident re-verifies every download (single-link, read-only regular file
    with the recorded size and SHA-256) before binding. ``None`` means it refused
    (fail closed). Only the resident's edits are applied, so key order and number
    formatting of the forwarded request stay what the client sent.
    """

    payload = native_mcp_proxy_decide(
        {
            "check": "external_archive_bind",
            "params": params,
            "downloads": [
                {
                    "source_url": download.source_url,
                    "path": str(download.path),
                    "size": download.size,
                    "sha256": download.sha256,
                }
                for download in downloads
            ],
            "requires_binding": requires_binding,
        },
        guard_home=guard_home,
        required_feature=MCP_PROXY_ARCHIVE_VERIFY_FEATURE,
    )
    kind = payload.get("kind")
    if kind == "unchanged":
        return deepcopy(params)
    edits = payload.get("edits")
    if kind != "bound" or not isinstance(edits, list):
        return None
    bound = deepcopy(params)
    for edit in edits:
        slot: Any = bound
        *parents, last = edit["path"]
        for step in parents:
            slot = slot[step]
        slot[last] = edit["value"]
    return bound


def _evaluation_entries(evaluation: object, name: str) -> list[object]:
    """One list-valued field of an evaluation, as the resident reads it.

    Anything that is not a list or a tuple carries no entries, exactly as the
    callers that used to read these fields themselves treated it.
    """

    value = getattr(evaluation, name, ())
    return list(value) if isinstance(value, (list, tuple)) else []


def native_external_archive_binding_required(evaluation: object, *, guard_home: Path) -> bool:
    """Whether ``evaluation`` only permits a request bound to its verified archives.

    The evaluator owns what its own reasons mean, so the answer comes from the
    resident. An unreachable resident answers ``True``: demanding a binding the
    caller cannot produce blocks the install, which is the closed direction.
    """

    try:
        payload = native_mcp_proxy_decide(
            {
                "check": "external_archive_binding_required",
                "evaluation": {
                    name: _evaluation_entries(evaluation, name)
                    for name in ("external_archive_source_hashes", "reasons", "packages")
                },
            },
            guard_home=guard_home,
            required_feature=MCP_PROXY_ARCHIVE_BINDING_REQUIRED_FEATURE,
        )
    except (NativeMcpProxyDecisionError, TypeError, ValueError):
        return True
    required = payload.get("required")
    return required if isinstance(required, bool) else True


def native_package_reason_signals(reasons: Sequence[object], *, guard_home: Path) -> tuple[dict[str, Any], ...]:
    """The risk signals the resident projects from a package evaluation's reasons."""

    payload = native_mcp_proxy_decide(
        {"check": "package_reason_signals", "reasons": list(reasons)},
        guard_home=guard_home,
    )
    signals = payload.get("signals")
    if not isinstance(signals, list):
        raise _fail("native_mcp_proxy_decision_payload_invalid")
    return tuple(signals)


def native_package_answer(
    kind: str,
    *,
    tool_name: str,
    server_name: str,
    guard_home: Path,
    policy_action: str | None = None,
    package_request: bool = False,
    signals: Sequence[str] = (),
    evaluation: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """What a stopped package-lane call answers with, as the resident writes it.

    ``kind`` names the stop the precheck, compose or postclaim decided. A block
    answers with its message, payload, event label and receipt signals; a
    queued package request answers with its decision and the restatement its
    safe-alternative block carries. Anything else raises so the caller fails
    closed before it records a receipt.
    """

    query: dict[str, object] = {
        "check": "package_answer",
        "kind": kind,
        "tool_name": tool_name,
        "server_name": server_name,
        "package_request": package_request,
        "signals": list(signals),
    }
    if policy_action is not None:
        query["policy_action"] = policy_action
    if evaluation is not None:
        query["evaluation"] = dict(evaluation)
    payload = native_mcp_proxy_decide(
        query,
        guard_home=guard_home,
        required_feature=MCP_PROXY_PACKAGE_ANSWER_FEATURE,
    )
    if payload.get("kind") not in {"block", "queue"}:
        raise _fail("native_mcp_proxy_decision_payload_invalid")
    return payload


def native_inline_approval_reply(
    payload: object,
    *,
    tool_name: str,
    server_name: str,
    guard_home: Path,
) -> dict[str, Any]:
    """What the client's answer to one inline approval prompt means.

    The resident owns the classification and the block a refused or malformed
    answer produces, so the proxy reads neither a second time. It answers with
    the ``inline_approval`` fact the route consumes and, for a block, the
    decision source, event decision and reason that name it.
    """

    answer = native_mcp_proxy_decide(
        {
            "check": "inline_approval_reply",
            "payload": _inline_approval_payload(payload),
            "tool_name": tool_name,
            "server_name": server_name,
        },
        guard_home=guard_home,
        required_feature=MCP_PROXY_INLINE_APPROVAL_REPLY_FEATURE,
    )
    classified = answer.get("inline_approval")
    block = answer.get("block")
    if classified not in _INLINE_APPROVAL_KINDS or not _block_matches(classified, block):
        raise _fail("native_mcp_proxy_decision_payload_invalid")
    return {"inline_approval": classified, "block": block}


def _inline_approval_payload(result: object) -> Any:
    """The two fields the resident classifies an inline answer on.

    The client wrote the rest of the elicitation result, so forwarding it whole
    sends unbounded foreign data through the request digest: a ``_meta`` block
    or an integer wider than 64 bits round-trips differently on the resident's
    side and reads as a resident failure rather than the answer the user gave.
    Only ``action`` and ``content.decision`` decide anything, so only those are
    sent, each kept when it is the string the classifier reads and dropped
    otherwise -- which is the same answer the resident gave reading the field
    itself. A result that is not a mapping stays one the resident reads as
    invalid.
    """

    if not isinstance(result, Mapping):
        return None
    projected: dict[str, Any] = {}
    action = result.get("action")
    if isinstance(action, str):
        projected["action"] = action
    content = result.get("content")
    if isinstance(content, Mapping):
        decision = content.get("decision")
        projected["content"] = {"decision": decision} if isinstance(decision, str) else {}
    return projected


_INLINE_APPROVAL_KINDS = frozenset({"allow", "denied", "fallthrough"})


def _block_matches(classified: str, block: object) -> bool:
    """Whether the block agrees with the classification it arrived with.

    Only a denial carries a block, and a denial carries nothing else. Reading
    the two independently let an answer that classified as ``allow`` arrive
    beside a fully named denial block: the route would take the allow and drop
    the block. A classification and a block that disagree are no answer at all.
    """

    if classified != "denied":
        return block is None
    return isinstance(block, dict) and all(
        isinstance(block.get(field), str) for field in ("decision_source", "event_decision", "reason")
    )


def native_inline_approval_reply_available() -> bool:
    """Whether this resident classifies the answer to an inline prompt.

    An older resident rejects the query as an unknown check, which fails closed
    -- correct, but only after the prompt was raised and answered. A caller asks
    this before it prompts so an answer it cannot use is never collected.
    """

    status = native_runtime_status()
    capabilities = status.capabilities
    return bool(
        status.available
        and status.compatible
        and capabilities is not None
        and MCP_PROXY_INLINE_APPROVAL_REPLY_FEATURE in capabilities.features
    )
