"""Resident bridge for the ``github_workflow_prepare`` op.

The Rust runtime owns GitHub workflow command understanding: it parses the hook
command, collects the live ``git``/``gh`` context, derives every digest and
returns the privacy-safe approval record, re-verifies a persisted command
against a record, and decides whether a persisted approval request, the Guard
operation it resolved and that operation's session are one unbroken workflow
lineage. This module only frames one request, binds the response by
``request_id`` plus ``request_sha256``, and decodes the result. Any transport
failure (resident unavailable, capability absent, timeout, overload, malformed
or mismatched result) yields ``None``/``False``; callers must treat that as "no
exactly bindable GitHub workflow operation" or "no lineage" and never recompute
one in Python. A resident too old to know ``lineage`` answers
``native_github_workflow_prepare_mode_invalid``, which is a transport failure
like any other, so the retry it would have authorized is refused.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from dataclasses import dataclass

from .native_resident_decision import BoundCall, ResidentCallError, bound_resident_call
from .runtime.github_workflow_approval_record import GitHubWorkflowApprovalRecord

_REQUEST_SCHEMA = "guard-github-workflow-prepare-request.v1"
_RESULT_SCHEMA = "guard-github-workflow-prepare-result.v1"
_REQUEST_IDS = itertools.count()
_DEFAULT_TIMEOUT_SECONDS = 9.0
_CALL = BoundCall(
    operation="github_workflow_prepare",
    feature="github-workflow-prepare-v1",
    prefix="native_github_workflow_prepare",
    result_schema=_RESULT_SCHEMA,
    max_request_bytes=1024 * 1024,
    timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
    check_circuit=True,
    transport_failure="unavailable",
)


@dataclass(frozen=True, slots=True)
class GitHubWorkflowLineage:
    """The identities a validated lineage yields; the store rows stay behind."""

    request_id: str
    operation_id: str
    session_id: str
    record: GitHubWorkflowApprovalRecord
    capability_id: str
    nonce: str


def github_workflow_validated_lineage(
    approval_request: Mapping[str, object],
    operation: Mapping[str, object],
    session: Mapping[str, object],
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> GitHubWorkflowLineage | None:
    """The validated workflow lineage for a persisted approval request, or ``None``.

    The three rows are read from the store by the caller because the resident
    does no store IO; every comparison between them is the resident's. ``None``
    means the lineage does not hold -- or could not be decided -- and the
    capability the caller was about to issue, claim or preflight must not exist.
    """
    envelope = _resident_envelope(
        {
            "mode": "lineage",
            "command_text": "",
            "approval_request": dict(approval_request),
            "operation": dict(operation),
            "session": dict(session),
        },
        timeout_seconds=timeout_seconds,
    )
    if envelope is None or envelope.get("code") != "ok":
        return None
    lineage = envelope.get("lineage")
    if not isinstance(lineage, dict):
        return None
    request_id = lineage.get("request_id")
    operation_id = lineage.get("operation_id")
    session_id = lineage.get("session_id")
    record_payload = lineage.get("record")
    capability_id = lineage.get("capability_id")
    nonce = lineage.get("nonce")
    if (
        not isinstance(request_id, str)
        or not request_id
        or not isinstance(operation_id, str)
        or not operation_id
        or not isinstance(session_id, str)
        or not session_id
        or not isinstance(record_payload, dict)
        or not isinstance(capability_id, str)
        or not capability_id
        or not isinstance(nonce, str)
        or not nonce
    ):
        return None
    try:
        record = GitHubWorkflowApprovalRecord.from_dict(record_payload)
    except (TypeError, ValueError):
        return None
    return GitHubWorkflowLineage(
        request_id=request_id,
        operation_id=operation_id,
        session_id=session_id,
        record=record,
        capability_id=capability_id,
        nonce=nonce,
    )


def _resident_envelope(fields: dict[str, object], *, timeout_seconds: float) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"ghwf-{next(_REQUEST_IDS)}",
        **fields,
    }
    try:
        reply = bound_resident_call(_CALL, request, timeout_seconds=timeout_seconds)
    except ResidentCallError:
        return None
    if reply.envelope.get("status") != "ok":
        reply.fail()
        return None
    reply.healthy()
    return reply.envelope
