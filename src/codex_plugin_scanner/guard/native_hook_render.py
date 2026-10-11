"""Resident bridge for the ``hook_render`` op.

Rust renders every harness hook response. The edge decision already returns the
response for the verdict Rust produced; this op renders a verdict the daemon
adjusted afterwards (a saved approval, a queued review, a policy repair). This
module only ships the adjusted verdict, binds the reply by ``request_id`` plus
``request_sha256`` and decodes it. A missing, malformed or mismatched reply
returns ``None``; nothing is ever rendered in Python.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

HOOK_RENDER_FEATURE = "hook-render-v2"
_REQUEST_SCHEMA = "guard-hook-render-request.v1"
_RESULT_SCHEMA = "guard-hook-render-result.v1"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 256 * 1024


def _render_payload(
    request: dict[str, object], guard_home: Path | None, deadline: float | None = None
) -> dict[str, object] | None:
    timeout = _TIMEOUT_SECONDS
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            return None
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        return None
    wire: dict[str, object] = {"schema": _REQUEST_SCHEMA, "request_id": f"hook-render-{uuid4().hex}", **request}
    try:
        response = _resident_request(
            operation="hook_render",
            request=wire,
            guard_home=home,
            timeout_seconds=timeout,
            required_feature=HOOK_RENDER_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        return None
    return _payload(response, wire, home)


def _render(
    request: dict[str, object], guard_home: Path | None, deadline: float | None = None
) -> dict[str, object] | None:
    payload = _render_payload(request, guard_home, deadline)
    rendered = payload.get("response") if payload is not None else None
    return dict(rendered) if isinstance(rendered, dict) else None


def native_render_cli(
    kind: str, harness: str, params: Mapping[str, object], *, guard_home: Path | None = None
) -> tuple[str, dict[str, object] | None] | None:
    """Render the in-process CLI hook outcome; ``None`` when the resident cannot answer.

    ``kind`` is ``cli_response`` or ``cli_document``. The result is the outcome
    (``document``, ``silent`` or ``fallback``) and the document for ``document``.
    """

    payload = _render_payload({"kind": kind, "harness": harness, "cli": dict(params)}, guard_home)
    outcome = payload.get("outcome") if payload is not None else None
    if payload is None or outcome not in {"document", "silent", "fallback"}:
        return None
    document = payload.get("response")
    return str(outcome), dict(document) if isinstance(document, dict) else None


def native_render_pre_tool(
    harness: str, verdict: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> dict[str, object] | None:
    """Render a PreToolUse verdict the daemon adjusted after the edge decision."""

    return _render({"kind": "pre_tool", "harness": harness, "verdict": dict(verdict)}, guard_home, deadline)


def native_render_pre_tool_review(
    harness: str,
    verdict: Mapping[str, object],
    *,
    approval: Mapping[str, object] | None,
    linked_reason: str | None,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Render a paused review; ``linked_reason`` already carries the signed approval link."""

    request: dict[str, object] = {"kind": "pre_tool_review", "harness": harness, "verdict": dict(verdict)}
    if approval is not None:
        # The renderer reads only the link and the request id; the stored row can be large.
        request["approval"] = {
            key: approval[key] for key in ("approval_url", "request_id") if isinstance(approval.get(key), str)
        }
    if linked_reason is not None:
        request["linked_reason"] = linked_reason
    return _render(request, guard_home, deadline)


def native_render_recording_only_pre_tool(
    harness: str, *, reason_code: str, reason: str, guard_home: Path | None = None, deadline: float | None = None
) -> dict[str, object] | None:
    """Render a Watch-posture PreToolUse that continues instead of pausing."""

    return _render(
        {"kind": "recording_only_pre_tool", "harness": harness, "reason_code": reason_code, "reason": reason},
        guard_home,
        deadline,
    )


__all__ = [
    "HOOK_RENDER_FEATURE",
    "native_render_cli",
    "native_render_pre_tool",
    "native_render_pre_tool_review",
    "native_render_recording_only_pre_tool",
]
