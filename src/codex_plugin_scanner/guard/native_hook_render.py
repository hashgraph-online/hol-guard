"""Resident bridge for the ``hook_render`` op.

Rust renders every harness hook response. The edge decision already returns the
response for the verdict Rust produced; this op renders a verdict the daemon
adjusted afterwards (a saved approval, a queued review, a policy repair). This
module only ships the adjusted verdict, binds the reply by ``request_id`` plus
``request_sha256`` and decodes it. A missing, malformed or mismatched reply
returns ``None``; nothing is ever rendered in Python.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from contextlib import suppress
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
# ``cli_hook_emit`` carries a whole daemon answer as escaped JSON text and
# ``cursor_shell_route`` carries the edge result the daemon already produced;
# the resident gives both kinds the larger budget (``hook_render_max_bytes``).
_CLI_HOOK_EMIT_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_CURSOR_ROUTE_MAX_REQUEST_BYTES = 4 * 1024 * 1024
# The bridge kinds carry the whole daemon reply they render, which may be as
# large as a native response, so they ask for the same larger budget.
_DAEMON_REPLY_MAX_REQUEST_BYTES = 4 * 1024 * 1024


def _render_payload(
    request: dict[str, object],
    guard_home: Path | None,
    deadline: float | None = None,
    *,
    max_request_bytes: int = _MAX_REQUEST_BYTES,
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
            max_request_bytes=max_request_bytes,
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
    kind: str,
    harness: str,
    params: Mapping[str, object],
    *,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> tuple[str, dict[str, object] | None] | None:
    """Render the in-process CLI hook outcome; ``None`` when the resident cannot answer.

    ``kind`` is ``cli_response`` or ``cli_document``. The result is the outcome
    (``document``, ``silent`` or ``fallback``) and the document for ``document``.
    """

    wire: dict[str, object] = {"kind": kind, "harness": harness, "cli": dict(params)}
    # Each kind names its own bound here rather than reading one out of a
    # table, so the scan that compares every bound against the transport's
    # ceiling can still read what this call offers.
    if kind == "cli_hook_emit":
        payload = _render_payload(wire, guard_home, deadline, max_request_bytes=_CLI_HOOK_EMIT_MAX_REQUEST_BYTES)
    elif kind == "cursor_shell_route":
        payload = _render_payload(wire, guard_home, deadline, max_request_bytes=_CURSOR_ROUTE_MAX_REQUEST_BYTES)
    elif kind in {"hermes_bridge", "muse_bridge"}:
        payload = _render_payload(wire, guard_home, deadline, max_request_bytes=_DAEMON_REPLY_MAX_REQUEST_BYTES)
    else:
        payload = _render_payload(wire, guard_home, deadline, max_request_bytes=_MAX_REQUEST_BYTES)
    outcome = payload.get("outcome") if payload is not None else None
    if payload is None or outcome not in {"document", "silent", "fallback"}:
        return None
    document = payload.get("response")
    return str(outcome), dict(document) if isinstance(document, dict) else None


def native_hermes_bridge(
    response: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> tuple[dict[str, object], int] | None:
    """Read a Hermes daemon reply into its stdout document and exit status.

    ``None`` when the resident cannot answer; the caller fails closed rather
    than deciding here what the reply meant. ``deadline`` is the hook's
    absolute ``time.monotonic()`` budget; the render gets only what remains.
    """

    rendered = native_render_cli(
        "hermes_bridge", "hermes", {"response": dict(response)}, guard_home=guard_home, deadline=deadline
    )
    if rendered is None or rendered[1] is None:
        return None
    document = rendered[1].get("document")
    exit_code = rendered[1].get("exit_code")
    if not isinstance(document, dict) or not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return None
    return dict(document), exit_code


def native_muse_bridge(
    response: Mapping[str, object],
    *,
    event_name: str,
    guard_home: Path | None = None,
    deadline: float | None = None,
) -> tuple[dict[str, object] | None, int] | None:
    """Read a Muse daemon reply into its stdout document and exit status.

    The document is ``None`` where Muse expects empty stdout, which is how it
    reads a permitted call. ``None`` for the whole result means the resident
    could not answer, and the caller fails closed rather than deciding here
    what the reply meant. ``deadline`` is the hook's absolute
    ``time.monotonic()`` budget; the render gets only what remains.
    """

    rendered = native_render_cli(
        "muse_bridge",
        "muse",
        {"response": dict(response), "event_name": str(event_name)},
        guard_home=guard_home,
        deadline=deadline,
    )
    if rendered is None or rendered[1] is None:
        return None
    document = rendered[1].get("document")
    exit_code = rendered[1].get("exit_code")
    if document is not None and not isinstance(document, dict):
        return None
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return None
    return (dict(document) if document is not None else None), exit_code


def native_cli_hook_emit(
    harness: str,
    response: Mapping[str, object],
    *,
    event_name: str,
    guard_home: Path | None = None,
    deadline: float | None = None,
    bridge: bool = False,
    document: bool = False,
) -> dict[str, object] | None:
    """Read a daemon answer the way ``hol-guard hook`` prints it.

    ``harness`` is canonical. A bridge-rendered harness gets ``stdout``,
    ``stderr`` and ``exit_code``; any other gets the ``policy_action`` its
    exit status follows. ``bridge`` asks for the bounded bridge's output for
    every harness, which is what that bridge prints. ``document`` also asks
    a harness outside the bridges for the redacted document it prints, as
    ``stdout``, and the ``exit_code`` it exits with; the resident shortens
    this process's home directory in it. A resident that predates
    ``document`` answers without ``stdout``. ``None`` when the resident
    cannot answer, so the caller fails closed rather than reading the answer here. The answer
    travels as compact JSON so the resident reads the exact text Python would
    have printed, lone surrogates included. ``deadline`` is the hook's
    absolute ``time.monotonic()`` budget; the render gets only what remains.
    """

    try:
        response_json = json.dumps(dict(response), ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    params: dict[str, object] = {"event_name": event_name, "response_json": response_json}
    if guard_home is not None:
        # The store this command reads. An authority block's recovery line
        # names it, so a person pasting the command repairs this install and
        # not whichever one the bare command would find.
        params["guard_home"] = str(guard_home)
    if bridge:
        params["bridge"] = True
    if document:
        params["document"] = True
        with suppress(RuntimeError):
            params["home_dir"] = str(Path.home())
    rendered = native_render_cli("cli_hook_emit", harness, params, guard_home=guard_home, deadline=deadline)
    return rendered[1] if rendered is not None else None


def native_evaluation_has_terminal_policy_action(
    harness: str,
    evaluation: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> bool | None:
    """Whether an approval could still change this evaluation; ``None`` when unavailable.

    A ``block`` or ``sandbox-required`` policy action is terminal: no answer a
    user gives can lift it, so the caller does not open an approval flow for
    it. Ranking those actions is the resident's own verdict about the
    evaluation it produced, so Python asks rather than re-reads it.
    """

    params: dict[str, object] = {"evaluation": {"artifacts": evaluation.get("artifacts")}}
    rendered = native_render_cli("terminal_policy_action", harness, params, guard_home=guard_home)
    if rendered is None or rendered[1] is None:
        return None
    value = rendered[1].get("value")
    return value if isinstance(value, bool) else None


# The payload fields the observer-event rule reads to name an attested event.


def native_render_pre_tool(
    harness: str, verdict: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> dict[str, object] | None:
    """Render a PreToolUse verdict the daemon adjusted after the edge decision."""

    return _render({"kind": "pre_tool", "harness": harness, "verdict": dict(verdict)}, guard_home, deadline)


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
    "native_cli_hook_emit",
    "native_evaluation_has_terminal_policy_action",
    "native_render_cli",
    "native_render_pre_tool",
    "native_render_recording_only_pre_tool",
]
