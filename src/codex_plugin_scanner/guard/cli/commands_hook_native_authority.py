"""Answer a ``hol-guard hook`` call through the daemon's native review path."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, TextIO

from ..harness_context import HarnessContext
from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY, collect_hook_execution_environment
from ..hook_failure_bridge import RUNTIME_MISSING, native_hook_failure, native_stderr_hook_failure
from ..hook_review.hook_availability_policy import (
    availability_harness_response,
    canonical_hook_event_name,
    hook_event_pauses_when_unavailable,
)
from ..hook_review.hook_fail_closed import fail_closed_response
from ..hook_review.hook_worker import HookWorker
from ..hook_review.hook_worker_unavailable import withhold_structured_destination, withholds_structured_destination
from ..native_hook_render import native_cli_hook_emit
from ..native_payload_facts import native_cli_hook_admission
from ..resident_evidence_client import ResidentEvidenceClient
from ..runtime_health.diagnostics import DaemonDiagnostics
from ..store import GuardStore
from .commands_support_runtime_resolution import _canonical_harness_name
from .native_hook_exit_code import native_hook_verdict_exit_code

_DIAGNOSTIC_DRAIN_TIMEOUT_SECONDS = 0.25

# Harnesses whose bounded hook bridge prints this command's output to the
# harness as is. Their daemon route renders the review into the harness's own
# wire format, so the CLI renders it the same way.
_BRIDGE_RENDERED_HARNESSES = frozenset(
    {"cline", "copilot", "devin", "grok", "hermes", "kimi", "muse", "openclaw", "zcode"}
)
_RENDER_FAILURE_REASON = "HOL Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
_BRIDGE_BLOCK_REASON = "HOL Guard blocked this action."
# What writing a finished answer is allowed to take when the review itself has
# already used the hook's whole budget.
_DELIVERY_BUDGET_SECONDS = 1.0


def _delivery_deadline(deadline: float | None) -> float | None:
    """The budget the resident gets for writing an answer Guard already gave.

    ``deadline`` bounds the review, and the review is over by the time this
    runs. A review that used all of it would leave the renderer nothing, and
    the decided verdict - an allow as readily as a block - would be thrown
    away for a fail-closed document. Writing the answer therefore keeps a
    small floor of its own; a deadline with more than that left is unchanged.
    """

    if deadline is None:
        return None
    return max(deadline, time.monotonic() + _DELIVERY_BUDGET_SECONDS)


def _failure_output(harness: str, event_name: str, reason: str) -> tuple[str, str, int]:
    """The runtime's fixed fail-closed answer, or a block that names the repair."""

    failure = native_hook_failure(harness, event_name, reason)
    if failure is None:
        return "", RUNTIME_MISSING, 2
    return failure[0], "", failure[1]


def _bridge_hook_output(
    canonical: str,
    response: dict[str, Any],
    *,
    event_name: str,
    guard_home: Path | None,
    deadline: float | None,
) -> tuple[str, str, int]:
    """The stdout, stderr and exit status a bridge-rendered harness reads.

    The resident reshapes the daemon's answer into the harness's wire format.
    When it cannot, the harness gets the fixed fail-closed payload its bridge
    writes for an outage; nothing reads the answer in Python.
    """

    rendered = native_cli_hook_emit(
        canonical, response, event_name=event_name, guard_home=guard_home, deadline=deadline
    )
    if rendered is not None:
        stdout, stderr, exit_code = rendered.get("stdout"), rendered.get("stderr"), rendered.get("exit_code")
        if (
            isinstance(stdout, str)
            and isinstance(stderr, str)
            and isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
        ):
            return stdout, stderr, exit_code
    if canonical == "muse":
        return native_stderr_hook_failure(canonical, event_name, _BRIDGE_BLOCK_REASON)
    if canonical == "hermes":
        return _failure_output(canonical, event_name, _BRIDGE_BLOCK_REASON)
    return _failure_output(canonical, event_name, _RENDER_FAILURE_REASON)


def _record_native_hook_exception(guard_home: Path, *, harness: str, event_name: str) -> None:
    """Write the swallowed hook exception to Guard's own log.

    The fail-closed response deliberately carries no detail: it travels the
    harness wire and would leak local paths. Without this the operator sees a
    deny with no stderr, no reason beyond the generic message, and nothing in
    any log to explain it. Diagnostics never change the returned verdict, so
    every failure here is suppressed. Call this from inside the ``except``
    block, where ``sys.exc_info()`` still holds the exception.
    """

    with suppress(Exception):
        diagnostics = DaemonDiagnostics(guard_home)
        try:
            diagnostics.record_exception(
                "native_hook_worker_exception",
                detail=f"harness={harness} event={event_name}",
            )
        finally:
            diagnostics.close(timeout_seconds=_DIAGNOSTIC_DRAIN_TIMEOUT_SECONDS)


def _unavailable_cli_response(
    harness: str, event_name: str, reason_code: str, *, worker_available: bool = False
) -> dict[str, object]:
    response = availability_harness_response(
        harness=harness,
        event_name=event_name,
        reason_code=reason_code,
        reason="HOL Guard could not complete the native hook decision safely.",
    )
    # Without a worker the managed destination cannot be resolved.
    if not worker_available and withholds_structured_destination(harness=harness, event_name=event_name):
        return withhold_structured_destination(response)
    return response


def try_native_hook_authority(
    *,
    payload: dict[str, object],
    harness: str,
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    store: GuardStore,
    deadline: float | None = None,
    event_name: str | None = None,
) -> dict[str, Any]:
    """Review one hook with the same fail-closed worker the daemon uses.

    Any failure answers with the harness's fail-safe availability response.
    """
    worker: HookWorker | None = None
    try:
        # Short-lived CLI hooks publish and await the resident-ACKed policy
        # snapshot themselves; with no Python fallback, a missing snapshot must
        # not silently downgrade a hook to a fail-safe allow.
        worker = HookWorker(
            store=store,
            activity_writer=ResidentEvidenceClient(store=store),
        )
        return worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
            event_name=event_name,
        )
    except Exception as error:
        _record_native_hook_exception(
            guard_home,
            harness=harness,
            event_name=event_name or canonical_hook_event_name(payload, guard_home=guard_home, deadline=deadline),
        )
        _log_worker_exception(error, harness=harness)
        event_name = event_name or canonical_hook_event_name(payload, guard_home=guard_home, deadline=deadline)
        response = _unavailable_cli_response(
            harness, event_name, "native_hook_worker_exception", worker_available=worker is not None
        )
        if worker is None:
            return response
        # The worker withholds a managed structured destination on its own
        # unavailable answers; an answer it never returned stays withheld too.
        return worker._apply_structured_unavailable_overlay(
            response,
            harness=harness,
            event_name=event_name,
            guard_home=guard_home,
            workspace=workspace,
        )
    finally:
        if worker is not None:
            close = getattr(worker, "close", None)
            if callable(close):
                close()
        # The writer belongs to the resident, not to this process, so a
        # one-shot hook never stops it: the records it handed over are
        # persisted after this process exits, and stopping the writer here
        # would drain and drop one the next hook would have to rebuild.


def _log_worker_exception(error: BaseException, *, harness: str) -> None:
    """Point the operator at the Guard log before denying.

    The harness wire document is a fixed deny that deliberately carries no
    detail. The full exception and traceback go to Guard's own log through
    ``_record_native_hook_exception``; this line only names the failure class
    so the operator knows where to look. Hook stderr can reach the harness, so
    no exception message, traceback, path or payload-derived value is logged
    here, and a failing log handler never changes the returned verdict.
    """

    with suppress(Exception):
        logging.getLogger(__name__).warning(
            "HOL Guard native hook authority failed for %s (%s); details are in the Guard daemon log",
            harness,
            type(error).__name__,
        )


def _payload_workspace(payload: dict[str, object]) -> Path | None:
    """The workspace the hook named, as spelled; the native edge settles it."""

    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd.strip() and Path(cwd).is_absolute():
        return Path(cwd)
    return None


def emit_hook_review(
    harness: str,
    response: dict[str, Any],
    *,
    event_name: str,
    guard_home: Path | None = None,
    output_stream: TextIO | None = None,
    deadline: float | None = None,
) -> int:
    """Write a reviewed hook's answer and return the harness's exit code.

    ``deadline`` is the hook's absolute ``time.monotonic()`` budget; reading
    the answer in the resident gets only what the review left.
    """

    canonical = _canonical_harness_name(harness)
    deadline = _delivery_deadline(deadline)
    if canonical in _BRIDGE_RENDERED_HARNESSES:
        stdout, stderr, exit_code = _bridge_hook_output(
            canonical, response, event_name=event_name, guard_home=guard_home, deadline=deadline
        )
        stream = output_stream or sys.stdout
        if stdout:
            _ = stream.write(stdout + "\n")
        if stderr:
            # The verdict is already on stdout; a closed stderr must not turn
            # the supplementary reason into a second, failing answer.
            with suppress(OSError, ValueError):
                print(stderr, file=sys.stderr)
        return exit_code
    if not response and not hook_event_pauses_when_unavailable(event_name, guard_home=guard_home, deadline=deadline):
        # An empty answer to an event that cannot pause the turn carries no
        # decision; writing nothing lets the harness continue on its own.
        return 0
    # Every other caller reads the daemon's response document; a hook caller
    # need not pass --json to receive a parseable one. The resident prints it
    # with secrets masked and the signed approval link the user is meant to
    # open intact, and names the status the harness reads with it.
    rendered = native_cli_hook_emit(
        canonical, response, event_name=event_name, guard_home=guard_home, deadline=deadline, document=True
    )
    stdout = rendered.get("stdout") if rendered is not None else None
    exit_code = rendered.get("exit_code") if rendered is not None else None
    stream = output_stream or sys.stdout
    if isinstance(stdout, str) and isinstance(exit_code, int) and not isinstance(exit_code, bool):
        # stdout is the harness delivery channel; the ephemeral approval
        # link must reach the operator intact.
        _ = stream.write(stdout + "\n")  # codeql[py/clear-text-logging-sensitive-data]
        return exit_code
    # Without the resident nothing reads the answer here: the harness gets the
    # fixed fail-closed document, and the exit status follows the outage
    # policy the bridges' fixed payload uses: block an event that may pause
    # the turn, and let any other continue.
    fallback = fail_closed_response(canonical, event_name)
    _ = stream.write(json.dumps(fallback, ensure_ascii=True, separators=(",", ":")) + "\n")
    if canonical == "claude-code":
        # Claude reads a hook's JSON only on exit 0; any other status discards
        # the document, a PostToolUse block and its reason included.
        return 0
    policy_action = (
        "block" if hook_event_pauses_when_unavailable(event_name, guard_home=guard_home, deadline=deadline) else "allow"
    )
    return native_hook_verdict_exit_code(canonical, policy_action, event_name=event_name)


def route_native_hook(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    payload: dict[str, object],
    runtime_workspace: Path | None,
    store: GuardStore,
    output_stream: TextIO | None = None,
) -> int:
    """Review a hook through the daemon's review path and emit its result.

    Every hook result is native or fail-safe; there is no Python semantic
    fallback, and the answer is the one the daemon gives the same request.
    """

    deadline: float | None = None
    event_name: str | None = None
    try:
        event_name, deadline = native_cli_hook_admission(payload, started_at=time.monotonic())
        response = None
        if time.monotonic() < deadline:
            payload = dict(payload)
            # Capture the caller's context from the shell the command would run in.
            if HOOK_EXECUTION_ENVIRONMENT_KEY not in payload:
                payload[HOOK_EXECUTION_ENVIRONMENT_KEY] = collect_hook_execution_environment()
            response = try_native_hook_authority(
                payload=payload,
                harness=args.harness,
                home_dir=context.home_dir,
                guard_home=context.guard_home,
                workspace=runtime_workspace or _payload_workspace(payload),
                store=store,
                deadline=deadline,
                event_name=event_name,
            )
        if not isinstance(response, dict):
            event_name = event_name or canonical_hook_event_name(
                payload, guard_home=context.guard_home, deadline=deadline
            )
            response = _unavailable_cli_response(args.harness, event_name, "native_hook_worker_unavailable")
        event_name = event_name or canonical_hook_event_name(payload, guard_home=context.guard_home, deadline=deadline)
        return emit_hook_review(
            args.harness,
            response,
            event_name=event_name,
            guard_home=context.guard_home,
            output_stream=output_stream,
            deadline=deadline,
        )
    except Exception as error:
        event_name = event_name or canonical_hook_event_name(payload, guard_home=context.guard_home, deadline=deadline)
        _record_native_hook_exception(context.guard_home, harness=args.harness, event_name=event_name)
        _log_worker_exception(error, harness=args.harness)
        response = _unavailable_cli_response(args.harness, event_name, "native_hook_worker_exception")
        return emit_hook_review(
            args.harness,
            response,
            event_name=event_name,
            guard_home=context.guard_home,
            output_stream=output_stream,
            deadline=deadline,
        )
