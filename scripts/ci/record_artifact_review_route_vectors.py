#!/usr/bin/env python3
"""Record artifact-hook review route vectors from the Python branch ladder.

Once the artifact hook settled its verdict, ``review_native_artifact_hook``
walked a ladder in Python to decide where a review-tier or terminal action
went: stored as a silent denial, observed, answered by Copilot or Claude
natively, or queued for approval, with the terminal copy, the Claude notice and
Cursor's request ids along the way. The resident decides all of that now
(``artifact_review_route`` in ``hook_decision_artifact_review_route.rs``).

The ladder below (``_recorded_review``) is that Python code as it stood at
4c96a78f2c, kept here so the oracle never calls the code it checks. Every
effect is a stub that appends a tagged entry to a trace, so a vector records
exactly which effects the old ladder ran, in order:

    PYTHONPATH=src .venv/bin/python scripts/ci/record_artifact_review_route_vectors.py

Each vector holds the resident's inputs (``facts``), the route fields the
recorded trace exhibits (``route``), the trace itself and the return code.
The Rust ``hook_decision_artifact_review_route_tests`` replays the route
fields; ``tests/test_artifact_review_route_parity.py`` runs the new executor
with the same stubs and checks that it runs the same effects.

One deliberate difference from the old ladder: it composed the native reason
before every branch, though only the Claude notice and the native response read
it. The oracle composes it where it is read, so the trace records the reason
only where it was used.
"""

from __future__ import annotations

import gzip
import itertools
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard.cli.commands_support_prompts import (
    _claude_prompt_additional_context,
    _claude_prompt_system_message,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import _canonical_harness_name

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/artifact_review_route_vectors.json.gz")

HARNESSES = ("codex", "claude-code", "claude", "copilot", "cursor", "grok", "pi", "unknown-harness")
EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "Stop")
ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
ARTIFACT_TYPES = ("tool_action_request", "prompt_request", "mcp_server")
_REVIEW_TIER = frozenset({"review", "require-reapproval"})
_LADDER_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})

REASON = "REASON"
RISK = "RISK summary"
SILENT_LEAD = "HOL Guard blocked this action."
_CLAUDE_SECRET = "HOL Guard intercepted this prompt because it asks Claude to access local secrets."
_CLAUDE_SENSITIVE = "HOL Guard intercepted this prompt because it leads to a sensitive action."


@dataclass(frozen=True)
class Case:
    """One enumerated fact combination."""

    harness: str
    event: str
    action: str
    artifact_type: str
    observe_mode: bool
    asks_for_approval: bool
    json: bool
    output_stream: bool
    prompt_hard_block: bool = False
    prompt_secret_read: bool = False

    @property
    def canonical(self) -> str:
        return _canonical_harness_name(self.harness)

    def facts(self) -> dict[str, object]:
        """The resident's ``ArtifactReviewRouteInputsV1`` for this case."""

        return {
            "harness": self.harness,
            "canonical_harness": self.canonical,
            "event": self.event,
            "policy_action": self.action,
            "artifact_type": self.artifact_type,
            "observe_mode": self.observe_mode,
            "asks_for_approval": self.asks_for_approval,
            "json": self.json,
            "output_stream_present": self.output_stream,
            "prompt_hard_block": self.prompt_hard_block,
            "prompt_secret_read": self.prompt_secret_read,
        }

    def artifact(self) -> SimpleNamespace:
        classes = []
        if self.prompt_hard_block:
            classes.append("guard_bypass_intent")
        if self.prompt_secret_read:
            classes.append("secret_read")
        metadata: dict[str, object] = {"prompt_request_classes": classes} if classes else {}
        return SimpleNamespace(artifact_type=self.artifact_type, metadata=metadata)


# --- The retired ladder -------------------------------------------------------


def _recorded_cursor_hook_requires_approval_center_queue(policy_action: str) -> bool:
    return policy_action in {"require-reapproval", "review"}


def _recorded_should_emit_copilot_hook_response(case: Case) -> bool:
    return case.harness == "copilot" and not case.json


def _recorded_should_emit_prequeue_native_hook_response(case: Case) -> bool:
    if case.canonical != "claude-code":
        return False
    if not case.json:
        return True
    if case.event == "UserPromptSubmit":
        return False
    return case.output_stream


def _recorded_should_emit_claude_native_pretooluse_notice(case: Case) -> bool:
    return case.canonical == "claude-code" and case.event == "PreToolUse" and case.action in _REVIEW_TIER


def additional_context_kind(text: object) -> str:
    if text is None:
        return "none"
    return "claude_prompt_secret" if "access local secrets" in str(text) else "claude_prompt_sensitive"


def system_message_kind(message: object) -> str:
    if message is None:
        return "none"
    text = str(message)
    if text.startswith(_CLAUDE_SECRET):
        return "claude_prompt_secret"
    if text.startswith(_CLAUDE_SENSITIVE):
        return "claude_prompt_sensitive"
    if text == f"{REASON}.":
        return "claude_punctuated"
    raise ValueError(f"unrecognized system message: {text!r}")


def _recorded_review(case: Case) -> tuple[list[list[object]], int | None]:
    """``review_native_artifact_hook`` as it stood, with every effect traced."""

    trace: list[list[object]] = []
    policy_action = case.action
    canonical = case.canonical
    cursor_native_queue = canonical == "cursor" and _recorded_cursor_hook_requires_approval_center_queue(policy_action)
    if (
        not case.observe_mode
        and not case.asks_for_approval
        and (policy_action in {"review", "require-reapproval", "block"} or cursor_native_queue)
    ):
        trace.append(["unprompted", policy_action in _REVIEW_TIER, policy_action, SILENT_LEAD])
        return trace, None
    terminal_action = policy_action in {"block", "sandbox-required"}
    if terminal_action:
        trace.append(["terminalize", "observe" if case.observe_mode else "enforce"])
    if policy_action in _LADDER_ACTIONS or cursor_native_queue:
        if case.observe_mode:
            trace.append(["observe"])
            return trace, None
        if canonical == "claude-code" and case.event == "PreToolUse" and policy_action in _REVIEW_TIER:
            trace.append(["claude_notice_record", REASON])
        if _recorded_should_emit_copilot_hook_response(case):
            trace.append(["receipt"])
            trace.append(["usage", policy_action])
            trace.append(["copilot_response", policy_action])
            return trace, 0
        if _recorded_should_emit_prequeue_native_hook_response(case):
            if _recorded_should_emit_claude_native_pretooluse_notice(case):
                trace.append(["claude_notice_stderr", REASON])
            system_message = None
            if canonical == "claude-code":
                system_message = _claude_prompt_system_message(
                    event_name=case.event,
                    policy_action=policy_action,
                    artifact=case.artifact(),  # type: ignore[arg-type]
                    native_reason=lambda: REASON,
                )
            additional_context = _claude_prompt_additional_context(
                harness=case.harness,
                event_name=case.event,
                policy_action=policy_action,
                artifact=case.artifact(),  # type: ignore[arg-type]
                native_reason=REASON,
            )
            trace.append(
                [
                    "native_response",
                    policy_action,
                    case.event,
                    REASON,
                    system_message_kind(system_message),
                    additional_context_kind(additional_context),
                ]
            )
            trace.append(["receipt"])
            trace.append(["usage", policy_action])
            return trace, 0
        # The ladder also skipped a block whose saved decision was a block; a
        # block is terminal, so that clause never decided anything.
        should_queue_approval_center = not terminal_action
        if not case.prompt_hard_block and should_queue_approval_center:
            attach = (
                canonical == "cursor"
                and case.event == "PreToolUse"
                and case.artifact_type == "tool_action_request"
                and _recorded_cursor_hook_requires_approval_center_queue(policy_action)
            )
            trace.append(["queue_approval", attach])
    return trace, None


# --- Vectors ------------------------------------------------------------------


def cases() -> Iterator[Case]:
    """Every fact combination the ladder can observe.

    The prompt classes are read out of the artifact, so they vary wherever the
    artifact is a prompt request and nowhere else.
    """

    for harness, event, action, artifact_type, observe, asks, as_json, stream in itertools.product(
        HARNESSES, EVENTS, ACTIONS, ARTIFACT_TYPES, (False, True), (False, True), (False, True), (False, True)
    ):
        prompts = (
            itertools.product((False, True), (False, True)) if artifact_type == "prompt_request" else [(False, False)]
        )
        for hard, secret in prompts:
            yield Case(
                harness=harness,
                event=event,
                action=action,
                artifact_type=artifact_type,
                observe_mode=observe,
                asks_for_approval=asks,
                json=as_json,
                output_stream=stream,
                prompt_hard_block=hard,
                prompt_secret_read=secret,
            )


def observed_route(trace: list[list[object]]) -> dict[str, Any]:
    """The route fields the recorded trace exhibits."""

    route: dict[str, Any] = {
        "route": "continue",
        "terminalize": "none",
        "record_claude_notice": False,
        "attach_cursor_request_ids": False,
        "system_message": "none",
        "additional_context": "none",
        "silent_review": None,
    }
    for entry in trace:
        kind = entry[0]
        if kind == "unprompted":
            route["route"] = "silent_review" if entry[1] else "silent_block"
            route["silent_review"] = {"action": entry[2], "reason": entry[3]}
        elif kind == "terminalize":
            route["terminalize"] = entry[1]
        elif kind == "observe":
            route["route"] = "observe"
        elif kind == "claude_notice_record":
            route["record_claude_notice"] = True
        elif kind == "copilot_response":
            route["route"] = "copilot_response"
        elif kind == "native_response":
            route.update(route="native_response", system_message=entry[4], additional_context=entry[5])
        elif kind == "queue_approval":
            route.update(route="queue_approval", attach_cursor_request_ids=entry[1])
    return route


def record(
    case: Case, run: Callable[[Case], tuple[list[list[object]], int | None]] = _recorded_review
) -> dict[str, Any]:
    trace, rc = run(case)
    return {"facts": case.facts(), "route": observed_route(trace), "trace": trace, "rc": rc}


def main() -> int:
    vectors = [record(case) for case in cases()]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(f"wrote {len(vectors)} vectors to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
