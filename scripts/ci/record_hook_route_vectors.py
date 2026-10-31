#!/usr/bin/env python3
"""Record hook pipeline route vectors from the Python dispatch ladder.

After the hook payload was prepared, ``run_native_hook_pipeline`` walked a
ladder in Python to decide which handler answered the hook and in what order:
the Claude guard question, the native edge decision, the edge outage, the
containment route, Copilot's pre-tool and permission request flows, the
runtime artifact, the Claude permission request, permission prompt and turn
stop handlers, then the artifact or generic flow. Devin and Zcode permission
requests were answered with no decision before any of it. The resident decides
that order now (``hook_route`` in ``hook_decision_hook_route.rs``) and returns
it as a plan of handler names.

The ladder below (``_recorded_ladder``) is that Python code as it stood at
3b8ac2e848, kept here so the oracle never calls the code it checks. Every
effect is a stub that appends a tagged entry to a trace, so a vector records
exactly which effects the old ladder ran, in order, in each of a set of
effect worlds (what the stubbed effects report):

    PYTHONPATH=src .venv/bin/python scripts/ci/record_hook_route_vectors.py

A vector holds the resident's inputs (``facts``), the route the traces exhibit
(the plan and the event name outage responses carry) and, per world, the trace
and return code. The Rust ``hook_decision_hook_route_tests`` replays the route.
The plan is read off the traces: the base world (no optional handler fires)
shows every handler reached before a terminal one answered, and the
``edge_missing`` world shows whether the edge outage check applied.

Two deliberate differences from the old ladder: the passthrough fact is
decided after the payload is prepared (it was decided before the config load),
and the Claude predicates and the Copilot pre-tool guard each handler used to
apply to itself are plan membership now, so the stubs do not model them.
"""

from __future__ import annotations

import gzip
import itertools
import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_event_name, _optional_string
from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import (
    _canonical_harness_name,
    _is_copilot_permission_request,
)
from codex_plugin_scanner.guard.daemon.hook_request_parsing import runtime_hook_event_name
from codex_plugin_scanner.guard.native_hook_artifact_facts import HookArtifactFactsUnavailableError
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/hook_route_vectors.json.gz")

HARNESSES = ("codex", "claude-code", "claude", "copilot", "cursor", "devin", "zcode", "grok", "unknown-harness")
_EDGE_EVENTS = frozenset({"PreToolUse", "PostToolUse", "UserPromptSubmit"})
_PASSTHROUGH_HARNESSES = frozenset({"devin", "zcode"})
SESSION = "session-1"
_PERMISSION_PROMPT = {"hook_event_name": "Notification", "notification_type": "permission_prompt"}

# Payload shapes as the harnesses send them: every key the event-name helpers read.
PAYLOADS: tuple[dict[str, object], ...] = (
    {},
    {"hook_event_name": "PreToolUse"},
    {"hook_event_name": "pretooluse"},
    {"hook_name": "preToolUse"},
    {"event": "PostToolUse"},
    {"hookEventName": "PostToolUse"},
    {"hook_event_name": "UserPromptSubmit"},
    {"hook_event_name": "UserPromptSubmitted"},
    {"hook_event_name": "PermissionRequest"},
    {"hook_event_name": "PermissionRequestV2"},
    {"hook_name": "permission_request"},
    {"eventName": "PermissionRequest"},
    {"hook_event_name": "copilotPermissionRequest"},
    {"hook_event_name": "Stop"},
    {"hook_event_name": "Stop", "notification_type": "permission_prompt"},
    _PERMISSION_PROMPT,
    {"hook_event_name": "Notification", "notification_type": "idle_prompt"},
    {"hook_event_name": "Notification"},
    {"hook_event_name": "SessionStart"},
    {"hook_event_name": "beforeShellExecution"},
    {"hookName": "afterShellExecution"},
)
# Harnesses whose preparation rewrites the event name: (as invoked, as prepared).
REWRITTEN: tuple[tuple[dict[str, object], dict[str, object]], ...] = (
    ({"hookEventName": "preToolUse"}, {"hook_event_name": "PreToolUse"}),
    ({"eventName": "PermissionRequest"}, {"hook_event_name": "PermissionRequest"}),
    ({"hook_event_name": "PermissionRequest"}, {"hook_event_name": "PreToolUse"}),
    ({"hook_event_name": "PreToolUse"}, {"hook_event_name": "PermissionRequest"}),
)
COPILOT_STAGES = ("", "pretooluse", "permissionrequest", "posttooluse")

RC = {
    "unavailable": 11,
    "containment": 12,
    "copilot_pretool": 13,
    "copilot_permission_request": 14,
    "claude_permission_request": 15,
    "claude_permission_prompt": 16,
    "artifact_flow": 17,
    "generic_flow": 18,
}
PENDING = ("pending-key", {"pending": True})
EDGES: dict[str, object] = {
    "ok": {"result": {"edge": "result"}, "receipt": {"edge": "receipt"}, "recording_only": True},
    "missing": {"failure_reason_code": "edge_down", "recording_only": True},
    "none": None,
}


@dataclass(frozen=True)
class World:
    """What the stubbed effects report."""

    name: str
    pending: str = "none"  # the Claude pending permission: none | plain | question
    edge: str = "ok"
    contained: bool = False
    copilot_resolves: bool = False
    fresh_calls: bool = False  # the Copilot handlers call the fresh authority provider
    artifact: bool = False
    revalidate: bool = False  # the generic flow calls its post-claim revalidator
    raises: str = ""  # the handler whose effect raises a resident outage


WORLDS = (
    World("base"),
    World("question", pending="question"),
    World("pending_plain", pending="plain"),
    World("edge_missing", edge="missing"),
    World("edge_none", edge="none"),
    World("edge_missing_artifact", edge="missing", artifact=True),
    World("contained", contained=True),
    World("copilot_resolves", copilot_resolves=True),
    World("copilot_fresh", copilot_resolves=True, fresh_calls=True),
    World("artifact", artifact=True),
    World("all_on", pending="question", contained=True, copilot_resolves=True, artifact=True),
    World("late_on", pending="plain", copilot_resolves=True, fresh_calls=True, artifact=True),
    World("revalidate", revalidate=True),
    World("raise_copilot", copilot_resolves=True, raises="copilot"),
    World("raise_artifact", artifact=True, raises="artifact"),
    World("raise_facts", artifact=True, raises="artifact_facts"),
    World("raise_generic", raises="generic"),
    World("raise_revalidate", revalidate=True, raises="revalidate"),
    World("raise_claude", raises="claude"),
    World("raise_containment", raises="containment"),
)


@dataclass(frozen=True, eq=False)
class Case:
    """One enumerated fact combination."""

    harness: str
    entry: dict[str, object]
    prepared: dict[str, object]
    copilot_stage: str
    copilot_tool_call: bool

    @property
    def canonical(self) -> str:
        return _canonical_harness_name(self.harness)

    def facts(self) -> dict[str, object]:
        """The resident's ``HookRouteInputsV1`` for this case."""
        return {
            "harness": self.harness,
            "canonical_harness": self.canonical,
            "invoked_event": runtime_hook_event_name(self.entry),
            "hook_event": _hook_event_name(self.prepared) or "",
            "runtime_event": runtime_hook_event_name(self.prepared),
            "notification_type": _optional_string(self.prepared.get("notification_type")) or "",
            "copilot_stage": self.copilot_stage,
            "copilot_tool_call_present": self.copilot_tool_call,
            "copilot_permission_request": _is_copilot_permission_request(self.prepared),
        }


class Recorder:
    """The stubbed effects of one run: each appends a tagged entry to the trace."""

    def __init__(self, world: World) -> None:
        self.world = world
        self.trace: list[list[Any]] = []

    def add_event(self, kind: str, data: object, now: object) -> None:
        self.note("event", kind, data)

    def note(self, *entry: object) -> None:
        self.trace.append(list(entry))

    def _raise(self, handler: str) -> None:
        if self.world.raises == handler:
            self.note("raise", handler)
            raise NativeHookDecisionError(f"outage_{handler}")

    def pending_pair(self) -> tuple[str, dict[str, bool]] | None:
        self.note("pending_load")
        return None if self.world.pending == "none" else PENDING

    def question_verdict(self) -> SimpleNamespace:
        is_question = self.world.pending == "question"
        self.note("question_verdict", is_question)
        return SimpleNamespace(is_question=is_question)

    def edge(self, harness: object, default_harness: object) -> object:
        self.note("edge", harness, default_harness)
        return EDGES[self.world.edge]

    def containment(self, edge_result: object) -> int | None:
        self.note("containment", edge_result)
        self._raise("containment")
        return RC["containment"] if self.world.contained else None

    def copilot_resolve(self, config: object, preferred: object) -> tuple[str, str, str] | None:
        self.note("copilot_resolve", config, preferred)
        if not self.world.copilot_resolves:
            return None
        return ("copilot-artifact", "copilot-hash", "copilot-args")

    def _fresh(self, provider: Callable[[], object] | None) -> None:
        if self.world.fresh_calls and provider is not None:
            fresh = provider()
            self.note("fresh_authority", list(fresh) if isinstance(fresh, tuple) else fresh)

    def copilot_pretool(self, edge_result: object, provider: Callable[[], object] | None) -> int:
        self.note("copilot_pretool", edge_result)
        self._fresh(provider)
        self._raise("copilot")
        return RC["copilot_pretool"]

    def copilot_permission_request(
        self, tool_call: object, provider: Callable[[], object] | None, managed_install: object
    ) -> int | None:
        if tool_call is None:
            return None
        self.note("copilot_permission_request", list(tool_call), managed_install)  # type: ignore[call-overload]
        self._fresh(provider)
        self._raise("copilot")
        return RC["copilot_permission_request"]

    def data_flow(self) -> tuple[tuple[str, ...], str]:
        self.note("data_flow")
        return ("flow-signal",), "flow-artifact"

    def runtime_artifact(self, signals: object, flow_artifact: object) -> str | None:
        self.note("runtime_artifact", signals, flow_artifact)
        return "runtime-artifact" if self.world.artifact else None

    def claude_permission_request(self, runtime_artifact: object) -> int:
        self.note("claude_permission_request", runtime_artifact)
        self._raise("claude")
        return RC["claude_permission_request"]

    def claude_permission_prompt(self) -> int:
        self.note("claude_permission_prompt")
        self._raise("claude")
        return RC["claude_permission_prompt"]

    def stop_discard(self) -> int:
        self.note("stop_discard")
        return 2

    def fresh(self, what: str) -> str:
        self.note(f"fresh_{what}")
        return f"fresh-{what}"

    def unavailable(self, event_name: object, reason_code: object, recording_only: object) -> int:
        self.note("unavailable", event_name, reason_code, recording_only)
        return RC["unavailable"]

    def artifact_flow(self, entry: Mapping[str, object]) -> int:
        self.note("artifact_flow", dict(entry))
        if self.world.raises == "artifact_facts":
            self.note("raise", "artifact_facts")
            raise HookArtifactFactsUnavailableError
        self._raise("artifact")
        return RC["artifact_flow"]

    def generic(self, entry: Mapping[str, object], revalidator: Callable[..., int] | None) -> int:
        self.note("generic", dict(entry), revalidator is not None)
        if revalidator is None:
            self._raise("revalidate")
            return RC["generic_flow"]
        if self.world.revalidate:
            result = revalidator("claimed-hash", "claimed-approval")
            self.note("generic_revalidated", result)
            return result
        self._raise("generic")
        return RC["generic_flow"]


# --- The retired ladder -------------------------------------------------------


def _recorded_ladder(case: Case, r: Recorder, claim: Mapping[str, object]) -> int:
    """``run_native_hook_pipeline`` after the payload was prepared, effects stubbed."""

    payload = case.prepared
    canonical = case.canonical
    claude = canonical == "claude-code"
    if runtime_hook_event_name(case.entry) == "PermissionRequest" and canonical in _PASSTHROUGH_HARNESSES:
        return 0
    if claude and _hook_event_name(payload) == "PostToolUse":
        pending_pair = r.pending_pair()
        if pending_pair is not None and r.question_verdict().is_question:
            r.note("question_persist")
            return 0
    edge = r.edge(case.harness, case.harness)
    edge = edge if isinstance(edge, Mapping) else {}
    edge_result, edge_receipt, edge_failure = edge.get("result"), edge.get("receipt"), edge.get("failure_reason_code")
    recording_only = bool(edge.get("recording_only"))
    event_name = _hook_event_name(payload) or runtime_hook_event_name(payload)
    if event_name in _EDGE_EVENTS and edge_result is None:
        return r.unavailable(event_name, str(edge_failure or "native_hook_event_unavailable"), recording_only)
    contained = r.containment(edge_result)
    if contained is not None:
        return contained

    def provider() -> tuple[str, str, str, str] | None:
        fresh = r.fresh("config")
        tool_call = r.copilot_resolve(fresh, "cli")
        return None if tool_call is None else (fresh, *tool_call)

    try:
        if case.copilot_tool_call and case.copilot_stage == "pretooluse":
            result = r.copilot_pretool(edge_result, provider)
            if result is not None:
                return result
        permission_request = (
            r.copilot_resolve("config", "cli")
            if case.harness == "copilot" and _is_copilot_permission_request(payload)
            else None
        )
        result = r.copilot_permission_request(permission_request, provider, "managed-install")
        if result is not None:
            return result
    except NativeHookDecisionError as error:
        return r.unavailable(event_name, error.code, recording_only)
    signals, flow_artifact = r.data_flow()
    runtime_artifact = r.runtime_artifact(signals, flow_artifact)
    if claude and _hook_event_name(payload) == "PermissionRequest":
        return r.claude_permission_request(runtime_artifact)
    notification = _optional_string(payload.get("notification_type")) == "permission_prompt"
    if claude and _hook_event_name(payload) == "Notification" and notification:
        return r.claude_permission_prompt()
    if claude and _hook_event_name(payload) == "Stop":
        r.stop_discard()
        r.add_event("claude/turn_stop", {"session_id": SESSION, "discarded_pending_permissions": 2}, "now")
        return 0
    edge_entry = {"edge_result": edge_result, "edge_receipt": edge_receipt}
    if runtime_artifact is not None:
        try:
            return r.artifact_flow(
                {
                    **edge_entry,
                    "config": "config",
                    "envelope": "envelope",
                    "managed_install": "managed-install",
                    "data_flow_signals": signals,
                    "runtime_artifact": runtime_artifact,
                    "recording_only": recording_only,
                    "claimed_hash": claim["claimed_hash"],
                    "trusted_override": claim["trusted_override"],
                    "approval_request_id": claim["approval_request_id"],
                    "claim_saved_approval": claim["claim_saved_approval"],
                }
            )
        except HookArtifactFactsUnavailableError:
            return r.unavailable(event_name, HookArtifactFactsUnavailableError.code, recording_only)
        except NativeHookDecisionError as error:
            return r.unavailable(event_name, error.code, recording_only)

    def run_generic(entry: Mapping[str, object], revalidator: Callable[..., int] | None) -> int:
        try:
            return r.generic(entry, revalidator)
        except NativeHookDecisionError as error:
            return r.unavailable(event_name, error.code, recording_only)

    def revalidate(claimed_hash: str, claimed_approval: str) -> int:
        r.fresh("config")
        r.fresh("envelope")
        entry = {
            **edge_entry,
            "config": "fresh-config",
            "envelope": "fresh-envelope",
            "claimed_hash": claimed_hash,
            "claimed_approval": claimed_approval,
            "claim_saved_approval": False,
        }
        return run_generic(entry, None)

    entry = {
        **edge_entry,
        "config": "config",
        "envelope": "envelope",
        "claimed_hash": claim["claimed_hash"],
        "claimed_approval": None,
        "claim_saved_approval": claim["claim_saved_approval"],
    }
    return run_generic(entry, revalidate)


def cases() -> Iterator[Case]:
    """Every fact combination the ladder can observe."""
    pairs = [(payload, payload) for payload in PAYLOADS] + list(REWRITTEN)
    for harness in HARNESSES:
        # Preparation derives the Copilot stage and tool call for Copilot only;
        # the other harnesses get one unreachable pair to pin the guard.
        variants = (
            list(itertools.product(COPILOT_STAGES, (False, True)))
            if harness == "copilot"
            else [("", False), ("pretooluse", True)]
        )
        for (entry, prepared), (stage, tool_call) in itertools.product(pairs, variants):
            yield Case(
                harness=harness,
                entry={**entry, "session_id": SESSION},
                prepared={**prepared, "session_id": SESSION},
                copilot_stage=stage,
                copilot_tool_call=tool_call,
            )


CLAIM: dict[str, object] = {
    "claimed_hash": "saved-hash",
    "claim_saved_approval": True,
    "trusted_override": True,
    "approval_request_id": "request-1",
}


def run(case: Case, world: World) -> tuple[list[list[Any]], int | str]:
    recorder = Recorder(world)
    try:
        rc: int | str = _recorded_ladder(case, recorder, CLAIM)
    except NativeHookDecisionError:
        rc = "raised"
    return recorder.trace, rc


_TRACE_STEPS = (
    ("pending_load", "claude_guard_question"),
    ("edge", "native_edge"),
    ("containment", "containment"),
    ("copilot_pretool", "copilot_pretool"),
    ("copilot_resolve", "copilot_permission_request"),
    ("runtime_artifact", "runtime_artifact"),
    ("claude_permission_request", "claude_permission_request"),
    ("claude_permission_prompt", "claude_permission_prompt"),
    ("stop_discard", "claude_stop"),
    ("generic", "generic_flow"),
)


def observed_route(
    base: list[list[Any]], edge_missing: list[list[Any]], event_name: str, *, passthrough: bool
) -> dict[str, Any]:
    """The plan the traces exhibit, and the event name outage responses carry."""
    if passthrough:
        return {"plan": ["passthrough"], "event_name": event_name}
    seen = {entry[0] for entry in base}
    plan: list[str] = []
    for kind, step in _TRACE_STEPS:
        if kind == "generic" and "generic" in seen:
            plan.append("artifact_flow")
        if kind in seen:
            plan.append(step)
        if kind == "edge" and any(entry[0] == "unavailable" for entry in edge_missing):
            plan.append("edge_unavailable")
    return {"plan": plan, "event_name": event_name}


def record(case: Case) -> dict[str, Any]:
    worlds = {world.name: run(case, world) for world in WORLDS}
    base, edge_missing = worlds["base"][0], worlds["edge_missing"][0]
    event_name = _hook_event_name(case.prepared) or runtime_hook_event_name(case.prepared)
    return {
        "facts": case.facts(),
        "route": observed_route(base, edge_missing, event_name, passthrough=not base),
        "worlds": {name: {"trace": trace, "rc": rc} for name, (trace, rc) in worlds.items()},
    }


def main() -> int:
    vectors = [record(case) for case in cases()]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    print(f"wrote {len(vectors)} vectors to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
