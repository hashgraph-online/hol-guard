#!/usr/bin/env python3
"""Record artifact-hook response directive vectors from the Python routing.

The artifact hook's final response used to be routed in Python
(``finalize_native_artifact_hook``): the exit block, the JSON document, the
native response, the post-tool envelope and the fallback envelope, with the
emitter, the reason mode, the Claude and Codex system messages, the
remediation gate and the exit code. The resident decides all of that now
(``artifact_directive`` in ``hook_decision_artifact_directive.rs``).

The routing below (``_recorded_*``) is that Python code as it stood at
e31d1c99d9, kept here so the oracle never calls the code it checks. Every
emitter is replaced by a stub that writes a tagged line, so a vector records
exactly which output the old routing produced:

    PYTHONPATH=src .venv/bin/python scripts/ci/record_artifact_directive_vectors.py

Each vector holds the resident's inputs (``facts``), the extra transport facts
(``extra``), the directive fields the recorded output exhibits
(``directive``), and the stubbed ``stdout``, ``stderr`` and ``rc``. The Rust
``hook_decision_artifact_directive_tests`` replays the directive fields.
"""

from __future__ import annotations

import gzip
import io
import itertools
import json
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard.cli.commands_support_prompts import (
    _claude_prompt_system_message,
    _codex_prompt_block_system_message,
)
from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import _canonical_harness_name
from codex_plugin_scanner.guard.cli.native_hook_exit_code import native_hook_verdict_exit_code
from codex_plugin_scanner.guard.runtime.embedded_script_evidence import EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/artifact_directive_vectors.json.gz")

HARNESSES = (
    "codex",
    "claude-code",
    "claude",
    "copilot",
    "cursor",
    "cline",
    "devin",
    "devin-cli",
    "antigravity",
    "gemini",
    "grok",
    "grok-build",
    "hermes",
    "kimi",
    "kimi-cli",
    "omp",
    "oh-my-pi",
    "pi",
    "pi-agent",
    "openclaw",
    "opencode",
    "zcode",
    "z-code",
    "paseo",
    "superagent",
    "unknown-harness",
)
EVENTS = (
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "PermissionRequest",
    "Notification",
    "SessionStart",
    "Stop",
    "pre_tool_use",
    "PreToolCall",
    "preToolUse",
    "BeforeTool",
)
ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
_BLOCKING = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_GUIDED_POLICY_ACTIONS = frozenset({"block", "review", "require-reapproval", "sandbox-required"})

# Tagged stand-ins. The raw reason names the approval centre so the Codex
# prompt message (which only quotes a reason that does) is exercised.
RAW = "RAW reason, open hol guard"
CTX = "CTX approval context"
HINT = "HINT review hint"
WHY = "WHY now"
RISK = "RISK headline"
REMEDIATION = EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE
GROK_EXIT = 77
JSON_DOCUMENT_EXIT = 5
_TAGS = {RAW: "raw (open hol guard)", CTX: "ctx", HINT: "hint", WHY: "why", RISK: "risk", REMEDIATION: "rem"}


@dataclass
class Case:
    """One enumerated fact combination and the state built from it."""

    harness: str
    event: str
    action: str
    json: bool
    output_stream: bool
    replayed: bool
    approval_context: bool
    review_hint: bool = False
    prompt_hard_block: bool = False
    prompt_secret_read: bool = False
    json_document_owns: bool = False
    exit_block: bool | None = None
    response_payload: dict[str, object] = field(default_factory=dict)
    payload: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.response_payload = {"why_now": WHY, "risk_headline": RISK}
        if self.review_hint:
            self.response_payload["review_hint"] = HINT
        self.payload = {"hook_event_name": self.event}
        if self.replayed:
            self.payload.update({"artifact_id": "artifact-1", "policy_action": self.action})

    @property
    def canonical(self) -> str:
        return _canonical_harness_name(self.harness)

    def facts(self) -> dict[str, object]:
        """The resident's ``ArtifactDirectiveInputsV1`` for this case."""

        return {
            "harness": self.harness,
            "canonical_harness": self.canonical,
            "event": self.event,
            "policy_action": self.action,
            "json": self.json,
            "output_stream_present": self.output_stream,
            "replayed": self.replayed,
            "approval_context_present": self.approval_context,
            "prompt_hard_block": self.prompt_hard_block,
            "prompt_secret_read": self.prompt_secret_read,
        }

    def extra(self) -> dict[str, bool]:
        return {"review_hint": self.review_hint, "json_document_owns": self.json_document_owns}

    def prompt_classes(self) -> list[str]:
        classes = []
        if self.prompt_hard_block:
            classes.append("guard_bypass_intent")
        if self.prompt_secret_read:
            classes.append("secret_read")
        return classes

    def artifact(self) -> SimpleNamespace:
        metadata: dict[str, object] = {}
        if self.prompt_classes():
            metadata["prompt_request_classes"] = self.prompt_classes()
        return SimpleNamespace(metadata=metadata)


CURRENT: list[Case] = []


def _current() -> Case:
    return CURRENT[-1]


# --- Stubs shared by the recorder and the parity test -----------------------


def _tag(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, str) and value in _TAGS:
        return _TAGS[value]
    return repr(value)


def _payload_tag(value: object) -> str:
    if value is None:
        return "none"
    if isinstance(value, Mapping) and "why_now" in value:
        return "response"
    if isinstance(value, Mapping) and "hook_event_name" in value:
        return "hook"
    return "other"


def _out(*fields: object) -> None:
    sys.stdout.write(json.dumps(list(fields)) + "\n")


def _err(*fields: object) -> None:
    sys.stderr.write(json.dumps(list(fields)) + "\n")


def stub_native_hook_reason(*values: object) -> str:
    return "NR[" + ",".join(_tag(value) for value in values) + "]"


def stub_native_hook_reason_for_harness(harness: str, *values: object) -> str:
    return f"NRH<{harness}>[" + ",".join(_tag(value) for value in values) + "]"


def stub_copilot_hook_reason(*values: object) -> str:
    return "COPILOT[" + ",".join(_tag(value) for value in values) + "]"


def stub_runtime_artifact_native_reason(*_args: object, **_kwargs: object) -> str:
    return RAW


def stub_live_hook_approval_context(*_args: object, **_kwargs: object) -> str | None:
    return CTX if _current().approval_context else None


def stub_emit_native_hook_response(
    *,
    harness: str,
    policy_action: str,
    reason: str,
    event_name: str = "PreToolUse",
    additional_context: str | None = None,
    system_message: str | None = None,
    output_stream: object = None,
) -> None:
    _out(
        "native",
        harness,
        policy_action,
        event_name,
        reason,
        system_message,
        additional_context,
        output_stream is not None,
    )


def stub_emit_grok_hook_response(
    *,
    policy_action: str,
    reason: str,
    event_name: str | None = None,
    approval_payload: object = None,
    output_stream: object = None,
) -> None:
    _out("grok", policy_action, event_name, reason, _payload_tag(approval_payload), output_stream is not None)


def stub_grok_hook_process_exit(_policy_action: str) -> int:
    return GROK_EXIT


def stub_emit_pi_hook_response(
    *, policy_action: str, reason: str, approval_payload: object = None, output_stream: object = None
) -> None:
    _out("pi", policy_action, reason, _payload_tag(approval_payload), output_stream is not None)


def _stub_payload_emitter(kind: str) -> Callable[..., None]:
    def emit(
        *,
        policy_action: str,
        reason: str,
        event_name: str | None = None,
        payload: object = None,
        output_stream: object = None,
    ) -> None:
        _out(kind, policy_action, reason, event_name, _payload_tag(payload), output_stream is not None)

    return emit


stub_emit_zcode_hook_response = _stub_payload_emitter("zcode")
stub_emit_devin_hook_response = _stub_payload_emitter("devin")


def stub_emit_native_hook_block_stderr(reason: str) -> None:
    _err("block", reason)


def stub_emit_native_hook_notification_stderr(reason: str) -> None:
    _err("notice", reason)


def stub_claude_native_pretooluse_terminal_notice(*, payload: object, reason: str) -> str:
    return f"TN<{_payload_tag(payload)}|{reason}>"


def stub_native_hook_json_document(
    args: object,
    *,
    event_name: str,
    policy_action: str,
    reason: str,
    exit_code: Callable[[], int] | None = None,
    envelope: object,
    system_message: str | None = None,
    generic_path: bool = False,
    native_protocol_payload: bool = False,
    command_text: str | None = None,
    command_surface: bool = False,
    verified_benign: bool = False,
) -> tuple[dict[str, object] | None, int] | None:
    _out(
        "json_document",
        event_name,
        policy_action,
        reason,
        _payload_tag(envelope),
        system_message,
        generic_path,
        native_protocol_payload,
        command_text,
        command_surface,
        verified_benign,
    )
    return ({"document": True}, JSON_DOCUMENT_EXIT) if _current().json_document_owns else None


def stub_emit_native_hook_json_document(
    payload: object, *, compact: bool = False, output_stream: object = None
) -> None:
    _out("json_emit", compact, output_stream is not None)


POST_TOOL_BLOCKING_ACTIONS = {"review", "require-reapproval", "sandbox-required", "block"}


def stub_emit_native_post_tool_envelope(
    harness: str,
    *,
    blocking: bool,
    reason: str,
    response_payload: object,
    output_stream: object = None,
    as_json: bool = False,
) -> None:
    _out("post_tool", harness, blocking, reason, _payload_tag(response_payload), output_stream is not None, as_json)


def stub_emit(command: str, payload: Mapping[str, object], as_json: bool) -> None:
    _out("envelope", command, payload.get("continue"), payload.get("decision"), bool(as_json))


# --- The routing as it stood in Python -------------------------------------


def _recorded_should_emit_native_hook_response(case: Case) -> bool:
    harness = _canonical_harness_name(case.harness)
    natives = {"claude-code", "codex", "kimi", "grok", "pi", "omp", "zcode", "devin"}
    return harness == "hermes" or (harness in natives and not case.json)


def _recorded_should_emit_native_hook_json_response(case: Case, *, event_name: str, output_stream: object) -> bool:
    harness = _canonical_harness_name(case.harness)
    if harness == "grok" and case.json:
        return True
    if harness == "zcode" and case.json:
        return True
    if harness == "codex" and case.json and event_name == "UserPromptSubmit":
        return True
    return (
        harness in {"claude-code", "codex"}
        and case.json
        and output_stream is not None
        and (
            event_name in {"PreToolUse", "Notification"}
            or (harness == "claude-code" and event_name == "UserPromptSubmit")
        )
    )


def _recorded_should_emit_native_hook_exit_block(case: Case, *, event_name: str, policy_action: str) -> bool:
    canonical = _canonical_harness_name(case.harness)
    compact_event = event_name.replace("_", "").replace("-", "").lower()
    blocking = compact_event in {"pretooluse", "userpromptsubmit", "pretoolcall"}
    if canonical in {"kimi", "grok", "hermes", "pi", "omp", "zcode", "devin"} and blocking:
        if canonical == "zcode":
            from codex_plugin_scanner.guard.adapters._modules.zcode.zcode_hooks import zcode_hook_process_exit

            return zcode_hook_process_exit(policy_action=policy_action, event_name=event_name) == 2
        return policy_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return False


def _recorded_exit_code(canonical: str, policy_action: str, event_name: str) -> int:
    if canonical == "grok":
        return stub_grok_hook_process_exit(policy_action)
    return native_hook_verdict_exit_code(canonical, policy_action, event_name)


def _recorded_embedded_script_remediation(policy_action: str) -> str | None:
    # Every recorded command carries an inline script body.
    return REMEDIATION if policy_action in _GUIDED_POLICY_ACTIONS else None


def _recorded_finalize(case: Case) -> int:
    """``finalize_native_artifact_hook`` from the receipt onward, emitters stubbed."""

    harness = case.harness
    event_name = case.event
    policy_action = case.action
    response_payload = case.response_payload
    payload = case.payload
    output_stream = io.StringIO() if case.output_stream else None
    approval_context = stub_live_hook_approval_context()
    composed: dict[str, str] = {}

    def raw_runtime_reason() -> str:
        if "raw" not in composed:
            composed["raw"] = stub_runtime_artifact_native_reason()
        return composed["raw"]

    case.exit_block = _recorded_should_emit_native_hook_exit_block(
        case, event_name=event_name, policy_action=policy_action
    )
    if case.exit_block:
        if _canonical_harness_name(harness) == "codex" and approval_context is not None:
            native_block_reason = stub_native_hook_reason(
                raw_runtime_reason(), approval_context, _recorded_embedded_script_remediation(policy_action)
            )
        else:
            native_block_reason = stub_native_hook_reason_for_harness(
                harness, raw_runtime_reason(), approval_context, _recorded_embedded_script_remediation(policy_action)
            )
        if _canonical_harness_name(harness) in {"kimi", "hermes"}:
            stub_emit_native_hook_response(
                harness=harness,
                policy_action=policy_action,
                event_name=event_name,
                reason=native_block_reason,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(harness) == "grok":
            stub_emit_grok_hook_response(
                policy_action=policy_action,
                event_name=event_name,
                reason=native_block_reason,
                approval_payload=response_payload,
                output_stream=output_stream,
            )
            return _recorded_exit_code(_canonical_harness_name(harness), policy_action, event_name)
        elif _canonical_harness_name(harness) in {"pi", "omp"}:
            stub_emit_pi_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                approval_payload=response_payload,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(harness) == "zcode":
            stub_emit_zcode_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
        elif _canonical_harness_name(harness) == "devin":
            stub_emit_devin_hook_response(
                policy_action=policy_action,
                reason=native_block_reason,
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
        stub_emit_native_hook_block_stderr(native_block_reason)
        return _recorded_exit_code(_canonical_harness_name(harness), policy_action, event_name)

    def runtime_reason() -> str:
        if "harness" not in composed:
            if _canonical_harness_name(harness) == "codex" and (
                event_name == "UserPromptSubmit"
                or approval_context is not None
                or policy_action in {"block", "sandbox-required"}
            ):
                composed["harness"] = stub_native_hook_reason(
                    raw_runtime_reason(),
                    approval_context or response_payload.get("review_hint"),
                    _recorded_embedded_script_remediation(policy_action),
                )
            else:
                composed["harness"] = stub_native_hook_reason_for_harness(
                    harness,
                    raw_runtime_reason(),
                    approval_context,
                    _recorded_embedded_script_remediation(policy_action),
                )
        return composed["harness"]

    if (
        _canonical_harness_name(harness) == "claude-code"
        and event_name == "PreToolUse"
        and policy_action in {"review", "require-reapproval"}
    ):
        stub_emit_native_hook_notification_stderr(
            stub_claude_native_pretooluse_terminal_notice(payload=dict(payload), reason=runtime_reason())
        )
    canonical_harness = _canonical_harness_name(harness)
    system_message = None
    if canonical_harness == "claude-code":
        system_message = _claude_prompt_system_message(
            event_name=event_name,
            policy_action=policy_action,
            artifact=case.artifact(),  # type: ignore[arg-type]
            native_reason=runtime_reason,
        )
    elif canonical_harness == "codex" and event_name == "UserPromptSubmit":
        system_message = _codex_prompt_block_system_message(policy_action=policy_action, native_reason=runtime_reason)
    if case.json and output_stream is None:
        if canonical_harness == "copilot":
            emit_reason = stub_copilot_hook_reason(
                response_payload.get("why_now"),
                response_payload.get("review_hint"),
                response_payload.get("risk_headline"),
            )
        else:
            emit_reason = runtime_reason()
        json_result = stub_native_hook_json_document(
            SimpleNamespace(harness=harness, json=case.json),
            event_name=event_name,
            policy_action=policy_action,
            reason=emit_reason,
            envelope=response_payload,
            system_message=system_message,
            native_protocol_payload="hook_event_name" in payload or "event" not in payload,
            command_surface=True,
        )
        if json_result is not None:
            json_doc, json_rc = json_result
            if json_doc:
                stub_emit_native_hook_json_document(
                    json_doc, compact=canonical_harness == "copilot", output_stream=output_stream
                )
            return json_rc
    if _recorded_should_emit_native_hook_response(case) or _recorded_should_emit_native_hook_json_response(
        case, event_name=event_name, output_stream=output_stream
    ):
        if canonical_harness == "grok":
            stub_emit_grok_hook_response(
                policy_action=policy_action,
                event_name=event_name,
                reason=runtime_reason(),
                approval_payload=response_payload,
                output_stream=output_stream,
            )
            return _recorded_exit_code(canonical_harness, policy_action, event_name)
        if canonical_harness in {"pi", "omp"}:
            stub_emit_pi_hook_response(
                policy_action=policy_action,
                reason=runtime_reason(),
                approval_payload=response_payload,
                output_stream=output_stream,
            )
            return _recorded_exit_code(canonical_harness, policy_action, event_name)
        if canonical_harness == "zcode":
            stub_emit_zcode_hook_response(
                policy_action=policy_action,
                reason=runtime_reason(),
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
            return _recorded_exit_code(canonical_harness, policy_action, event_name)
        if canonical_harness == "devin":
            stub_emit_devin_hook_response(
                policy_action=policy_action,
                reason=runtime_reason(),
                event_name=event_name,
                payload=payload,
                output_stream=output_stream,
            )
            return _recorded_exit_code(canonical_harness, policy_action, event_name)
        stub_emit_native_hook_response(
            harness=harness,
            policy_action=policy_action,
            event_name=event_name,
            reason=runtime_reason(),
            system_message=system_message,
            output_stream=output_stream,
        )
        return _recorded_exit_code(canonical_harness, policy_action, event_name)
    if event_name == "PostToolUse":
        stub_emit_native_post_tool_envelope(
            harness,
            # The recording keeps deriving this from the policy action, which is
            # what Python did before the renderer started reading the native
            # envelope decision.
            blocking=policy_action in POST_TOOL_BLOCKING_ACTIONS,
            reason=runtime_reason(),
            response_payload=response_payload,
            output_stream=output_stream,
            as_json=case.json,
        )
        return _recorded_exit_code(canonical_harness, policy_action, event_name)
    response_payload["continue"] = True
    response_payload["decision"] = (
        "block" if policy_action in {"review", "require-reapproval", "sandbox-required", "block"} else "allow"
    )
    stub_emit("hook", response_payload, case.json)
    if isinstance(payload.get("artifact_id"), str) and isinstance(payload.get("policy_action"), str):
        return 0
    return _recorded_exit_code(canonical_harness, policy_action, event_name)


# --- Enumeration and the directive the output exhibits ---------------------


def cases() -> Iterator[Case]:
    """Every fact combination the routing can observe.

    Raw ``copilot`` without ``--json`` answers before the routing runs, so it
    is not part of the directive. Review hints only reach Codex reasons and the
    prompt classes only reach Claude, so they vary only there; the JSON
    document's own answer varies only where a document is built.
    """

    for harness, event, action, as_json, stream, replayed, context in itertools.product(
        HARNESSES, EVENTS, ACTIONS, (False, True), (False, True), (False, True), (False, True)
    ):
        if harness == "copilot" and not as_json:
            continue
        canonical = _canonical_harness_name(harness)
        hints = (False, True) if canonical == "codex" else (False,)
        prompts = itertools.product((False, True), (False, True)) if canonical == "claude-code" else [(False, False)]
        owns = (
            (False, True) if as_json and not stream and canonical in {"copilot", "claude-code", "codex"} else (False,)
        )
        for hint, (hard, secret), own in itertools.product(hints, list(prompts), owns):
            yield Case(
                harness=harness,
                event=event,
                action=action,
                json=as_json,
                output_stream=stream,
                replayed=replayed,
                approval_context=context,
                review_hint=hint,
                prompt_hard_block=hard,
                prompt_secret_read=secret,
                json_document_owns=own,
            )


def capture(run: Callable[[], int]) -> tuple[str, str, int]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        rc = run()
    return stdout.getvalue(), stderr.getvalue(), rc


_CLAUDE_SECRET = "HOL Guard intercepted this prompt because it asks Claude to access local secrets."
_CLAUDE_SENSITIVE = "HOL Guard intercepted this prompt because it leads to a sensitive action."


def _system_message_kind(message: object) -> str:
    if message is None:
        return "none"
    text = str(message)
    if text.startswith(_CLAUDE_SECRET):
        return "claude_prompt_secret"
    if text.startswith(_CLAUDE_SENSITIVE):
        return "claude_prompt_sensitive"
    if text.startswith("HOL Guard paused your Codex prompt."):
        return "codex_prompt"
    if text.startswith(("NR[", "NRH<")):
        return "claude_punctuated"
    raise ValueError(f"unrecognized system message: {text!r}")


def _reason_fields(reason: str, directive: dict[str, Any]) -> None:
    if reason.startswith("NR["):
        directive["codex_native_reason"] = "artifact_codex"
    elif reason.startswith("NRH<"):
        directive["codex_native_reason"] = "never"
    else:
        return
    directive["include_remediation"] = ",rem]" in reason


_EMITTERS = {"native": "default", "grok": "grok", "pi": "pi", "zcode": "zcode", "devin": "devin"}


def observed_directive(case: Case, stdout: str, stderr: str, rc: int) -> dict[str, Any]:
    """The directive fields the recorded output determines."""

    out = [json.loads(line) for line in stdout.splitlines()]
    err = [json.loads(line) for line in stderr.splitlines()]
    directive: dict[str, Any] = {"route": "exit_block" if case.exit_block else "render"}
    emitted = [line for line in out if line[0] in _EMITTERS]
    if emitted:
        line = emitted[0]
        directive["emitter"] = _EMITTERS[line[0]]
        reason = {"native": 4, "grok": 3, "pi": 2, "zcode": 2, "devin": 2}[line[0]]
        _reason_fields(line[reason], directive)
        if line[0] == "native" and not case.exit_block:
            directive["system_message"] = _system_message_kind(line[5])
    if case.exit_block:
        directive["exit_block_stderr"] = any(line[0] == "block" for line in err)
        directive["exit_code"] = None if rc == GROK_EXIT else rc
        return directive
    directive["terminal_notice"] = any(line[0] == "notice" for line in err)
    documents = [line for line in out if line[0] == "json_document"]
    directive["try_json_document"] = bool(documents)
    if documents:
        document = documents[0]
        directive["json_reason"] = "copilot" if document[3].startswith("COPILOT[") else "harness"
        if directive["json_reason"] == "harness":
            _reason_fields(document[3], directive)
        directive["system_message"] = _system_message_kind(document[5])
        if case.json_document_owns:
            # The stub owns the document route's status, so the recording
            # carries the exit code the real route took: the harness table,
            # before the replayed fallback envelope relaxes it to 0.
            directive["json_exit_code"] = (
                None if case.canonical == "grok" else _recorded_exit_code(case.canonical, case.action, case.event)
            )
            return directive
    post = [line for line in out if line[0] == "post_tool"]
    envelope = [line for line in out if line[0] == "envelope"]
    if emitted:
        directive["after_json"] = "native_response"
    elif post:
        directive["after_json"] = "post_tool_envelope"
        # The post-tool envelope carries a verdict of its own, and the renderer
        # now reads it off the directive instead of re-deriving it from the
        # policy action, so the recording has to carry it as well.
        directive["envelope_decision"] = "block" if post[0][2] else "allow"
        _reason_fields(post[0][3], directive)
    else:
        directive["after_json"] = "fallback_envelope"
        directive["envelope_decision"] = envelope[0][3]
    directive["exit_code"] = None if rc == GROK_EXIT else rc
    return directive


def record(case: Case, run: Callable[[Case], int] = _recorded_finalize) -> dict[str, Any]:
    CURRENT.append(case)
    try:
        stdout, stderr, rc = capture(lambda: run(case))
    finally:
        CURRENT.pop()
    return {
        "facts": case.facts(),
        "extra": case.extra(),
        "directive": observed_directive(case, stdout, stderr, rc),
        "stdout": stdout,
        "stderr": stderr,
        "rc": rc,
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
