"""The artifact hook renders the resident's directive exactly as Python routed it.

``scripts/ci/record_artifact_directive_vectors.py`` recorded the retired
Python routing of ``finalize_native_artifact_hook`` with every emitter
stubbed. The Rust suite replays the directive fields; this suite feeds each
recorded directive to the new transport, with the same stubs, and checks the
output is unchanged. A directive field the recording never exhibited is
withheld, so a renderer that consults it fails here.
"""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.adapters import grok_hooks
from codex_plugin_scanner.guard.adapters._modules.devin import devin_hooks
from codex_plugin_scanner.guard.adapters._modules.pi import pi_hooks
from codex_plugin_scanner.guard.adapters._modules.zcode import zcode_hooks
from codex_plugin_scanner.guard.cli import commands_hook_native_finish as finish
from codex_plugin_scanner.guard.cli import commands_hook_native_generic_render as render
from codex_plugin_scanner.guard.runtime import embedded_script_evidence

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/artifact_directive_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_artifact_directive_vectors.py"


def _recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_artifact_directive_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _vectors() -> list[dict[str, Any]]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


class _Observed(dict):
    """A directive that refuses the fields the recording never exhibited."""

    def __getitem__(self, key: str) -> Any:
        if key not in self:
            raise AssertionError(f"renderer consulted unrecorded directive field {key!r}")
        return super().__getitem__(key)


def _stub_transport(monkeypatch: pytest.MonkeyPatch, recorder: Any) -> None:
    monkeypatch.setattr(finish, "_browser_approval_decision", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "_record_harness_usage_for_hook", lambda *_a, **_k: None)
    monkeypatch.setattr(finish, "live_hook_approval_context", recorder.stub_live_hook_approval_context)
    monkeypatch.setattr(finish, "_runtime_artifact_native_reason", recorder.stub_runtime_artifact_native_reason)
    for name in (
        "native_hook_reason",
        "native_hook_reason_for_harness",
        "copilot_hook_reason",
        "emit_native_hook_response",
        "emit_native_hook_block_stderr",
        "emit_native_hook_notification_stderr",
        "claude_native_pretooluse_terminal_notice",
        "native_hook_json_document",
        "emit_native_hook_json_document",
        "emit_native_post_tool_envelope",
        "emit",
    ):
        monkeypatch.setattr(render, f"_{name}", getattr(recorder, f"stub_{name}"))
    monkeypatch.setattr(grok_hooks, "emit_grok_hook_response", recorder.stub_emit_grok_hook_response)
    monkeypatch.setattr(grok_hooks, "grok_hook_process_exit", recorder.stub_grok_hook_process_exit)
    monkeypatch.setattr(pi_hooks, "emit_pi_hook_response", recorder.stub_emit_pi_hook_response)
    monkeypatch.setattr(zcode_hooks, "emit_zcode_hook_response", recorder.stub_emit_zcode_hook_response)
    monkeypatch.setattr(devin_hooks, "emit_devin_hook_response", recorder.stub_emit_devin_hook_response)
    monkeypatch.setattr(embedded_script_evidence, "command_has_embedded_script", lambda _command: True)


def test_render_reproduces_the_recorded_python_routing(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    _stub_transport(monkeypatch, recorder)

    def vector_key(facts: object, extra: object) -> str:
        return json.dumps([facts, extra], sort_keys=True)

    vectors = {vector_key(vector["facts"], vector["extra"]): vector for vector in _vectors()}
    assert len(vectors) > 40_000
    asked: list[dict[str, object]] = []

    def directive(inputs: dict[str, object], *, guard_home: object = None) -> dict[str, Any]:
        asked.append(dict(inputs))
        case = recorder.CURRENT[-1]
        recorded = vectors[vector_key(case.facts(), case.extra())]["directive"]
        return _Observed({**recorded, "queue_observe_request": False, "queue_approval_request": False})

    monkeypatch.setattr(finish, "native_artifact_directive", directive)

    def run(case: Any) -> int:
        state = SimpleNamespace(
            action_envelope=SimpleNamespace(command="python -c 'x'", action_type="shell_command"),
            event_name=case.event,
            policy_action=case.action,
            response_payload=case.response_payload,
            runtime_artifact=case.artifact(),
        )
        return finish.finalize_native_artifact_hook(
            state,  # type: ignore[arg-type]
            SimpleNamespace(harness=case.harness, json=case.json),  # type: ignore[arg-type]
            config=None,  # type: ignore[arg-type]
            output_stream=io.StringIO() if case.output_stream else None,
            payload=case.payload,
            store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
        )

    failures: list[str] = []
    replayed = 0
    for case in recorder.cases():
        replayed += 1
        expected = vectors[vector_key(case.facts(), case.extra())]
        asked.clear()
        actual = recorder.record(case, run=run)
        if asked != [case.facts()]:
            failures.append(f"{case.facts()}: asked {asked}")
        for key in ("stdout", "stderr", "rc"):
            if actual[key] != expected[key]:
                failures.append(f"{case.facts()} {case.extra()}: {key} {actual[key]!r} != {expected[key]!r}")
        if len(failures) > 10:
            break
    assert failures == []
    assert replayed == len(vectors)


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_directives() -> None:
    failures: list[str] = []
    for vector in _vectors()[::53]:
        answer = decision.native_artifact_directive(vector["facts"])
        assert answer["queue_observe_request"] is False
        assert answer["queue_approval_request"] is False
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {expected!r}"
            for key, expected in vector["directive"].items()
            if answer[key] != expected
        )
    assert failures == []


_FACTS = {
    "harness": "kimi",
    "canonical_harness": "kimi",
    "event": "PreToolUse",
    "policy_action": "block",
    "json": False,
    "output_stream_present": False,
    "replayed": False,
    "approval_context_present": False,
    "prompt_hard_block": False,
    "prompt_secret_read": False,
}
_DIRECTIVE = {
    "kind": "artifact_directive",
    "route": "exit_block",
    "queue_observe_request": False,
    "queue_approval_request": False,
    "emitter": "default",
    "exit_code": 2,
    "stderr_only_on_nonzero_exit": False,
    "codex_native_reason": "never",
    "include_remediation": True,
    "terminal_notice": False,
    "system_message": "none",
    "try_json_document": False,
    "after_json": "native_response",
    "envelope_decision": "block",
    "exit_block_stderr": True,
    "json_reason": "harness",
}


def _resident_answering(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], asked: list[str]) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(
            features={"resident-protocol-v2", decision.HOOK_DECISION_ARTIFACT_DIRECTIVE_FEATURE}
        ),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append(required_feature)
        assert request["query"] == {"kind": "artifact_directive", "inputs": _FACTS}
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(decision, "_resident_request", transport)


def test_a_bound_directive_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _DIRECTIVE, asked)
    answer = decision.native_artifact_directive(_FACTS)
    assert answer == {key: value for key, value in _DIRECTIVE.items() if key != "kind"}
    assert asked == [decision.HOOK_DECISION_ARTIFACT_DIRECTIVE_FEATURE]


@pytest.mark.parametrize(
    "overrides",
    [
        {"route": "silent_exit"},
        {"emitter": "copilot"},
        {"codex_native_reason": "always"},
        {"system_message": "sometimes"},
        {"after_json": "other"},
        {"envelope_decision": "ask"},
        {"json_reason": "prompt"},
        {"queue_approval_request": True},
        {"exit_block_stderr": None},
        {"exit_code": "2"},
        {"extra": True},
    ],
)
def test_a_malformed_directive_fails_closed(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_answering(monkeypatch, {**_DIRECTIVE, **overrides}, [])
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_directive(_FACTS)


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _DIRECTIVE, asked)
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_artifact_directive({key: value for key, value in _FACTS.items() if key != "replayed"})
    assert asked == []


def test_an_unavailable_directive_records_no_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    _stub_transport(monkeypatch, recorder)
    receipts: list[object] = []
    monkeypatch.setattr(finish, "record_native_artifact_hook_receipt", lambda state, _store: receipts.append(state))

    def unavailable(_inputs: dict[str, object], *, guard_home: object = None) -> dict[str, Any]:
        raise decision.NativeHookDecisionError("native_hook_decision_unavailable")

    monkeypatch.setattr(finish, "native_artifact_directive", unavailable)
    case = next(iter(recorder.cases()))
    state = SimpleNamespace(
        action_envelope=SimpleNamespace(command="python -c 'x'", action_type="shell_command"),
        event_name=case.event,
        policy_action=case.action,
        response_payload=case.response_payload,
        runtime_artifact=case.artifact(),
    )
    recorder.CURRENT.append(case)
    try:
        with pytest.raises(decision.NativeHookDecisionError):
            finish.finalize_native_artifact_hook(
                state,  # type: ignore[arg-type]
                SimpleNamespace(harness=case.harness, json=case.json),  # type: ignore[arg-type]
                config=None,  # type: ignore[arg-type]
                payload=case.payload,
                store=SimpleNamespace(guard_home=None),  # type: ignore[arg-type]
            )
    finally:
        recorder.CURRENT.pop()
    assert receipts == []
