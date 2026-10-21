"""The resident decides the tail of the artifact hook's policy stack.

``scripts/ci/record_policy_stack_tail_vectors.py`` recorded the Python that
``evaluate_native_artifact_hook`` used to run around ``policy_stack``: whether
the native floor is skipped, whether local tool-grant evidence is required,
and the settled verdict's ``policy_composition`` trace and receipt
``approval_source``. The Rust suite replays every vector against the contract
functions; this suite sends them through the Python bridge to the real resident
(CI runs it with the packaged runtime) and checks that the bridge helpers read
the answers, and fail closed on malformed ones, instead of computing a fallback.

``approval_source`` and ``policy_composition`` are written into persisted
receipts, so the literal values are pinned here too, not only compared with the
recorder.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard import native_hook_artifact_facts as facts_bridge
from codex_plugin_scanner.guard import native_hook_route as route_module
from codex_plugin_scanner.guard.cli import commands_hook_native_pipeline as pipeline
from codex_plugin_scanner.guard.cli import commands_hook_native_policy_tail as tail
from codex_plugin_scanner.guard.cli import commands_hook_native_route as route_run
from codex_plugin_scanner.guard.cli import commands_hook_native_route_handlers as handlers
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifact_policy import artifact_fact_skip_native_floor
from codex_plugin_scanner.guard.native_hook_artifact_compose import (
    HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE,
    NativeHookComposeError,
    native_hook_compose,
)
from codex_plugin_scanner.guard.native_hook_artifact_facts import (
    HookArtifactFactsUnavailableError,
    native_hook_artifact_facts,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "rust/crates/guard-runtime/tests/fixtures"
VECTORS = FIXTURES / "policy_stack_tail_vectors.json.gz"
COMPOSE_VECTORS = FIXTURES / "hook_artifact_compose_vectors.json"
RECORDER = ROOT / "scripts/ci/record_policy_stack_tail_vectors.py"
INVALID = "native_hook_artifact_compose_payload_invalid"


def _recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_policy_stack_tail_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _vectors(kind: str | None = None) -> list[dict[str, Any]]:
    recorded = json.loads(gzip.decompress(VECTORS.read_bytes()))
    return recorded if kind is None else [vector for vector in recorded if vector["kind"] == kind]


def _stack_query() -> dict[str, Any]:
    vectors = json.loads(COMPOSE_VECTORS.read_text(encoding="utf-8"))
    return next(vector for vector in vectors if vector["name"] == "stack_defaults")["query"]


# --- The fixture is what the recorder writes ---------------------------------


def test_the_fixture_is_the_recorders_output() -> None:
    # The recorder is the frozen Python oracle: a change to the fixture that it
    # did not write, or to the oracle without re-recording, fails here.
    assert json.loads(json.dumps(_recorder().vectors(), sort_keys=True)) == _vectors()


def test_the_fixture_covers_every_decision_and_every_source() -> None:
    by_kind = {
        kind: _vectors(kind) for kind in ("skip_native_floor", "local_eligibility_required", "policy_composition")
    }
    assert all(len(vectors) >= 80 for vectors in by_kind.values())
    assert {vector["expected"] for vector in by_kind["skip_native_floor"]} == {True, False}
    assert {vector["expected"] for vector in by_kind["local_eligibility_required"]} == {True, False}
    assert {vector["expected"]["approval_source"] for vector in by_kind["policy_composition"]} == {
        "inline",
        "approval_center",
        "policy",
    }


def test_the_migrated_policy_stack_vectors_carry_the_recorded_eligibility() -> None:
    recorder = _recorder()
    stacks = [
        vector
        for vector in json.loads(COMPOSE_VECTORS.read_text(encoding="utf-8"))
        if vector["query"]["kind"] == "policy_stack"
    ]
    assert len(stacks) >= 20
    for vector in stacks:
        query = vector["query"]
        assert vector["expected"]["local_eligibility_required"] == recorder.recorded_local_eligibility_required(
            query["event_name"], query["artifact_type"], query["has_raw_command"]
        ), vector["name"]
        assert isinstance(query["runtime"]["skip_native_floor"], bool), vector["name"]
        assert isinstance(query["approval_context"]["skip_native_floor"], bool), vector["name"]


# --- The receipt fields, pinned literally ------------------------------------


def _inputs(**changes: object) -> dict[str, object]:
    inputs: dict[str, object] = {
        "current_config_action": "review",
        "current_action_override": None,
        "trusted_cli_action": "warn",
        "untrusted_payload_action": None,
        "package_policy_action": None,
        "data_flow_action": "review",
        "scanner_action": None,
        "current_composed_action": "review",
        "saved_policy_action": "allow",
        "approval_reuse_source": "saved_policy",
        "trusted_request_override": False,
        "trusted_request_override_reason": None,
        "authoritative_action": "review",
        "claude_native_approval_observed": False,
        "user_override_present": False,
    }
    inputs.update(changes)
    return inputs


_PINNED_TRACE = {
    "current_config_action": "review",
    "current_action_override": None,
    "trusted_cli_override": "warn",
    "untrusted_hook_payload_hint": None,
    "package_action": None,
    "data_flow_action": "review",
    "scanner_action": None,
    "current_composed_action": "review",
    "saved_policy_action": "allow",
    "approval_reuse_source": "saved_policy",
    "trusted_request_override": False,
    "trusted_request_override_reason": None,
    "authoritative_action": "review",
}

_PINNED_SOURCES = [
    # (changes, approval_source): the label every receipt records.
    ({}, "policy"),
    ({"authoritative_action": "allow"}, "policy"),
    ({"authoritative_action": "block"}, "policy"),
    ({"authoritative_action": "require-reapproval"}, "approval_center"),
    ({"claude_native_approval_observed": True}, "inline"),
    ({"user_override_present": True}, "inline"),
    ({"claude_native_approval_observed": True, "user_override_present": True}, "inline"),
    # An inline answer outranks the approval center.
    ({"authoritative_action": "require-reapproval", "user_override_present": True}, "inline"),
    ({"authoritative_action": "require-reapproval", "claude_native_approval_observed": True}, "inline"),
]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
@pytest.mark.parametrize(("changes", "source"), _PINNED_SOURCES)
def test_the_resident_pins_the_receipt_approval_source(
    native_approval_reuse_runtime: Path, changes: dict[str, object], source: str
) -> None:
    composed = tail.settled_policy_composition(guard_home=native_approval_reuse_runtime, **_inputs(**changes))
    assert composed.approval_source == source


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_the_resident_pins_the_receipt_policy_composition(native_approval_reuse_runtime: Path) -> None:
    composed = tail.settled_policy_composition(guard_home=native_approval_reuse_runtime, **_inputs())
    assert composed.policy_composition == _PINNED_TRACE
    assert composed.evidence == {"source": "policy_composition", **_PINNED_TRACE}


def test_a_pinned_trace_is_what_the_recorded_python_wrote() -> None:
    recorded = _recorder().recorded_policy_composition(_inputs())
    assert recorded["policy_composition"] == _PINNED_TRACE
    assert recorded["evidence"] == {"source": "policy_composition", **_PINNED_TRACE}
    for changes, source in _PINNED_SOURCES:
        assert _recorder().recorded_policy_composition(_inputs(**changes))["approval_source"] == source


# --- The bridge helpers read the resident's answer ---------------------------


def _answering(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    asked: list[tuple[str, dict[str, object]]] = []

    def fake(kind: str, fields: dict[str, object], *, guard_home: Path | None) -> dict[str, object]:
        asked.append((kind, dict(fields)))
        return answer

    monkeypatch.setattr(tail, "native_hook_compose", fake)
    return asked


def test_the_composition_is_the_residents_answer_for_the_fields_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _recorder()
    inputs = _inputs(authoritative_action="require-reapproval", trusted_request_override=True)
    answer = recorder.recorded_policy_composition(inputs)
    asked = _answering(monkeypatch, answer)
    composed = tail.settled_policy_composition(guard_home=Path("/guard-home"), **inputs)
    assert asked == [("policy_composition", inputs)]
    assert composed.policy_composition == answer["policy_composition"]
    assert composed.evidence == answer["evidence"]
    assert composed.approval_source == "approval_center"


def _good_answer() -> dict[str, Any]:
    return json.loads(json.dumps(_recorder().recorded_policy_composition(_inputs())))


def _mutated(mutate: Any) -> dict[str, Any]:
    answer = _good_answer()
    mutate(answer)
    return answer


_MALFORMED_ANSWERS = {
    "unknown source": _mutated(lambda a: a.update(approval_source="remembered")),
    "source in another case": _mutated(lambda a: a.update(approval_source="Inline")),
    "empty source": _mutated(lambda a: a.update(approval_source="")),
    "trace key dropped": _mutated(lambda a: a["policy_composition"].pop("scanner_action")),
    "trace key added": _mutated(lambda a: a["policy_composition"].update(extra=None)),
    "trace key renamed": _mutated(
        lambda a: a["policy_composition"].update(trusted_cli_action=a["policy_composition"].pop("trusted_cli_override"))
    ),
    "evidence key dropped": _mutated(lambda a: a["evidence"].pop("package_action")),
    "evidence key added": _mutated(lambda a: a["evidence"].update(extra=None)),
    "evidence without source": _mutated(lambda a: a["evidence"].pop("source")),
    "evidence from another source": _mutated(lambda a: a["evidence"].update(source="claim")),
}


@pytest.mark.parametrize("name", sorted(_MALFORMED_ANSWERS))
def test_a_malformed_composition_answer_fails_closed(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    _answering(monkeypatch, _MALFORMED_ANSWERS[name])
    with pytest.raises(NativeHookComposeError) as error:
        tail.settled_policy_composition(guard_home=Path("/guard-home"), **_inputs())
    assert error.value.code == INVALID


def test_an_unavailable_resident_gives_no_composition(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(kind: str, fields: dict[str, object], *, guard_home: Path | None) -> dict[str, object]:
        raise NativeHookComposeError("native_hook_artifact_compose_unavailable")

    monkeypatch.setattr(tail, "native_hook_compose", unavailable)
    with pytest.raises(NativeHookComposeError):
        tail.settled_policy_composition(guard_home=Path("/guard-home"), **_inputs())


def test_local_eligibility_is_the_residents_answer() -> None:
    assert tail.local_eligibility_required({"local_eligibility_required": True}, raw_command="git status") is True
    assert tail.local_eligibility_required({"local_eligibility_required": False}, raw_command="git status") is False
    assert tail.local_eligibility_required({"local_eligibility_required": False}, raw_command=None) is False


@pytest.mark.parametrize("answer", [{}, {"local_eligibility_required": None}, {"local_eligibility_required": "true"}])
def test_a_malformed_eligibility_answer_fails_closed(answer: dict[str, object]) -> None:
    with pytest.raises(NativeHookComposeError) as error:
        tail.local_eligibility_required(answer, raw_command="git status")
    assert error.value.code == INVALID


def test_a_required_eligibility_without_a_command_fails_closed() -> None:
    with pytest.raises(NativeHookComposeError) as error:
        tail.local_eligibility_required({"local_eligibility_required": True}, raw_command=None)
    assert error.value.code == INVALID


@pytest.mark.parametrize("answer", [True, False])
def test_the_floor_is_skipped_as_the_resident_says(answer: bool) -> None:
    assert artifact_fact_skip_native_floor({"skip_native_floor": answer}) is answer


@pytest.mark.parametrize(
    "facts", [{}, {"skip_native_floor": None}, {"skip_native_floor": "true"}, {"skip_native_floor": 1}]
)
def test_a_missing_or_malformed_floor_fact_fails_closed(facts: dict[str, object]) -> None:
    with pytest.raises(HookArtifactFactsUnavailableError):
        artifact_fact_skip_native_floor(facts)


def test_a_resident_without_the_tail_feature_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """An older resident omits ``skip_native_floor``; the hook must not guess it."""

    required: list[object] = []

    def refuse(**kwargs: object) -> dict[str, object]:
        required.append(kwargs.get("required_feature"))
        raise RuntimeError("required feature missing")

    monkeypatch.setattr(facts_bridge, "_resolve_digest_home", lambda _home: Path("/tmp/policy-tail-home"))
    monkeypatch.setattr(facts_bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(facts_bridge, "_resident_request", refuse)
    with pytest.raises(HookArtifactFactsUnavailableError):
        native_hook_artifact_facts([{"artifact_type": "tool_action_request", "metadata": {}}])
    assert required == [HOOK_ARTIFACT_COMPOSE_POLICY_TAIL_FEATURE]


# --- The pipeline turns a missing answer into the host outage ----------------


def test_a_policy_tail_outage_is_the_host_outage_response(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    emitted: list[dict[str, object]] = []
    monkeypatch.setattr(pipeline, "runtime_hook_event_name", lambda _payload: "PreToolUse")
    monkeypatch.setattr(pipeline, "_normalize_hook_payload", lambda payload, harness: payload)
    monkeypatch.setattr(
        pipeline,
        "prepare_native_hook_state",
        lambda *_a, payload, workspace, **_k: (payload, None, False, workspace, None, None, None, None),
    )
    monkeypatch.setattr(
        pipeline,
        "native_hook_route",
        lambda _inputs, **_k: route_module.NativeHookRoute(
            ("native_edge", "containment", "runtime_artifact", "artifact_flow", "generic_flow"), "PreToolUse"
        ),
    )
    monkeypatch.setattr(handlers, "emit_native_containment_route", lambda *_a: None)
    monkeypatch.setattr(handlers, "_runtime_action_data_flow_signals", lambda *_a, **_k: ((), None))
    monkeypatch.setattr(handlers, "_runtime_data_flow_naming", lambda **_k: None)
    monkeypatch.setattr(
        handlers,
        "ExtensionControlRuntimeSnapshot",
        SimpleNamespace(from_authority_view=lambda _view: None),
    )
    monkeypatch.setattr(handlers, "use_extension_control_snapshot", lambda _snapshot: contextlib.nullcontext())
    monkeypatch.setattr(handlers, "_hook_runtime_artifact", lambda **_k: object())

    def no_composition(*_args: object, **_kwargs: object) -> int:
        raise NativeHookComposeError(INVALID)

    def unavailable(_args: object, **kwargs: object) -> int:
        emitted.append(kwargs)
        return 0

    monkeypatch.setattr(pipeline, "_run_native_artifact_hook_flow", no_composition)
    monkeypatch.setattr(route_run, "_emit_native_unavailable", unavailable)

    class _Worker:
        def review_native_edge_decision(self, **_kwargs: object) -> dict[str, object]:
            return {"result": {"decision": "allow"}}

    class _Store:
        def read_extension_control_authority_for_registry(self, _registry: object) -> object:
            return object()

    context = SimpleNamespace(home_dir=tmp_path / "home", guard_home=tmp_path / "guard-home")
    result = pipeline.run_native_hook_pipeline(
        argparse.Namespace(harness="claude-code"),
        config=SimpleNamespace(),
        context=context,  # type: ignore[arg-type]
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "pwd"}},
        runtime_workspace=None,
        store=_Store(),  # type: ignore[arg-type]
        worker=_Worker(),  # type: ignore[arg-type]
    )
    assert result == 0
    assert [item["reason_code"] for item in emitted] == [INVALID]


# --- The real resident answers every recorded vector -------------------------


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_floor_skips(native_approval_reuse_runtime: Path) -> None:
    vectors = _vectors("skip_native_floor")
    assert len(vectors) >= 500
    answers = native_hook_artifact_facts(
        [
            {"artifact_type": vector["artifact"]["artifact_type"], "metadata": vector["artifact"]["metadata"]}
            for vector in vectors
        ],
        guard_home=native_approval_reuse_runtime,
    )
    mismatches = [
        index
        for index, (vector, facts) in enumerate(zip(vectors, answers, strict=True))
        if facts["skip_native_floor"] is not vector["expected"]
    ]
    assert mismatches == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_local_eligibility(native_approval_reuse_runtime: Path) -> None:
    base = _stack_query()
    mismatches = []
    for vector in _vectors("local_eligibility_required"):
        query = dict(base)
        query.update(vector["stack"])
        fields = {key: value for key, value in query.items() if key != "kind"}
        answer = native_hook_compose("policy_stack", fields, guard_home=native_approval_reuse_runtime)
        if answer["local_eligibility_required"] is not vector["expected"]:
            mismatches.append(vector["stack"])
    assert mismatches == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_compositions(native_approval_reuse_runtime: Path) -> None:
    vectors = _vectors("policy_composition")
    assert len(vectors) >= 1000
    # Every third vector: the Rust suite replays all of them in process, so
    # this checks the wire format and the bridge's validation across the
    # whole spread without a request per vector.
    mismatches = []
    for vector in vectors[::3]:
        answer = native_hook_compose("policy_composition", vector["inputs"], guard_home=native_approval_reuse_runtime)
        if answer != vector["expected"]:
            mismatches.append(vector["inputs"])
    assert mismatches == []
