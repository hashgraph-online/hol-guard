"""The hook pipeline dispatches the way Python's ladder did, but by the resident's route.

``scripts/ci/record_hook_route_vectors.py`` recorded the retired Python ladder of
``run_native_hook_pipeline`` with every effect stubbed, in twenty effect worlds.
The Rust suite replays the route (the plan and the event name). This suite runs
the new pipeline for every recorded case and world with the same stubs, handing
it the recorded route, and checks that it gathers the facts the route was
recorded for, runs the same effects in the same order and returns the same exit
code. It also pins the fail-closed edges: a route the resident cannot supply or
that is malformed is the host outage response, never a guess.
"""

from __future__ import annotations

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
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_hook_route as route_module
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.cli import commands_hook_native_pipeline as pipeline
from codex_plugin_scanner.guard.cli import commands_hook_native_route as route_run
from codex_plugin_scanner.guard.cli import commands_hook_native_route_handlers as handlers

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/hook_route_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_hook_route_vectors.py"
_TOOL_CALL = ("tool-call-artifact", "tool-call-hash", "tool-call-args")


def _recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_hook_route_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rec = _recorder()
VECTOR_LIST: list[dict[str, Any]] = json.loads(gzip.decompress(VECTORS.read_bytes()))
CASES = list(rec.cases())


class _Current:
    """The recorder of the run in flight, and the route the resident would send."""

    recorder: Any = None
    route: tuple[tuple[str, ...], str] = ((), "")
    facts: Any = None
    prepared: tuple[Any, ...] = ()


def _stub_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace every effect a handler runs with an entry in the recorder's trace."""
    now = _Current

    def edge_result(edge: object) -> object:
        return edge.get("result") if isinstance(edge, dict) else None

    def route(inputs: dict[str, object], **_kwargs: object) -> route_module.NativeHookRoute:
        assert inputs == now.facts
        return route_module.NativeHookRoute(*now.route)

    def unavailable(_args: object, *, event_name: object, reason_code: object, recording_only: object, **_k: object):
        return now.recorder.unavailable(event_name, reason_code, recording_only)

    def artifact_flow(_args: object, **kw: Any) -> int:
        return now.recorder.artifact_flow(
            {
                "edge_result": kw["native_edge_result"],
                "edge_receipt": kw["native_edge_receipt"],
                "config": kw["config"],
                "envelope": kw["action_envelope"],
                "managed_install": kw["managed_install"],
                "data_flow_signals": kw["data_flow_signals"],
                "runtime_artifact": kw["runtime_artifact"],
                "recording_only": kw["native_recording_only"],
                "claimed_hash": kw["_claimed_saved_allow_hash"],
                "trusted_override": kw["_claimed_trusted_request_override"],
                "approval_request_id": kw["_claimed_approval_request_id"],
                "claim_saved_approval": kw["_claim_saved_approval"],
            }
        )

    def generic(_args: object, **kw: Any) -> int:
        entry = {
            "edge_result": kw["native_edge_result"],
            "edge_receipt": kw["native_edge_receipt"],
            "config": kw["config"],
            "envelope": kw["action_envelope"],
            "claimed_hash": kw.get("_claimed_saved_allow_hash"),
            "claimed_approval": kw.get("_claimed_saved_approval"),
            "claim_saved_approval": kw["_claim_saved_approval"],
        }
        return now.recorder.generic(entry, kw.get("post_claim_revalidator"))

    patches: dict[Any, dict[str, Any]] = {
        pipeline: {
            "native_hook_route": route,
            "prepare_native_hook_state": lambda *_a, **_k: _Current.prepared,
            "_emit_native_unavailable": unavailable,
            "_normalize_hook_payload": lambda payload, *, harness: payload,
            "_run_native_artifact_hook_flow": artifact_flow,
        },
        route_run: {"_emit_native_unavailable": unavailable},
        handlers: {
            "_load_single_claude_pending_permission": lambda _store, _payload: now.recorder.pending_pair(),
            "_claude_guard_question_verdict": lambda _payload, _pending: now.recorder.question_verdict(),
            "_persist_claude_guard_question_decision": lambda *_a, **_k: now.recorder.note("question_persist"),
            "emit_native_containment_route": lambda edge, *_a: now.recorder.containment(edge_result(edge)),
            "run_native_copilot_pretool": lambda _args, **kw: now.recorder.copilot_pretool(
                kw["native_edge_result"], kw["fresh_tool_call_authority_provider"]
            ),
            "run_native_copilot_permission_request": lambda _args, *, copilot_permission_request, **kw: (
                now.recorder.copilot_permission_request(
                    copilot_permission_request,
                    kw["fresh_tool_call_authority_provider"],
                    kw["managed_install"],
                )
            ),
            "_copilot_runtime_tool_call": lambda *, config, preferred_workspace_config, **_k: (
                now.recorder.copilot_resolve(config, preferred_workspace_config)
            ),
            "_fresh_config": lambda _run: now.recorder.fresh("config"),
            "_hook_action_envelope": lambda **_k: now.recorder.fresh("envelope"),
            "_runtime_action_data_flow_signals": lambda *_a, **_k: now.recorder.data_flow(),
            "_runtime_data_flow_naming": lambda **_k: None,
            "ExtensionControlRuntimeSnapshot": SimpleNamespace(from_authority_view=lambda view: view),
            "use_extension_control_snapshot": lambda _snapshot: contextlib.nullcontext(),
            "_hook_runtime_artifact": lambda **kw: now.recorder.runtime_artifact(
                kw["data_flow_signals"], kw["data_flow_artifact"]
            ),
            "run_native_claude_permission_request": lambda _args, *, runtime_artifact, **_k: (
                now.recorder.claude_permission_request(runtime_artifact)
            ),
            "run_native_claude_permission_prompt_notification": lambda *_a, **_k: (
                now.recorder.claude_permission_prompt()
            ),
            "_discard_claude_pending_permissions": lambda _store, _payload: now.recorder.stop_discard(),
            "_now": lambda: "now",
            "_run_native_generic_payload": generic,
        },
    }
    for module, replacements in patches.items():
        for name, value in replacements.items():
            monkeypatch.setattr(module, name, value)


def _run_pipeline(case: Any, vector: dict[str, Any], world: Any) -> tuple[list[Any], object]:
    now = _Current
    now.recorder = rec.Recorder(world)
    now.facts = vector["facts"]
    now.route = (tuple(vector["route"]["plan"]), vector["route"]["event_name"])
    claim = rec.CLAIM
    prepared = (
        case.prepared,
        "managed-install",
        False,
        None,
        None,
        "envelope",
        case.copilot_stage or None,
        _TOOL_CALL if case.copilot_tool_call else None,
    )
    now.prepared = prepared
    store = SimpleNamespace(
        add_event=now.recorder.add_event,
        read_extension_control_authority_for_registry=lambda _registry: None,
    )
    worker = SimpleNamespace(
        review_native_edge_decision=lambda *, harness, default_harness, **_k: now.recorder.edge(
            harness, default_harness
        )
    )
    try:
        rc: object = pipeline.run_native_hook_pipeline(
            SimpleNamespace(harness=case.harness, json=False),  # type: ignore[arg-type]
            config="config",  # type: ignore[arg-type]
            context=SimpleNamespace(home_dir=None, guard_home=None),  # type: ignore[arg-type]
            payload=dict(case.entry),
            runtime_workspace=None,
            store=store,  # type: ignore[arg-type]
            worker=worker,  # type: ignore[arg-type]
            output_stream=None,
            _claim_saved_approval=claim["claim_saved_approval"],
            _claimed_saved_allow_hash=claim["claimed_hash"],
            _claimed_trusted_request_override=claim["trusted_override"],
            _claimed_approval_request_id=claim["approval_request_id"],
        )
    except decision.NativeHookDecisionError:
        rc = "raised"
    return json.loads(json.dumps(now.recorder.trace)), rc


def test_the_recorded_cases_are_the_vectors() -> None:
    assert len(CASES) == len(VECTOR_LIST) >= 600
    assert all(case.facts() == vector["facts"] for case, vector in zip(CASES, VECTOR_LIST, strict=True))


@pytest.mark.parametrize("world", rec.WORLDS, ids=lambda world: world.name)
def test_the_pipeline_runs_the_recorded_effects(monkeypatch: pytest.MonkeyPatch, world: Any) -> None:
    _stub_effects(monkeypatch)
    failures = []
    for case, vector in zip(CASES, VECTOR_LIST, strict=True):
        trace, rc = _run_pipeline(case, vector, world)
        expected = vector["worlds"][world.name]
        if (trace, rc) != (expected["trace"], expected["rc"]):
            failures.append(f"{vector['facts']}: {(trace, rc)!r} != {(expected['trace'], expected['rc'])!r}")
    assert failures[:3] == []


def test_the_handler_table_is_the_routes_vocabulary() -> None:
    assert set(pipeline._HANDLERS) == route_module.ROUTE_HANDLERS


def _a_case(harness: str, event: str) -> Any:
    return next(case for case in CASES if case.harness == harness and case.entry.get("hook_event_name") == event)


def test_no_route_is_the_outage_response_and_no_handler_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_effects(monkeypatch)
    case = _a_case("codex", "PreToolUse")
    vector = VECTOR_LIST[CASES.index(case)]

    def outage(inputs: object, **_kwargs: object) -> None:
        raise decision.NativeHookDecisionError("native_hook_decision_unavailable")

    monkeypatch.setattr(pipeline, "native_hook_route", outage)
    trace, rc = _run_pipeline(case, vector, rec.WORLDS[0])
    # The route failed before the world's effects: only the outage was answered.
    assert trace == [["unavailable", "PreToolUse", "native_hook_decision_unavailable", False]]
    assert rc == rec.RC["unavailable"]


def test_a_plan_that_never_answers_is_an_outage_not_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_effects(monkeypatch)
    case = _a_case("codex", "PreToolUse")
    vector = {**VECTOR_LIST[CASES.index(case)], "route": {"plan": ["native_edge"], "event_name": "PreToolUse"}}
    trace, rc = _run_pipeline(case, vector, rec.WORLDS[0])
    assert trace[-1] == ["unavailable", "PreToolUse", route_run.ROUTE_UNANSWERED, True]
    assert rc == rec.RC["unavailable"]


def test_a_copilot_pretool_route_without_a_tool_call_is_an_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_effects(monkeypatch)
    case = next(case for case in CASES if case.harness == "copilot" and case.copilot_tool_call)
    vector = VECTOR_LIST[CASES.index(case)]
    case = rec.Case(case.harness, case.entry, case.prepared, case.copilot_stage, False)
    vector = {**vector, "facts": {**vector["facts"], "copilot_tool_call_present": False}}
    vector = {**vector, "route": {"plan": ["copilot_pretool"], "event_name": vector["route"]["event_name"]}}
    trace, rc = _run_pipeline(case, vector, rec.WORLDS[0])
    assert trace == [["unavailable", vector["route"]["event_name"], decision._INVALID, False]]
    assert rc == rec.RC["unavailable"]


@pytest.mark.parametrize("harness", ("devin", "zcode"))
def test_a_devin_or_zcode_permission_request_gets_no_decision(monkeypatch: pytest.MonkeyPatch, harness: str) -> None:
    """Empty output and exit 0: the harness shows its own approval prompt."""
    _stub_effects(monkeypatch)
    cases = [
        (case, vector)
        for case, vector in zip(CASES, VECTOR_LIST, strict=True)
        if vector["route"]["plan"] == ["passthrough"] and case.harness == harness
    ]
    assert len(cases) >= 10
    for case, vector in cases:
        assert vector["facts"]["invoked_event"] == "PermissionRequest"
        # No edge call, no control-plane bridge: nothing but the answer.
        for world in rec.WORLDS:
            assert _run_pipeline(case, vector, world) == ([], 0)


def test_every_other_permission_request_keeps_its_review_route() -> None:
    for vector in VECTOR_LIST:
        facts = vector["facts"]
        if facts["invoked_event"] == "PermissionRequest" and facts["canonical_harness"] not in {"devin", "zcode"}:
            assert vector["route"]["plan"] != ["passthrough"]


_FACTS = {
    "harness": "codex",
    "canonical_harness": "codex",
    "invoked_event": "PreToolUse",
    "hook_event": "PreToolUse",
    "runtime_event": "PreToolUse",
    "notification_type": "",
    "copilot_stage": "",
    "copilot_tool_call_present": False,
    "copilot_permission_request": False,
}
_ROUTE = {
    "kind": "hook_route",
    "plan": ["native_edge", "edge_unavailable", "containment", "runtime_artifact", "artifact_flow", "generic_flow"],
    "event_name": "PreToolUse",
}


def _resident_answering(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, Any],
    asked: list[str],
    timeouts: list[float] | None = None,
) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", route_module.HOOK_DECISION_HOOK_ROUTE_FEATURE}),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(
        *, request: dict[str, Any], required_feature: str, timeout_seconds: float, **_kwargs: object
    ) -> dict[str, Any]:
        asked.append(required_feature)
        if timeouts is not None:
            timeouts.append(timeout_seconds)
        assert request["query"] == {"kind": "hook_route", "inputs": _FACTS}
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(route_module, "_resident_request", transport)


def test_a_bound_route_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _ROUTE, asked)
    answer = route_module.native_hook_route(_FACTS)
    assert answer == route_module.NativeHookRoute(tuple(_ROUTE["plan"]), "PreToolUse")  # type: ignore[arg-type]
    assert asked == [route_module.HOOK_DECISION_HOOK_ROUTE_FEATURE]


@pytest.mark.parametrize(
    ("budget", "waited"), [(None, 5.0), (30.0, 5.0), (0.7, 0.7)], ids=("no-hint", "roomy", "tight")
)
def test_the_route_never_waits_past_what_the_harness_allows(
    monkeypatch: pytest.MonkeyPatch, budget: float | None, waited: float
) -> None:
    timeouts: list[float] = []
    _resident_answering(monkeypatch, _ROUTE, [], timeouts)
    route_module.native_hook_route(_FACTS, budget_seconds=budget)
    assert timeouts == [waited]


@pytest.mark.parametrize("budget", (0.0, -1.5))
def test_an_exhausted_budget_is_an_outage_without_asking_the_resident(
    monkeypatch: pytest.MonkeyPatch, budget: float
) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _ROUTE, asked)
    with pytest.raises(decision.NativeHookDecisionError):
        route_module.native_hook_route(_FACTS, budget_seconds=budget)
    assert asked == []


def test_the_budget_is_what_remains_of_the_timing_anchored_at_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(route_run.time, "monotonic", lambda: 100.0)
    assert route_run.route_budget_seconds({"deadline": 102.5}) == 2.5
    assert route_run.route_budget_seconds({"deadline": 99.0}) == -1.0
    assert route_run.route_budget_seconds({"edge_budget_seconds": 3.0}) == 3.0
    # The explicit budget is a duration sampled at entry: preparation has spent some of it.
    assert route_run.route_budget_seconds({"edge_budget_seconds": 3.0}, started_at=98.5) == 1.5
    assert route_run.route_budget_seconds({"edge_budget_seconds": 3.0}, started_at=100.0) == 3.0
    assert route_run.route_budget_seconds({"edge_budget_seconds": 3.0}, started_at=101.0) == 3.0
    assert route_run.route_budget_seconds({"deadline": 102.5}, started_at=90.0) == 2.5
    assert route_run.route_budget_seconds({}) is None


def test_the_pipeline_hands_the_route_the_remaining_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_effects(monkeypatch)
    case = _a_case("codex", "PreToolUse")
    vector = VECTOR_LIST[CASES.index(case)]
    budgets: list[object] = []

    def route(inputs: object, **kwargs: object) -> route_module.NativeHookRoute:
        budgets.append(kwargs["budget_seconds"])
        return route_module.NativeHookRoute(*_Current.route)

    monkeypatch.setattr(pipeline, "native_hook_route", route)
    monkeypatch.setattr(pipeline, "route_budget_seconds", lambda timing, **_kwargs: 1.25)
    _run_pipeline(case, vector, rec.WORLDS[0])
    assert budgets == [1.25]


@pytest.mark.parametrize("event", ("PermissionRequest", "Stop", "Notification"))
def test_a_claude_control_event_without_a_route_is_the_outage_response(
    monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    """With no route there is no handler: not Claude's own dialog, not a Stop discard."""
    _stub_effects(monkeypatch)
    case = _a_case("claude-code", event)
    vector = VECTOR_LIST[CASES.index(case)]

    def outage(inputs: object, **_kwargs: object) -> None:
        raise decision.NativeHookDecisionError("native_hook_decision_unavailable")

    monkeypatch.setattr(pipeline, "native_hook_route", outage)
    trace, rc = _run_pipeline(case, vector, rec.WORLDS[0])
    assert [entry[:1] for entry in trace] == [["unavailable"]]
    assert rc == rec.RC["unavailable"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"plan": []},
        {"plan": "generic_flow"},
        {"plan": ["generic_flow", "native_edge"]},
        {"plan": ["native_edge", "teleport", "generic_flow"]},
        {"plan": ["native_edge", "native_edge", "generic_flow"]},
        {"plan": ["native_edge", "containment"]},
        {"plan": ["copilot_pretool", "generic_flow"]},
        {"plan": ["passthrough", "generic_flow"]},
        {"plan": ["native_edge", 7, "generic_flow"]},
        {"event_name": ""},
        {"event_name": None},
        {"extra": True},
    ],
)
def test_a_malformed_route_fails_closed(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_answering(monkeypatch, {**_ROUTE, **overrides}, [])
    with pytest.raises(decision.NativeHookDecisionError):
        route_module.native_hook_route(_FACTS)


def test_incomplete_inputs_are_refused_before_the_resident_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    _resident_answering(monkeypatch, _ROUTE, asked)
    for broken in (
        {key: value for key, value in _FACTS.items() if key != "invoked_event"},
        {**_FACTS, "extra": "x"},
        {**_FACTS, "copilot_tool_call_present": "no"},
        {**_FACTS, "harness": None},
    ):
        with pytest.raises(decision.NativeHookDecisionError):
            route_module.native_hook_route(broken)
    assert asked == []


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_routes() -> None:
    failures: list[str] = []
    for vector in VECTOR_LIST[::11]:
        answer = route_module.native_hook_route(vector["facts"])
        expected = (tuple(vector["route"]["plan"]), vector["route"]["event_name"])
        if tuple(answer) != expected:
            failures.append(f"{vector['facts']}: {tuple(answer)!r} != {expected!r}")
    assert failures == []
