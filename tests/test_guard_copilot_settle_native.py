"""Copilot tool-call settlement is answered by the native runtime.

The vectors were recorded from the retired Python settle logic. The Rust suite
replays them against the op; this suite replays them through the real
resident and the Python transport, and checks the Copilot response shaping.
"""

from __future__ import annotations

import gzip
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.cli import commands_hook_native_copilot as copilot

_VECTORS: list[dict[str, Any]] = json.loads(
    gzip.decompress(
        (
            Path(__file__).resolve().parent.parent
            / "rust/crates/guard-runtime/tests/fixtures/hook_copilot_settle_vectors.json.gz"
        ).read_bytes()
    )
)["vectors"]
_PLAN_KEYS = ("effects", "exit_code", "approval_reuse", "scanner_evidence")
_INPUTS = {key: value for key, value in _VECTORS[0]["inputs"].items() if key != "acked_recording_only"}


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_matches_recorded_vectors() -> None:
    failures: list[str] = []
    for vector in _VECTORS:
        inputs = dict(vector["inputs"])
        acked = inputs.pop("acked_recording_only", None)
        asked: list[bool] = []

        def acked_fact(acked: object = acked, asked: list[bool] = asked) -> bool:
            asked.append(True)
            return bool(acked)

        plan = decision.native_copilot_settle(inputs, acked_fact)
        if bool(asked) != vector["needs_acked_snapshot"]:
            failures.append(f"{vector['name']}: acked snapshot asked={bool(asked)}")
        failures.extend(f"{vector['name']}: {key}" for key in _PLAN_KEYS if plan[key] != vector["expected"][key])
    assert failures == []


def test_pretool_response_matches_recorded_documents() -> None:
    checked = 0
    for vector in _VECTORS:
        effects = [effect for effect in vector["expected"]["effects"] if effect["effect"] == "pretool_response"]
        if not effects:
            continue
        stream = io.StringIO()
        copilot._emit_copilot_pretool_response(
            SimpleNamespace(json=vector["json_requested"]),
            permission_decision=effects[0]["permission_decision"],
            reason=effects[0]["reason"],
            approval_reuse=vector["expected"]["approval_reuse"],
            scanner_evidence=tuple(vector["expected"]["scanner_evidence"]),
            output_stream=stream,
        )
        assert [json.loads(line) for line in stream.getvalue().splitlines()] == vector["pretool_documents"]
        checked += 1
    assert checked > 100


def _resident_returning(monkeypatch: pytest.MonkeyPatch, payloads: list[dict[str, Any]]) -> None:
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def reply(*, request: dict[str, Any], **_kwargs: object) -> dict[str, Any]:
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payloads.pop(0),
        }

    monkeypatch.setattr(decision, "_resident_request", reply)


_ASK = {"kind": "copilot_settle", "needs_facts": ["acked_recording_only"], "plan": None}
_PLAN = {
    "policy_action": "allow",
    "approval_reuse": None,
    "scanner_evidence": [],
    "effects": [{"effect": "usage", "policy_action": "allow"}],
    "exit_code": 0,
}

_ACTIVITY = {
    "effect": "activity",
    "event": "preToolUse",
    "policy_action": "allow",
    "prompted": False,
    "reuse_status": "not-applicable",
}
_RECEIPT = {"effect": "receipt", "verdict": "allow", "decision_source": "policy", "policy_action": "allow"}


@pytest.mark.parametrize(
    "payloads",
    [
        [{"kind": "copilot_settle", "needs_facts": ["other"], "plan": None}],
        [_ASK, _ASK],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "exit_code": "0"}}],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "effects": [{"effect": "shell"}]}}],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "effects": [{"effect": "usage"}]}}],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "policy_action": "bogus"}}],
        [{"kind": "copilot_settle", "needs_facts": None, "plan": _PLAN}],
        [{"kind": "copilot_settle", "needs_facts": "", "plan": _PLAN}],
        [
            {
                "kind": "copilot_settle",
                "needs_facts": [],
                "plan": {**_PLAN, "effects": [_ACTIVITY | {"reuse_status": "x"}]},
            }
        ],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "effects": [_ACTIVITY | {"event": "x"}]}}],
        [{"kind": "copilot_settle", "needs_facts": [], "plan": {**_PLAN, "effects": [_RECEIPT | {"verdict": "x"}]}}],
        [
            {
                "kind": "copilot_settle",
                "needs_facts": [],
                "plan": {**_PLAN, "effects": [_RECEIPT | {"policy_action": "x"}]},
            }
        ],
    ],
)
def test_malformed_answers_raise(monkeypatch: pytest.MonkeyPatch, payloads: list[dict[str, Any]]) -> None:
    _resident_returning(monkeypatch, payloads)
    with pytest.raises(decision.NativeHookDecisionError):
        decision.native_copilot_settle(_INPUTS, lambda: False)


def test_acked_fact_is_asked_once(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, [_ASK, {"kind": "copilot_settle", "needs_facts": [], "plan": _PLAN}])
    calls: list[bool] = []
    assert decision.native_copilot_settle(_INPUTS, lambda: calls.append(True) or True) == _PLAN
    assert calls == [True]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_large_tool_arguments_settle() -> None:
    # Tool arguments above the 256 KiB contained-execution budget still settle.
    inputs = {**_INPUTS, "artifact": {**_INPUTS["artifact"], "launch_target": "x" * (300 * 1024)}}
    plan = decision.native_copilot_settle(inputs, lambda: False)
    assert plan["effects"]


def _sink_calls(effects: list[dict[str, Any]]) -> list[tuple[object, ...]]:
    calls: list[tuple[object, ...]] = []
    receipt_id = ""
    for effect in effects:
        kind = effect["effect"]
        if kind == "receipt":
            receipt_id = f"receipt-{effect['verdict']}"
            calls.append((effect["verdict"], effect["decision_source"], effect["policy_action"]))
        elif kind == "activity":
            calls.append(
                (kind, effect["event"], effect["policy_action"], receipt_id, effect["prompted"], effect["reuse_status"])
            )
        elif kind == "observe_queue":
            calls.append((kind, effect["executable_action"], effect["observed_policy_action"]))
        elif kind in {"usage", "pretool_response"}:
            calls.append((kind, effect.get("policy_action", effect.get("permission_decision"))))
        elif kind == "permission_response":
            calls.append((kind, effect["behavior"], effect["message"], effect["interrupt"]))
        else:
            calls.append((kind,))
    return calls


def test_transport_runs_recorded_effects_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import approvals, blocked_request_mode

    calls: list[tuple[object, ...]] = []
    plans: list[dict[str, Any]] = []

    def receipt(verdict: str) -> Any:
        def record(**kwargs: Any) -> SimpleNamespace:
            calls.append((verdict, kwargs["decision_source"], kwargs["policy_action"]))
            return SimpleNamespace(receipt_id=f"receipt-{verdict}")

        return record

    def activity(**kwargs: Any) -> None:
        reuse = kwargs["approval_reuse_status"].value
        calls.append(
            ("activity", kwargs["event"], kwargs["policy_action"], kwargs["receipt_id"], kwargs["prompted"], reuse)
        )

    stubs: dict[str, Any] = {
        "evaluate_tool_call": lambda **_kwargs: SimpleNamespace(
            post_claim_authority=None,
            signals=(),
            risk_categories=(),
            summary="summary",
            **{
                key: None
                for key in (
                    "action",
                    "source",
                    "normalization_reason_code",
                    "original_action",
                    "approval_reuse_status",
                    "approval_reuse_reason_code",
                    "current_action",
                    "saved_action",
                )
            },
        ),
        "native_copilot_settle": lambda *_args, **_kwargs: plans[0],
        "harness_is_recording_only": lambda *_args: False,
        "harness_posture_override": lambda *_args: None,
        "_action_envelope_json": lambda _envelope: None,
        "_now": lambda: "now",
        "_runtime_detection": lambda *_args: None,
        "queue_observe_mode_request": lambda **kwargs: calls.append(
            ("observe_queue", kwargs["executable_action"], kwargs["observed_policy_action"])
        ),
        "allow_tool_call": receipt("allow"),
        "block_tool_call": receipt("block"),
        "record_pre_hook_command_activity_best_effort": activity,
        "_record_harness_usage_for_hook": lambda **kwargs: calls.append(("usage", kwargs["policy_action"])),
        "_emit_copilot_permission_request_response": lambda **kwargs: calls.append(
            ("permission_response", kwargs["behavior"], kwargs["message"], kwargs["interrupt"])
        ),
        "_queue_copilot_approval": lambda *_args, **kwargs: calls.append(("queue_approval",)),
    }
    for name, stub in stubs.items():
        monkeypatch.setattr(copilot, name, stub)
    monkeypatch.setattr(approvals, "record_unprompted_review", lambda **_kwargs: calls.append(("silent_review",)))
    monkeypatch.setattr(blocked_request_mode, "asks_for_approval", lambda _config: True)
    emit_pretool = copilot._emit_copilot_pretool_response

    def pretool(*args: Any, **kwargs: Any) -> None:
        calls.append(("pretool_response", kwargs["permission_decision"]))
        emit_pretool(*args, **kwargs)

    monkeypatch.setattr(copilot, "_emit_copilot_pretool_response", pretool)
    for vector in _VECTORS:
        calls.clear()
        plans[:] = [{**vector["expected"], "policy_action": "allow"}]
        facts = vector["inputs"]["artifact"]
        artifact = SimpleNamespace(
            artifact_id=facts["artifact_id"],
            name=facts["artifact_name"],
            artifact_type=facts["artifact_type"],
            source_scope=facts["source_scope"],
            config_path=facts["config_path"],
            command=facts["launch_target"],
        )
        stream = io.StringIO()
        common: dict[str, Any] = {
            "action_envelope": None,
            "config": SimpleNamespace(receipt_redaction_level="standard"),
            "context": SimpleNamespace(guard_home=Path("/tmp/copilot-home"), home_dir=Path("/tmp/copilot-user")),
            "output_stream": stream,
            "payload": {},
            "runtime_workspace": None,
            "store": SimpleNamespace(guard_home=Path("/tmp/copilot-home")),
        }
        args = SimpleNamespace(harness="copilot", json=vector["json_requested"])
        tool_call = (artifact, facts["artifact_hash"], None)
        if vector["inputs"]["stage"] == "pre_tool_use":
            exit_code = copilot.run_native_copilot_pretool(
                args, copilot_hook_stage="pretooluse", copilot_runtime_tool_call=tool_call, **common
            )
            documents = [json.loads(line) for line in stream.getvalue().splitlines()]
            assert documents == vector["pretool_documents"], vector["name"]
        else:
            exit_code = copilot.run_native_copilot_permission_request(
                args,
                copilot_permission_request=tool_call,
                guard_home=Path("/tmp/copilot-home"),
                managed_install=None,
                **common,
            )
        assert calls == _sink_calls(vector["expected"]["effects"]), vector["name"]
        assert exit_code == vector["expected"]["exit_code"], vector["name"]


def test_unknown_effect_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = {**_PLAN, "effects": [{"effect": "queue_approval"}]}
    monkeypatch.setattr(
        copilot,
        "evaluate_tool_call",
        lambda **_kwargs: SimpleNamespace(
            post_claim_authority=None,
            signals=(),
            risk_categories=(),
            summary="",
            action=None,
            source=None,
            normalization_reason_code=None,
            original_action=None,
            approval_reuse_status=None,
            approval_reuse_reason_code=None,
            current_action=None,
            saved_action=None,
        ),
    )
    monkeypatch.setattr(copilot, "native_copilot_settle", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(copilot, "harness_is_recording_only", lambda *_args: False)
    monkeypatch.setattr(copilot, "harness_posture_override", lambda *_args: None)
    monkeypatch.setattr(copilot, "_action_envelope_json", lambda _envelope: None)
    artifact = SimpleNamespace(
        artifact_id="a", name="n", artifact_type="tool_call", source_scope="project", config_path=None, command=None
    )
    with pytest.raises(decision.NativeHookDecisionError):
        # The pre-tool stage has no approval queue, so a queue effect is malformed.
        copilot.run_native_copilot_pretool(
            SimpleNamespace(harness="copilot", json=False),
            action_envelope=None,
            config=SimpleNamespace(receipt_redaction_level="standard"),
            context=SimpleNamespace(guard_home=Path("/tmp/copilot-home"), home_dir=None),
            copilot_hook_stage="pretooluse",
            copilot_runtime_tool_call=(artifact, "sha256:a", None),
            payload={},
            runtime_workspace=None,
            store=SimpleNamespace(guard_home=Path("/tmp/copilot-home")),
        )
