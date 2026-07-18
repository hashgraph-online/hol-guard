"""Regression coverage for one display, persistence, and launch decision."""

from __future__ import annotations

import copy
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessAdapter, HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import service as consumer_service
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.composition_rules import compose_action_from_signals
from codex_plugin_scanner.guard.runtime.decisions import (
    AUTHORITATIVE_DECISION_INCONSISTENT,
    AuthoritativeGuardDecision,
    authoritative_decision_from_artifact,
    build_authoritative_decision,
    evaluation_authority_error,
    rebuild_artifact_authority,
)
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.types import GuardVerdict, GuardVerdictAction


def _artifact(tmp_path: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:project:authoritative-tool",
        name="authoritative-tool",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
        command=sys.executable,
        args=("-c", "pass"),
        transport="stdio",
    )


def _detection(artifact: GuardArtifact | None) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,) if artifact is not None else (),
        artifacts=(artifact,) if artifact is not None else (),
    )


def _scoring_verdict(action: GuardVerdictAction) -> GuardVerdict:
    return GuardVerdict(
        action=action,
        severity=1,
        confidence=0.9,
        reasons=(f"scanner recommends {action}",),
        recommended_next_actions=(),
        suppressible=True,
        review_priority="low",
        evidence_sources=("artifact",),
        provenance_state="none",
    )


def _runtime_signal(
    *,
    signal_id: str,
    category: str,
    severity: str,
    confidence: str,
) -> RiskSignalV2:
    return RiskSignalV2.from_dict(
        {
            "signal_id": signal_id,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "detector": "authoritative-decision-test",
            "title": "Runtime signal",
            "plain_reason": "Runtime detector found a policy-relevant signal.",
            "technical_detail": None,
            "evidence_ref": None,
            "redaction_level": "summary",
            "false_positive_hint": None,
            "advisory_id": None,
        }
    )


def _assert_authoritative_projection(
    item: dict[str, object],
    *,
    action: str,
    scoring_action: str,
) -> None:
    decision_payload = item["authoritative_decision"]
    assert isinstance(decision_payload, dict)
    decision = AuthoritativeGuardDecision.from_dict(decision_payload)
    assert decision.action == action
    assert item["policy_action"] == action
    assert item["verdict_action"] == action
    assert item["policy_composition"]["final_action"] == action  # type: ignore[index]
    assert item["decision_v2_json"] == decision.decision_v2.to_dict()
    scoring = item["scoring_recommendation"]
    assert isinstance(scoring, dict)
    assert scoring["non_authoritative"] is True
    assert scoring["action"] == scoring_action
    composition = item["policy_composition"]
    assert isinstance(composition, dict)
    assert composition["raw_scoring_recommendation"] == scoring_action
    assert composition["scoring_recommendation_non_authoritative"] is True
    assert "scoring_recommendation" not in composition
    assert authoritative_decision_from_artifact(item) == decision


def test_evaluate_detection_does_not_serialize_scoring_allow_as_the_enforced_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        default_action="block",
        changed_hash_action="block",
    )
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )

    output = consumer_service.evaluate_detection(
        _detection(artifact),
        store,
        config,
        default_action="block",
        persist=True,
    )
    item = output["artifacts"][0]

    _assert_authoritative_projection(item, action="block", scoring_action="allow")
    assert output["blocked"] is True
    assert store.list_receipts(harness="codex")[0]["policy_decision"] == "block"
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert inventory is not None
    assert inventory["last_policy_action"] == "block"
    assert inventory["last_approved_at"] is None
    assert store.get_snapshot("codex", artifact.artifact_id) is None


def test_removed_artifact_uses_the_authoritative_action_instead_of_a_hard_coded_warn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        default_action="allow",
        changed_hash_action="allow",
    )
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )
    consumer_service.evaluate_detection(
        _detection(artifact),
        store,
        config,
        default_action="allow",
        persist=True,
    )

    output = consumer_service.evaluate_detection(
        _detection(None),
        store,
        config,
        default_action="allow",
        persist=True,
    )
    item = output["artifacts"][0]

    assert item["removed"] is True
    _assert_authoritative_projection(item, action="allow", scoring_action="warn")
    assert item["policy_composition"]["scanner_action"] is None
    assert "paused" not in str(item["why_now"]).lower()
    assert output["blocked"] is False
    assert store.list_receipts(harness="codex")[0]["policy_decision"] == "allow"
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert inventory is not None
    assert inventory["last_policy_action"] == "allow"


def test_history_counts_every_non_executable_install_action_but_not_warn(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact_id = "package:npm:exact-actions"
    for index, action in enumerate(
        ("block", "review", "require-reapproval", "sandbox-required", "warn")
    ):
        store.add_event(
            f"install_time_{action}",
            {
                "artifact_id": artifact_id,
                "artifact_name": "exact-actions",
                "policy_action": action,
            },
            f"2026-07-18T00:00:0{index}Z",
        )

    history = consumer_service.build_history_context(store, "guard-cli", artifact_id, None)

    assert history.prior_incidents == 4


@pytest.mark.parametrize("guard_action", ["block", "unknown-action"])
def test_legacy_artifact_rejects_contradictory_or_unknown_exact_guard_action(
    guard_action: str,
) -> None:
    decision = build_authoritative_decision(
        "allow",
        reason="legacy-allow",
        composition_trace={"final_action": "allow"},
        authority_finalized=True,
    )
    decision_v2 = decision.decision_v2.to_dict()
    decision_v2["guard_action"] = guard_action

    with pytest.raises(ValueError, match=r"(?:guard_action|known Guard action)"):
        authoritative_decision_from_artifact(
            {
                "policy_action": "allow",
                "decision_v2_json": decision_v2,
            }
        )


@pytest.mark.parametrize(
    "hidden_alias",
    [
        "action",
        "final_action",
        "terminal_action",
        "guard_action",
        "resolved_policy_action",
        "observed_policy_action",
        "preExecutionResult",
    ],
)
def test_launch_boundary_rejects_hidden_artifact_action_aliases(hidden_alias: str) -> None:
    decision = build_authoritative_decision(
        "allow",
        reason="policy-allow",
        composition_trace={"final_action": "allow"},
        authority_finalized=True,
    )
    item = {
        "artifact_id": "codex:project:hidden-alias",
        **decision.to_artifact_projection(),
        hidden_alias: "block",
    }

    assert (
        evaluation_authority_error(
            {"artifacts": [item], "blocked": False},
            require_launch_permitted=True,
        )
        == AUTHORITATIVE_DECISION_INCONSISTENT
    )


def test_authoritative_schema_rejects_extra_top_level_or_enforcement_fields() -> None:
    decision = build_authoritative_decision(
        "allow",
        reason="policy-allow",
        composition_trace={"final_action": "allow"},
        authority_finalized=True,
    )
    extra_top_level = decision.to_dict()
    extra_top_level["diagnostic"] = {"policy_action": "block"}
    extra_enforcement = decision.to_dict()
    enforcement = dict(extra_enforcement["enforcement"])  # type: ignore[arg-type]
    enforcement["policy_action"] = "block"
    extra_enforcement["enforcement"] = enforcement

    with pytest.raises(ValueError, match="authoritative_decision fields must match schema"):
        AuthoritativeGuardDecision.from_dict(extra_top_level)
    with pytest.raises(ValueError, match="enforcement fields must match schema"):
        AuthoritativeGuardDecision.from_dict(extra_enforcement)


def test_launch_boundary_rejects_hidden_action_alias_inside_action_envelope() -> None:
    decision = build_authoritative_decision(
        "allow",
        reason="policy-allow",
        composition_trace={"final_action": "allow"},
        authority_finalized=True,
    )
    item = {
        "artifact_id": "codex:project:hidden-envelope-alias",
        **decision.to_artifact_projection(),
        "action_envelope_json": {
            "pre_execution_result": "allow",
            "final_action": "block",
        },
    }

    assert (
        evaluation_authority_error(
            {"artifacts": [item], "blocked": False},
            require_launch_permitted=True,
        )
        == AUTHORITATIVE_DECISION_INCONSISTENT
    )


@pytest.mark.parametrize(
    "bad_item",
    [
        {
            "artifact_id": "codex:project:authoritative-tool",
            "policy_action": "block",
            "decision_v2_json": {"action": "block", "reason": "fixture-block"},
            "policy_composition": {"final_action": "block"},
            "verdict_action": "allow",
        },
        {
            "artifact_id": "codex:project:authoritative-tool",
            "policy_action": "allow",
            "decision_v2_json": {"action": "allow", "reason": "legacy-allow"},
            "policy_composition": {"final_action": "allow"},
            "verdict_action": "allow",
        },
    ],
    ids=["contradictory-alias", "missing-authoritative-schema"],
)
def test_guard_run_fails_closed_before_launch_for_invalid_authority_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad_item: dict[str, object],
) -> None:
    artifact = _artifact(tmp_path)
    contradictory = {
        "harness": "codex",
        "artifacts": [bad_item],
        "blocked": False,
        "receipts_recorded": 0,
    }

    class _LaunchAdapter(HarnessAdapter):
        def launch_command(self, _context: HarnessContext, _args: list[str]) -> list[str]:
            return [sys.executable, "-c", "pass"]

        def prepare_launch_environment(
            self,
            _context: HarnessContext,
            inherited: dict[str, str],
        ) -> dict[str, str]:
            return dict(inherited)

    monkeypatch.setattr(guard_runner, "detect_harness", lambda *_args, **_kwargs: _detection(artifact))
    monkeypatch.setattr(
        guard_runner,
        "evaluate_detection",
        lambda *_args, **_kwargs: copy.deepcopy(contradictory),
    )
    monkeypatch.setattr(guard_runner, "get_adapter", lambda _harness: _LaunchAdapter())
    monkeypatch.setattr(
        guard_runner.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("contradictory decision state must not reach the launch sink"),
    )

    result = guard_runner.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        GuardStore(tmp_path / "guard-home"),
        GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
            default_action="allow",
            changed_hash_action="allow",
        ),
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["authority_error"] == AUTHORITATIVE_DECISION_INCONSISTENT
    assert result["launch_command"] == []
    assert "refused to launch" in result["authority_error_message"]


def test_unanimous_allow_launches_without_a_new_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    (tmp_path / "workspace").mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        default_action="allow",
        changed_hash_action="allow",
    )
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )

    class _LaunchAdapter(HarnessAdapter):
        def launch_command(self, _context: HarnessContext, _args: list[str]) -> list[str]:
            return [sys.executable, "-c", "pass"]

    launches: list[list[str]] = []
    monkeypatch.setattr(guard_runner, "detect_harness", lambda *_args, **_kwargs: _detection(artifact))
    monkeypatch.setattr(guard_runner, "get_adapter", lambda _harness: _LaunchAdapter())
    monkeypatch.setattr(
        guard_runner.subprocess,
        "run",
        lambda command, **_kwargs: launches.append(command) or SimpleNamespace(returncode=0),
    )

    output = guard_runner.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
        default_action="allow",
    )

    assert output["blocked"] is False
    assert output["launched"] is True
    assert len(launches) == 1
    _assert_authoritative_projection(
        output["artifacts"][0],
        action="allow",
        scoring_action="allow",
    )


def test_exact_allow_once_keeps_scoring_recommendation_diagnostic_at_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    (tmp_path / "workspace").mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        default_action="allow",
        changed_hash_action="allow",
    )
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("require_reapproval"),
    )

    class _LaunchAdapter(HarnessAdapter):
        def launch_command(self, _context: HarnessContext, _args: list[str]) -> list[str]:
            return [sys.executable, "-c", "pass"]

    launches: list[list[str]] = []
    monkeypatch.setattr(guard_runner, "detect_harness", lambda *_args, **_kwargs: _detection(artifact))
    monkeypatch.setattr(guard_runner, "get_adapter", lambda _harness: _LaunchAdapter())
    monkeypatch.setattr(
        guard_runner.subprocess,
        "run",
        lambda command, **_kwargs: launches.append(command) or SimpleNamespace(returncode=0),
    )

    def _allow_once(
        _detection_value: HarnessDetection,
        evaluation: dict[str, object],
    ) -> dict[str, object]:
        resolved = copy.deepcopy(evaluation)
        item = resolved["artifacts"][0]  # type: ignore[index]
        item["policy_action"] = "allow"  # type: ignore[index]
        item["user_override"] = "allow-once"  # type: ignore[index]
        resolved["blocked"] = False
        return resolved

    output = guard_runner.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
        default_action="allow",
        interactive_resolver=_allow_once,
    )

    assert output["blocked"] is False
    assert output["launched"] is True
    assert len(launches) == 1
    _assert_authoritative_projection(
        output["artifacts"][0],
        action="allow",
        scoring_action="require_reapproval",
    )
    assert store.list_receipts(harness="codex")[0]["policy_decision"] == "allow"


@pytest.mark.parametrize(
    ("policy_action", "scoring_action", "expected_action"),
    [
        ("block", "warn", "block"),
        ("sandbox-required", "allow", "sandbox-required"),
        ("allow", "block", "block"),
    ],
)
def test_policy_and_scoring_pairs_have_one_final_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy_action: str,
    scoring_action: GuardVerdictAction,
    expected_action: str,
) -> None:
    artifact = _artifact(tmp_path)
    store = GuardStore(tmp_path / f"guard-home-{policy_action}")
    config = GuardConfig(
        guard_home=tmp_path / f"guard-home-{policy_action}",
        workspace=tmp_path / "workspace",
        default_action=policy_action,
        changed_hash_action=policy_action,
    )
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict(scoring_action),
    )

    output = consumer_service.evaluate_detection(
        _detection(artifact),
        store,
        config,
        default_action=policy_action,
        persist=False,
    )

    assert output["blocked"] is (expected_action not in {"allow", "warn"})
    _assert_authoritative_projection(
        output["artifacts"][0],
        action=expected_action,
        scoring_action=scoring_action,
    )


def test_first_unchanged_changed_and_persisted_surfaces_share_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        default_action="allow",
        changed_hash_action="allow",
    )
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )

    first = consumer_service.evaluate_detection(
        _detection(artifact), store, config, default_action="allow", persist=True
    )
    unchanged = consumer_service.evaluate_detection(
        _detection(artifact), store, config, default_action="allow", persist=False
    )
    changed_artifact = replace(artifact, args=("-c", "print('changed')"))
    changed = consumer_service.evaluate_detection(
        _detection(changed_artifact), store, config, default_action="allow", persist=True
    )

    assert first["artifacts"][0]["changed_fields"] == ["first_seen"]
    assert unchanged["artifacts"][0]["changed"] is False
    assert changed["artifacts"][0]["changed"] is True
    for output in (first, unchanged, changed):
        _assert_authoritative_projection(output["artifacts"][0], action="allow", scoring_action="allow")
    snapshot = store.get_snapshot("codex", artifact.artifact_id)
    assert snapshot is not None
    assert snapshot["args"] == ["-c", "print('changed')"]
    assert store.list_receipts(harness="codex")[0]["policy_decision"] == "allow"
    event = store.list_events(event_name="changed_artifact_caught")[0]
    assert event["payload"]["policy_action"] == "allow"


def test_authoritative_schema_rejects_contradictory_alias_and_enforcement_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        default_action="allow",
        changed_hash_action="allow",
    )
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )
    output = consumer_service.evaluate_detection(
        _detection(artifact), store, config, default_action="allow", persist=False
    )

    contradictory_alias = copy.deepcopy(output)
    contradictory_alias["artifacts"][0]["verdict_action"] = "block"
    assert evaluation_authority_error(contradictory_alias) == AUTHORITATIVE_DECISION_INCONSISTENT

    contradictory_state = copy.deepcopy(output["artifacts"][0]["authoritative_decision"])
    contradictory_state["enforcement"]["launch_permitted"] = False
    with pytest.raises(ValueError, match="launch_permitted"):
        AuthoritativeGuardDecision.from_dict(contradictory_state)

    contradictory_copy = copy.deepcopy(output["artifacts"][0]["authoritative_decision"])
    contradictory_copy["decision_v2"]["user_title"] = "Blocked by policy"
    with pytest.raises(ValueError, match="derive entirely"):
        AuthoritativeGuardDecision.from_dict(contradictory_copy)

    terminal_trace_tamper = copy.deepcopy(output)
    terminal_item = terminal_trace_tamper["artifacts"][0]
    terminal_item["authoritative_decision"]["composition_trace"]["runtime_detector_action"] = "block"
    terminal_item["policy_composition"]["runtime_detector_action"] = "block"
    assert (
        evaluation_authority_error(terminal_trace_tamper, require_launch_permitted=True)
        == AUTHORITATIVE_DECISION_INCONSISTENT
    )

    contradictory_envelope = copy.deepcopy(output)
    contradictory_envelope["artifacts"][0]["action_envelope_json"] = GuardActionEnvelope(
        schema_version=1,
        action_id="contradictory-envelope",
        harness="codex",
        event_name="PreToolUse",
        action_type="tool_call",
        workspace=str(tmp_path / "workspace"),
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command="true",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        pre_execution_result="block",
    ).to_dict()
    assert evaluation_authority_error(contradictory_envelope, require_launch_permitted=True) == (
        AUTHORITATIVE_DECISION_INCONSISTENT
    )

    malformed_envelope = copy.deepcopy(output)
    malformed_envelope["artifacts"][0]["action_envelope_json"] = ["not-an-envelope"]
    assert evaluation_authority_error(malformed_envelope, require_launch_permitted=True) == (
        AUTHORITATIVE_DECISION_INCONSISTENT
    )

    with pytest.raises(ValueError, match="runtime detector block cannot be overridden"):
        build_authoritative_decision(
            "allow",
            reason="tampered detector trace",
            composition_trace={
                "current_action": "allow",
                "runtime_detector_action": "block",
            },
            authority_finalized=True,
        )

    with pytest.raises(ValueError, match="known Guard action"):
        build_authoritative_decision(
            "allow",
            reason="unknown trace action",
            composition_trace={"current_action": "future-action"},
            authority_finalized=True,
        )

    with pytest.raises(ValueError, match="unknown action-bearing field"):
        build_authoritative_decision(
            "allow",
            reason="hidden contradictory action",
            composition_trace={"current_action": "allow", "approval_action": "block"},
            authority_finalized=True,
        )

    with pytest.raises(ValueError, match="required at the launch boundary"):
        rebuild_artifact_authority(
            {"policy_action": "allow"},
            composition_updates={"runtime_detector_action": "warn"},
        )


@pytest.mark.parametrize(
    "hidden_trace",
    [
        {"approval": {"action": "block"}},
        {"approval.action": "block"},
        {"action_override": "block"},
        {"preExecutionResult": "block"},
    ],
)
def test_authoritative_schema_rejects_nested_and_aliased_action_fields(
    hidden_trace: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="unknown action-bearing field"):
        build_authoritative_decision(
            "allow",
            reason="hidden contradictory action",
            composition_trace={"current_action": "allow", **hidden_trace},
            authority_finalized=True,
        )


@pytest.mark.parametrize("runtime_action", ["warn", "review"])
def test_runtime_detector_authority_cannot_be_erased_without_approval_evidence(
    runtime_action: str,
) -> None:
    with pytest.raises(ValueError, match="runtime detector"):
        build_authoritative_decision(
            "allow",
            reason="detector result was erased",
            composition_trace={
                "current_action": "allow",
                "runtime_detector_action": runtime_action,
                "trusted_request_override": False,
            },
            authority_finalized=True,
        )


@pytest.mark.parametrize(
    "runtime_composition",
    [
        None,
        "malformed",
        {
            "action": "allow",
            "reason": "tampered detector composition",
            "downgraded": False,
            "upgraded": False,
        },
    ],
)
def test_runtime_detector_signals_require_their_exact_composed_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_composition: object,
) -> None:
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )
    output = consumer_service.evaluate_detection(
        _detection(artifact),
        GuardStore(tmp_path / "guard-home"),
        GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
            default_action="allow",
            changed_hash_action="allow",
        ),
        default_action="allow",
        persist=False,
    )
    signal = _runtime_signal(
        signal_id="runtime:critical-bypass",
        category="bypass",
        severity="critical",
        confidence="strong",
    )
    output["artifacts"][0] = rebuild_artifact_authority(
        output["artifacts"][0],
        composition_updates={"runtime_detector_action": "allow"},
        additional_signals=(signal,),
    )
    output["runtime_detector_signals_v2"] = [signal.to_dict()]
    if runtime_composition is not None:
        output["runtime_detector_composition"] = runtime_composition

    assert evaluation_authority_error(output) == AUTHORITATIVE_DECISION_INCONSISTENT


def test_run_authority_rejects_a_runtime_trace_that_disagrees_with_composition() -> None:
    signal = _runtime_signal(
        signal_id="runtime:persistence",
        category="persistence",
        severity="high",
        confidence="strong",
    )
    composition = compose_action_from_signals((signal,), "allow")
    run_decision = build_authoritative_decision(
        composition.action,
        reason=composition.reason,
        composition_trace={"runtime_detector_action": "allow"},
        signals=(signal,),
        authority_finalized=False,
        source="runtime-detector-registry",
    )
    evaluation = {
        "artifacts": [],
        "blocked": True,
        "blocked_by_detector": composition.reason,
        "runtime_detector_signals_v2": [signal.to_dict()],
        "runtime_detector_composition": {
            "action": composition.action,
            "reason": composition.reason,
            "downgraded": composition.downgraded,
            "upgraded": composition.upgraded,
        },
        "run_authoritative_decision": run_decision.to_dict(),
    }

    assert evaluation_authority_error(evaluation) == AUTHORITATIVE_DECISION_INCONSISTENT


def test_trusted_request_trace_requires_matching_outer_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )
    output = consumer_service.evaluate_detection(
        _detection(artifact),
        GuardStore(tmp_path / "guard-home"),
        GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
            default_action="review",
            changed_hash_action="review",
        ),
        persist=False,
    )
    item = output["artifacts"][0]
    trace = dict(item["policy_composition"])
    trace["trusted_request_override"] = True
    decision = build_authoritative_decision(
        "allow",
        reason="trusted_request_override_exact_context",
        composition_trace=trace,
        authority_finalized=True,
    )
    item.update(decision.to_artifact_projection())
    output["blocked"] = False

    assert evaluation_authority_error(output, require_launch_permitted=True) == (AUTHORITATIVE_DECISION_INCONSISTENT)


def test_outer_approval_reuse_action_cannot_contradict_launch_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )
    output = consumer_service.evaluate_detection(
        _detection(artifact),
        GuardStore(tmp_path / "guard-home"),
        GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
            default_action="allow",
            changed_hash_action="allow",
        ),
        default_action="allow",
        persist=False,
    )
    output["artifacts"][0]["approval_reuse"]["action"] = "block"

    assert evaluation_authority_error(output, require_launch_permitted=True) == (
        AUTHORITATIVE_DECISION_INCONSISTENT
    )


def test_finalized_saved_allow_requires_an_exact_atomic_claim_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(
        consumer_service,
        "score_verdict",
        lambda *_args, **_kwargs: _scoring_verdict("allow"),
    )
    output = consumer_service.evaluate_detection(
        _detection(artifact),
        GuardStore(tmp_path / "guard-home"),
        GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=tmp_path / "workspace",
            default_action="review",
            changed_hash_action="review",
        ),
        persist=False,
    )
    item = output["artifacts"][0]
    item["approval_reuse"] = {
        **item["approval_reuse"],
        "action": "allow",
        "status": "accepted",
        "reason_code": "approval_reuse_accepted",
        "current_action": "review",
        "saved_action": "allow",
        "should_claim": True,
    }
    item["approval_reuse_status"] = "accepted"
    item["approval_reuse_reason_code"] = "approval_reuse_accepted"
    item["scanner_evidence"] = [
        {
            "source": "approval_reuse",
            "status": "accepted",
            "reason_code": "approval_reuse_accepted",
        }
    ]
    trace = dict(item["policy_composition"])
    trace.update({"saved_action": "allow", "saved_state_present": True})
    decision = build_authoritative_decision(
        "allow",
        reason="approval_reuse_accepted",
        composition_trace=trace,
        authority_finalized=True,
    )
    item.update(decision.to_artifact_projection())
    output["blocked"] = False

    assert evaluation_authority_error(output, require_launch_permitted=True) == (AUTHORITATIVE_DECISION_INCONSISTENT)

    claim = {
        "status": "consumed",
        "approval_context_hash": item["approval_context_hash"],
        "reason_code": "approval_reuse_accepted",
    }
    trace["saved_approval_claim"] = claim
    claimed_decision = build_authoritative_decision(
        "allow",
        reason="approval_reuse_accepted",
        composition_trace=trace,
        authority_finalized=True,
    )
    item.update(claimed_decision.to_artifact_projection())
    item["approval_claim"] = dict(claim)
    assert evaluation_authority_error(output, require_launch_permitted=True) is None

    tampered = copy.deepcopy(output)
    tampered["artifacts"][0]["approval_claim"]["approval_context_hash"] = "different-context"
    assert evaluation_authority_error(tampered, require_launch_permitted=True) == (AUTHORITATIVE_DECISION_INCONSISTENT)
