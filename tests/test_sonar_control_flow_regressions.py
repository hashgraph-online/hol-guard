"""Behavioral regressions for Sonar's invariant-return findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.cli import commands_dispatch_records as records
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.runtime.mcp_skill_firewall import build_runtime_action_record


@pytest.mark.parametrize("health", [health for health in AuthorityHealth if health is not AuthorityHealth.PROTECTED])
def test_unprotected_snapshot_preserves_both_protected_revision_floors(health: AuthorityHealth) -> None:
    def view(revision: int, managed_revision: int, health: AuthorityHealth) -> ExtensionControlAuthorityView:
        return ExtensionControlAuthorityView(health, revision, "a" * 64, (), managed_revision)

    runtime = ExtensionControlRuntime(view(4, 2, AuthorityHealth.PROTECTED))
    unprotected = runtime.refresh(view(0, 0, health))

    assert runtime.current() is unprotected
    assert unprotected.health is health
    for revision, managed_revision in ((3, 2), (5, 1)):
        with pytest.raises(ValueError, match="move backwards"):
            runtime.refresh(view(revision, managed_revision, AuthorityHealth.PROTECTED))
        assert runtime.current() is unprotected
    replacement = runtime.refresh(view(5, 3, AuthorityHealth.PROTECTED))
    assert runtime.current() is replacement
    assert (replacement.revision, replacement.managed_revision) == (5, 3)


@pytest.mark.parametrize("artifact_type", ["skill", "tool_call"])
@pytest.mark.parametrize("categories", [(), ("network",), ("network", "secret_access", "network")])
def test_observed_capabilities_preserve_order_and_are_detached(artifact_type: str, categories: tuple[str, ...]) -> None:
    artifact = GuardArtifact(
        artifact_id="fixture",
        name="fixture",
        harness="codex",
        artifact_type=artifact_type,
        source_scope="user",
        config_path="fixture.json",
    )
    payload = build_runtime_action_record(artifact=artifact, risk_categories=categories)
    if not categories:
        assert payload is None
        return
    assert payload is not None
    assert payload["observedCapabilities"] == list(categories)
    assert payload["claimedCapabilities"] == []
    assert payload["sensitiveDataClasses"] == (["secret_access"] if "secret_access" in categories else [])
    observed = payload["observedCapabilities"]
    assert isinstance(observed, list)
    observed.append("mutated")
    second = build_runtime_action_record(artifact=artifact, risk_categories=categories)
    assert second is not None
    assert second["observedCapabilities"] == list(categories)


@pytest.mark.parametrize("format_name,json_output", [("markdown", False), ("markdown", True), ("json", False)])
def test_abom_emits_exactly_one_selected_format(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    format_name: str,
    json_output: bool,
) -> None:
    payload = {"markdown": "# Inventory", "items": []}
    emit = Mock()
    monkeypatch.setattr(records, "_require_guard_store", Mock(), raising=False)
    monkeypatch.setattr(records, "_build_abom_payload", Mock(return_value=payload), raising=False)
    monkeypatch.setattr(records, "_emit", emit, raising=False)

    result = records._run_guard_abom_command(argparse.Namespace(format=format_name, json=json_output))

    assert result == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    if format_name == "markdown" and not json_output:
        assert captured.out == "# Inventory\n"
        emit.assert_not_called()
    else:
        assert captured.out == ""
        emit.assert_called_once_with("abom", payload, True)


def test_invalid_codex_input_denies_without_reviewing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    review = Mock(side_effect=AssertionError("invalid input must not reach review"))
    monkeypatch.setattr(bridge, "_bound_hook_input", Mock(return_value=None))
    monkeypatch.setattr(bridge, "bridge_review_response", review)

    result = bridge.main(
        state_path=tmp_path / "daemon-state.json", fallback_command=(), start_command=(), query="", hook_timeouts={}
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out) == bridge._fail_closed("PreToolUse")
    review.assert_not_called()


@pytest.mark.parametrize("decision", ["allow", "deny"])
def test_codex_review_emits_original_decision_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], decision: str
) -> None:
    response = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision}}
    review = Mock(return_value=(response, False, False))
    output = Mock(side_effect=lambda value, **_kwargs: json.dumps(value))
    monkeypatch.setattr(bridge, "_bound_hook_input", Mock(return_value=("PreToolUse", "{}", 5)))
    monkeypatch.setattr(bridge, "bridge_review_response", review)
    monkeypatch.setattr(bridge, "_bridge_output", output)

    result = bridge.main(
        state_path=tmp_path / "daemon-state.json", fallback_command=(), start_command=(), query="", hook_timeouts={}
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out) == response
    review.assert_called_once()
    output.assert_called_once()
    assert output.call_args.args[0] is response
