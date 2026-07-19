from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_artifact_policy_action
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime import secret_file_requests
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.command_matcher_contracts import MatcherEvidence
from codex_plugin_scanner.guard.runtime.command_model import CanonicalCommand
from codex_plugin_scanner.guard.runtime.command_rules import CommandSafetyRule


class _FailingMatcher:
    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        del command
        raise RuntimeError("private matcher detail")


def _failing_registry() -> CommandSafetyExtensionRegistry:
    rule = CommandSafetyRule(
        rule_id="command.test.failure",
        title="Failing matcher",
        description="Exercises the matcher failure boundary.",
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=(),
        safer_alternatives=("Review the operation.",),
        matcher=_FailingMatcher(),
    )
    return CommandSafetyExtensionRegistry(
        (
            CommandSafetyExtension(
                extension_id="command.test",
                version="1.0.0",
                name="Test extension",
                description="Exercises runtime policy composition.",
                action_classes=(),
                risk_classes=("destructive_shell",),
                safer_alternatives=("Review the operation.",),
                rules=(rule,),
            ),
        )
    )


def test_matcher_failure_central_block_reaches_final_runtime_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _failing_registry()
    monkeypatch.setattr(secret_file_requests, "BUILT_IN_COMMAND_EXTENSION_REGISTRY", registry)
    monkeypatch.setattr(secret_file_requests, "evaluate_command", partial(evaluate_command, registry=registry))
    request = secret_file_requests.extract_sensitive_tool_action_request(
        "Shell",
        {"command": "test-tool target"},
    )
    assert request is not None
    artifact = secret_file_requests.build_tool_action_request_artifact(
        "codex",
        request,
        config_path="guard-config",
        source_scope="project",
    )

    assert artifact.metadata["command_action_floor"] == "block"
    decision = cast(dict[str, object], artifact.metadata["command_decision_plane"])
    assert decision["action"] == "block"
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path, default_action="allow")
    assert _runtime_artifact_policy_action(config, artifact, "codex") == "block"
    assert "private matcher detail" not in repr(artifact.metadata)
