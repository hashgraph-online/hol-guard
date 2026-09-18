"""Cross-language fixtures keep an oracle independent of the Rust classifier."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.github_capability_contract import github_capability_contract
from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = _ROOT / "rust/crates/guard-command/tests/fixtures/native-command-compatibility-v1.json"


def test_frozen_github_capabilities_and_owners_match_independent_python_oracle() -> None:
    fixture = json.loads(_FIXTURE.read_text())
    checked = 0
    for case in fixture["cases"]:
        expected = case["python_capabilities"]
        if expected is None:
            continue
        arguments = shlex.split(case["command"])
        assert arguments[0] == "gh"
        assessment = classify_github_cli(arguments[1:])
        assert sorted(assessment.capabilities) == expected, case["case_id"]
        owners = tuple(github_capability_contract(capability) for capability in assessment.capabilities)
        assert sorted(owner.rule_id for owner in owners if owner.rule_id) == case["expected_rules"]
        assert sorted(owner.permission_id for owner in owners if not owner.rule_id) == case["expected_permissions"]
        checked += 1
    assert checked == 123
    assert fixture["complete_python_parity"] is False
    assert fixture["qualification_complete"] is False


def test_git_attribution_expansion_is_explicitly_not_claimed_as_legacy_observation_parity() -> None:
    # These catalog entries currently have no Python matcher/fallback. Native
    # attribution intentionally closes that omission for disabled permissions.
    for command in ("git status", "git log", "git diff --no-ext-diff --no-textconv", "git ls-files"):
        evaluation = evaluate_command(command, extension_control_layers=())
        assert not evaluation.extension_observations
        assert not evaluation.matches
