"""Resolved-version policy sinks for npm prerelease admission."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore
from tests import test_guard_js_supply_chain_phase11 as support


@pytest.mark.parametrize(
    ("resolved_version", "policy_selector", "expected_decision", "expected_rule_id"),
    [
        ("1.3.0-beta.1", "^1.2.3", "block", None),
        ("1.3.0-beta.1", ">=1.2.0, <2.0.0", "block", None),
        ("1.3.0-beta.1", ">=1.3.0-beta.1 <1.3.0", "allow", "allow-range"),
        ("1.3.0", "^1.2.3", "allow", "allow-range"),
        ("1.2.3", "==1.2.3", "block", None),
    ],
)
def test_policy_range_matches_resolved_npm_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resolved_version: str,
    policy_selector: str,
    expected_decision: str,
    expected_rule_id: str | None,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    support._write_text(
        workspace_dir / "package.json",
        '{"name":"demo","dependencies":{"minimist":"^1.2.3"}}\n',
    )
    support._write_text(
        workspace_dir / "package-lock.json",
        (
            '{"lockfileVersion":3,"packages":{"":{"dependencies":{"minimist":"^1.2.3"}},'
            f'"node_modules/minimist":{{"version":"{resolved_version}"}}}}}}\n'
        ),
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: support.WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        support.WORKSPACE_ID,
        support._bundle_response(
            packages=[support._package(name="minimist", version=resolved_version, default_action="block")],
            policy_rules=[
                {
                    "action": "allow",
                    "ruleId": "allow-range",
                    "ecosystemSelector": "npm",
                    "enabled": True,
                    "expiresAt": None,
                    "harnessSelector": "codex",
                    "packageSelector": "minimist",
                    "priority": 1,
                    "severityThreshold": None,
                    "versionRangeSelector": policy_selector,
                }
            ],
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = support._artifact_from_command("npm install minimist@^1.2.3", workspace=workspace_dir)
    assert isinstance(artifact, GuardArtifact)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == expected_decision
    assert result.matched_rule_id == expected_rule_id
    assert result.packages[0]["requestedVersion"] == "^1.2.3"
    assert result.packages[0]["resolvedVersion"] == resolved_version
