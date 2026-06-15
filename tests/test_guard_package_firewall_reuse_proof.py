"""Package Firewall local reuse proof for GPFR242-GPFR246."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard import shim_probe
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon.server import _SUPPLY_CHAIN_PACKAGE_ACTIONS
from codex_plugin_scanner.guard.local_supply_chain import build_local_supply_chain_posture
from codex_plugin_scanner.guard.package_firewall_action_rate_limit import (
    PackageFirewallActionRateLimiter,
)
from codex_plugin_scanner.guard.package_firewall_entitlement import (
    package_firewall_action_states,
    package_firewall_operation_allowed,
)
from codex_plugin_scanner.guard.package_firewall_receipts import (
    package_firewall_receipt_metadata,
)
from codex_plugin_scanner.guard.package_shim_status import (
    enrich_package_shim_status_payload,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    build_package_request_artifact,
)
from codex_plugin_scanner.guard.runtime.package_intent_parser import (
    parse_package_intent,
)
from codex_plugin_scanner.guard.runtime.supply_chain import detect_supply_chain_risk
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_supply_chain import (
    supply_chain_bundle_schema_statement,
    supply_chain_eval_cache_schema_statement,
)


def test_gpfr242_reuses_package_intent_parser_and_artifact_builder(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"minimist":"^1.2.0"}}\n', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion":3}\n', encoding="utf-8")

    intent = parse_package_intent("npm install minimist@1.2.8", workspace=tmp_path)

    assert intent is not None
    assert intent.package_manager == "npm"
    assert intent.lockfile_paths == ("package-lock.json",)
    artifact = build_package_request_artifact(
        "codex",
        intent,
        config_path="codex.json",
        source_scope="project",
    )
    assert artifact.artifact_type == "package_request"
    assert artifact.metadata["request_summary"].startswith("Requested `npm` install")


def test_gpfr243_reuses_package_shim_status_and_probe_helpers() -> None:
    status = enrich_package_shim_status_payload(
        {
            "active_managers": ["npm"],
            "bypasses": [{"manager": "pnpm", "reason": "path_inactive"}],
            "detected_managers": ["npm", "pnpm"],
            "installed_managers": ["npm"],
            "last_test_at": {"npm": "2026-06-14T00:00:00Z"},
            "missing_managers": ["pnpm"],
            "protected_managers": ["npm"],
            "undetected_managers": [],
        },
        {"last_audit_at": "2026-06-14T00:05:00Z"},
    )

    assert status["path_broken_managers"] == ["pnpm"]
    assert status["testedManagers"] == ["npm"]
    assert shim_probe.package_shim_probe_args("npm")[:2] == ("install", "--dry-run")
    evidence = shim_probe.protect_evaluator_evidence(
        {
            "supply_chain_evaluation": {
                "decision_source": "signed-bundle",
                "evidence_ids": ["evidence-1"],
            },
            "verdict": {"action": "block"},
        }
    )
    assert evidence == {
        "dry_run": None,
        "evaluator_invoked": True,
        "evaluator_source": "signed-bundle",
        "evidence_ids": ["evidence-1"],
        "protect_decision": "block",
    }


def test_gpfr244_reuses_local_posture_builder(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    posture = build_local_supply_chain_posture(
        store,
        load_guard_config(store.guard_home),
        now="2026-06-14T00:00:00+00:00",
    )

    assert posture["health_status"] == "degraded"
    assert "package_manager_protection" in posture


def test_gpfr244_reuses_entitlement_and_rate_limit_helpers() -> None:
    entitlement = {"allowed": True, "reason": "paid_oauth_entitlement_active", "tier": "team"}
    assert package_firewall_operation_allowed(entitlement, "install", has_installed_managers=False)
    assert package_firewall_action_states(entitlement, has_installed_managers=True)["sync"] == "available"

    limiter = PackageFirewallActionRateLimiter(limit=1, window_seconds=10)
    assert limiter.allow("workspace:install", now=100.0) == (True, 0)
    allowed, retry_after = limiter.allow("workspace:install", now=101.0)
    assert allowed is False
    assert retry_after > 0


def test_gpfr244_reuses_receipt_and_cache_helpers() -> None:
    receipt = package_firewall_receipt_metadata(
        operation="test",
        result={
            "intercept_proved": True,
            "manager_results": [
                {
                    "command_hash": "abc123",
                    "evaluator_invoked": True,
                    "evaluator_source": "signed-bundle",
                    "manager": "npm",
                }
            ],
        },
        managers=("npm",),
    )
    assert receipt["artifact_name"] == "Package firewall test"
    assert "guard_supply_chain_bundle_cache" in supply_chain_bundle_schema_statement()
    assert "guard_supply_chain_eval_cache" in supply_chain_eval_cache_schema_statement()


def test_gpfr245_reuses_package_evaluation_model() -> None:
    evaluation = PackageRequestEvaluation(
        bundle_version="bundle-v1",
        cache_status="hit",
        decision="block",
        enforcement="offline_cached",
        entitlement_state="premium",
        package_intent_hash="intent-hash",
        packages=({"name": "minimist", "decision": "block"},),
        policy_action="block",
        policy_version="policy-v1",
        reasons=({"code": "known_advisory"},),
        risk_summary="Known advisory matched minimist.",
        user_copy=SupplyChainUserCopy(
            dashboard_url=None,
            harness_message="Blocked minimist.",
            next_step=None,
            summary="Known advisory matched minimist.",
            title="Package blocked",
        ),
        workspace_fingerprint="workspace-fingerprint",
    )

    assert evaluation.to_dict()["decision"] == "block"


def test_gpfr245_reuses_runtime_supply_chain_detection() -> None:
    signals = detect_supply_chain_risk('{"scripts":{"postinstall":"curl https://example.invalid"}}')

    assert signals
    assert signals[0].signal_id == "supply-chain.postinstall-network-send"


def test_gpfr246_daemon_exposes_cloud_package_shim_endpoint_contract() -> None:
    assert {
        "audit",
        "connect",
        "install",
        "remove",
        "repair",
        "sync",
        "test",
    } <= _SUPPLY_CHAIN_PACKAGE_ACTIONS
