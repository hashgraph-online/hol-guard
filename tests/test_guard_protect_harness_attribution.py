"""Harness attribution for package shims and local protect flows."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.protect import build_protect_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.harness_attribution_env import strip_harness_env_markers
from tests.test_guard_local_supply_chain_phase15 import _package, _seed_supply_chain_bundle


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_review_advisory(store: GuardStore) -> None:
    store.cache_advisories(
        [
            {
                "id": "adv-review-pkg",
                "ecosystem": "npm",
                "package": "reviewpkg",
                "severity": "medium",
                "action": "review",
                "headline": "Provenance requires review.",
            }
        ],
        _now(),
    )


def _stub_approval_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_dispatch_local

    monkeypatch.setattr(
        commands_dispatch_local,
        "ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4455",
    )


def test_guard_protect_attributes_package_requests_to_invoking_harness(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    store = GuardStore(home_dir)
    _seed_review_advisory(store)
    monkeypatch.setenv("ZCODE_ENV", "production")
    _stub_approval_daemon(monkeypatch)

    rc = main(
        [
            "guard",
            "protect",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
            "--dry-run",
            "npm",
            "install",
            "reviewpkg",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert output["request"]["harness"] == "zcode"
    assert output["receipt"]["harness"] == "zcode"
    assert output["targets"]
    assert all(target.get("harness") == "zcode" for target in output["targets"])
    assert str(output["receipt"]["artifact_id"]).startswith("guard-cli:")

    queued = store.list_approval_requests(status="pending", limit=10)
    assert queued
    assert all(item["harness"] == "zcode" for item in queued)
    assert all(str(item["artifact_id"]).startswith("guard-cli:") for item in queued)
    assert any("ZCode" in str(item.get("trigger_summary") or "") for item in queued)
    assert rc == 2

    install_events = [
        event for event in store.list_events(limit=20) if str(event["event_name"]).startswith("install_time_")
    ]
    assert install_events
    assert all(event["payload"].get("harness") == "zcode" for event in install_events)


def test_guard_protect_keeps_guard_cli_attribution_outside_harness_env(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    strip_harness_env_markers(monkeypatch)
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    store = GuardStore(home_dir)
    _seed_review_advisory(store)
    _stub_approval_daemon(monkeypatch)

    main(
        [
            "guard",
            "protect",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--json",
            "--dry-run",
            "npm",
            "install",
            "reviewpkg",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert output["request"]["harness"] == "guard-cli"
    assert output["receipt"]["harness"] == "guard-cli"
    queued = store.list_approval_requests(status="pending", limit=10)
    assert queued
    assert all(item["harness"] == "guard-cli" for item in queued)


@pytest.mark.usefixtures("bundle_first_cloud")
def test_guard_protect_receipt_keeps_matched_policy_rule_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    strip_harness_env_markers(monkeypatch)
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    _seed_supply_chain_bundle(
        store,
        packages=[_package(name="minimist", version="1.2.5", default_action="block")],
        now="2026-05-19T12:00:00+00:00",
        policy_rules=[
            {
                "action": "warn",
                "ruleId": "policy-rule-1",
                "ecosystemSelector": "npm",
                "enabled": True,
                "expiresAt": "2099-01-01T00:00:00Z",
                "harnessSelector": "guard-cli",
                "packageSelector": "minimist",
                "priority": 1,
                "severityThreshold": "low",
                "versionRangeSelector": "1.2.5",
            }
        ],
    )

    payload, exit_code = build_protect_payload(
        command=["npm", "install", "minimist@1.2.5"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-05-19T12:00:00+00:00",
        unsafe_raw_output=False,
    )

    assert exit_code == 0
    assert payload["supply_chain_evaluation"]["matched_rule_id"] == "policy-rule-1"
    action_envelope = dict(payload["receipt"]["action_envelope_json"])
    package_context = action_envelope.pop("package_execution_context")
    assert action_envelope.pop("policy_action") == "warn"
    assert action_envelope.pop("additional_policy_context") == {
        "action": "allow",
        "matched_advisories": [],
        "reason": "Guard found no blocking advisory or risky install signal for this request.",
        "risk_signals": [],
        "version": 1,
    }
    assert action_envelope == {
        "bundle_version": "1747612800000-deadbeef",
        "matched_rule_id": "policy-rule-1",
        "package_manager": "npm",
        "package_targets": ["minimist@1.2.5"],
        "policy_version": "policy-hash-1",
        "redacted_command": "npm install minimist@1.2.5",
    }
    assert package_context["kind"] == "package_execution_context"
    assert package_context["schema_version"] == 2
    assert str(workspace_dir) not in json.dumps(package_context, sort_keys=True)
    stored_receipt = store.list_receipts(limit=1)[0]
    assert stored_receipt["action_envelope_json"]["matched_rule_id"] == "policy-rule-1"
    assert stored_receipt["action_envelope_json"]["package_execution_context"] == package_context
