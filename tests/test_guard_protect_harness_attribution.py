"""Harness attribution for package shims and local protect flows."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import protect
from codex_plugin_scanner.guard.approvals import apply_approval_resolution, queue_blocked_approvals
from codex_plugin_scanner.guard.cli.protect_approvals import _protect_approval_item, _protect_request_artifact
from codex_plugin_scanner.guard.local_supply_chain import _is_fresh_artifact_approval, build_package_protect_payload
from codex_plugin_scanner.guard.models import GuardApprovalRequest, HarnessDetection
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


def _package_payload(
    *,
    package_manager: str,
    store: GuardStore,
    workspace_dir: Path,
    now: str,
    dry_run: bool = True,
    allow_saved_approval_execution: bool = False,
) -> tuple[dict[str, object], int]:
    result = build_package_protect_payload(
        command=[package_manager, "install", "reviewpkg"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=dry_run,
        allow_saved_approval_execution=allow_saved_approval_execution,
        now=now,
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert result is not None
    return result


def _queue_package_approval(
    *,
    payload: dict[str, object],
    store: GuardStore,
    workspace_dir: Path,
    now: str,
) -> dict[str, object]:
    artifact = _protect_request_artifact(payload, workspace=workspace_dir)
    assert artifact is not None
    item = _protect_approval_item(payload, workspace=workspace_dir, artifact=artifact)
    assert item is not None
    queued = queue_blocked_approvals(
        detection=HarnessDetection(
            harness=artifact.harness,
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        ),
        evaluation={"artifacts": [item]},
        store=store,
        approval_center_url="http://127.0.0.1:4455",
        now=now,
        notify=False,
    )
    assert len(queued) == 1
    return queued[0]


def _install_fake_package_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    package_manager: str,
) -> None:
    package_bin = tmp_path / "package-bin"
    package_bin.mkdir()
    executable = package_bin / (f"{package_manager}.cmd" if os.name == "nt" else package_manager)
    executable.write_text("@echo off\r\nexit /b 0\r\n" if os.name == "nt" else "#!/bin/sh\nexit 0\n")
    if os.name != "nt":
        executable.chmod(0o755)
    inherited_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", os.pathsep.join(filter(None, (str(package_bin), inherited_path))))


@pytest.mark.parametrize("origin,harness", [("environment", "zcode"), ("zcode-cli", "zcode"), ("grok", "grok")])
@pytest.mark.parametrize("package_manager", ["npm", "bun"])
def test_guard_protect_attributes_package_requests_to_invoking_harness(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    origin: str,
    harness: str,
    package_manager: str,
) -> None:
    if origin != "environment" and os.name == "nt":
        pytest.skip("Process-table attribution is Unix-only")
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    store = GuardStore(home_dir)
    _seed_review_advisory(store)
    strip_harness_env_markers(monkeypatch)
    if origin == "environment":
        monkeypatch.setenv("ZCODE_ENV", "production")
    else:
        from codex_plugin_scanner.guard.runtime import harness_attribution

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.package_protect_projection.resolve_parent_process_harness",
            harness_attribution.resolve_parent_process_harness,
        )
        original_run = subprocess.run

        def process_snapshot(command, **kwargs):
            if command == ["/bin/ps", "-axo", "pid=,ppid=,comm="]:
                return subprocess.CompletedProcess(command, 0, f"42 41 /bin/sh\n41 1 {origin}\n", "")
            return original_run(command, **kwargs)

        monkeypatch.setattr(harness_attribution.os, "getppid", lambda: 42)
        monkeypatch.setattr(harness_attribution.subprocess, "run", process_snapshot)
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
            package_manager,
            "install",
            "reviewpkg",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert output["request"]["harness"] == harness
    assert output["receipt"]["harness"] == harness
    assert output["targets"]
    assert all(target.get("harness") == harness for target in output["targets"])
    assert str(output["receipt"]["artifact_id"]).startswith("guard-cli:")

    queued = store.list_approval_requests(status="pending", limit=10)
    assert queued
    assert all(item["harness"] == harness for item in queued)
    assert all(str(item["artifact_id"]).startswith("guard-cli:") for item in queued)
    assert any(harness in str(item.get("trigger_summary") or "").lower() for item in queued)
    assert rc == 2

    install_events = [
        event for event in store.list_events(limit=20) if str(event["event_name"]).startswith("install_time_")
    ]
    assert install_events
    assert all(event["payload"].get("harness") == harness for event in install_events)


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


@pytest.mark.parametrize(
    ("command", "expected_harness"),
    [
        (("bun", "run", "build"), "guard-cli"),
        (("npm", "run", "build"), "guard-cli"),
        (("custom-tool", "run", "build"), "custom-tool"),
    ],
)
def test_guard_protect_receipt_classifies_package_tool_fallback_without_inventing_custom_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: tuple[str, ...],
    expected_harness: str,
) -> None:
    strip_harness_env_markers(monkeypatch)
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    store = GuardStore(home_dir)

    payload, exit_code = build_protect_payload(
        command=list(command),
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-09-10T00:00:00+00:00",
    )

    assert exit_code == 0
    assert payload["request"]["harness"] is None
    assert payload["receipt"]["harness"] == expected_harness
    assert store.list_receipts(limit=1)[0]["harness"] == expected_harness


def test_guard_protect_package_tool_fallback_preserves_shared_runtime_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    strip_harness_env_markers(monkeypatch)
    monkeypatch.setenv("CODEX_SANDBOX", "1")
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    store = GuardStore(home_dir)

    payload, exit_code = build_protect_payload(
        command=["bun", "run", "build"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-09-10T00:00:00+00:00",
    )

    assert exit_code == 0
    assert payload["request"]["harness"] is None
    assert payload["receipt"]["harness"] == "codex"
    assert store.list_receipts(limit=1)[0]["harness"] == "codex"


def test_guard_protect_receipt_preserves_explicit_request_harness() -> None:
    request = protect.parse_protect_command(["codex", "mcp", "add", "server"])
    verdict = protect.ProtectVerdict(
        action="allow",
        reason="test",
        risk_signals=(),
        matched_advisories=(),
    )

    receipt = protect._build_install_receipt(request, verdict)

    assert receipt.harness == "codex"


@pytest.mark.usefixtures("bundle_first_cloud")
@pytest.mark.parametrize("parent_harness", [None, "codex"])
def test_guard_protect_receipt_keeps_matched_policy_rule_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_harness: str | None
) -> None:
    strip_harness_env_markers(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.package_protect_projection.resolve_parent_process_harness",
        lambda: parent_harness,
    )
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
    assert payload["receipt"]["harness"] == (parent_harness or "guard-cli")
    if parent_harness:
        assert action_envelope.pop("invoking_harness") == parent_harness
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


@pytest.mark.parametrize("package_manager", ["npm", "bun"])
@pytest.mark.parametrize(
    ("persist_policy", "expected_second_rc"),
    [(True, 0), (None, 2)],
    ids=["remember", "once"],
)
def test_package_approval_reuses_under_policy_harness_after_invoking_harness_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package_manager: str,
    persist_policy: bool | None,
    expected_second_rc: int,
    install_fake_system_keyring,
) -> None:
    install_fake_system_keyring()
    _install_fake_package_manager(monkeypatch, tmp_path, package_manager)
    if persist_policy is None:
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.local_supply_chain.subprocess.run",
            lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
        )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_supply_chain._resolve_local_supply_chain_harness",
        lambda: "zcode",
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    baseline, baseline_rc = _package_payload(
        package_manager=package_manager,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:00:00+00:00",
    )
    request = _queue_package_approval(
        payload=baseline,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:00:00+00:00",
    )

    assert baseline_rc == 2
    assert request["harness"] == "zcode"
    assert str(request["artifact_id"]).startswith("guard-cli:project:package-request:")
    apply_approval_resolution(
        store=store,
        request_id=str(request["request_id"]),
        action="allow",
        scope="artifact",
        workspace=None,
        reason="approved exact package request",
        now="2026-09-10T00:01:00+00:00",
        persist_policy=persist_policy,
        scope_contract_version=str(request["scope_contract_version"]),
        scope_contract_digest=str(request["scope_contract_digest"]),
    )

    policy_lookup = store.resolve_policy_decision_lookup(
        "guard-cli",
        str(request["artifact_id"]),
        str(request["artifact_hash"]),
        now="2026-09-10T00:01:30+00:00",
        consume_one_shot=False,
    )
    assert policy_lookup["decision"] is not None
    assert policy_lookup["decision"]["harness"] == "guard-cli"
    assert (
        store.resolve_policy_decision_lookup(
            "zcode",
            str(request["artifact_id"]),
            str(request["artifact_hash"]),
            now="2026-09-10T00:01:30+00:00",
            consume_one_shot=False,
        )["decision"]
        is None
    )

    retry, retry_rc = _package_payload(
        package_manager=package_manager,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:02:00+00:00",
        dry_run=persist_policy is not None,
        allow_saved_approval_execution=persist_policy is None,
    )
    retry_reasons = retry["supply_chain_evaluation"]["reasons"]
    assert isinstance(retry_reasons, list)
    assert retry_reasons[0]["code"] == "saved_package_approval"
    assert retry_rc == 0
    assert retry["verdict"]["action"] == "allow"
    assert retry["receipt"]["harness"] == "zcode"
    assert retry["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_approval"

    after_first_retry = store.resolve_policy_decision_lookup(
        "guard-cli",
        str(request["artifact_id"]),
        str(request["artifact_hash"]),
        now="2026-09-10T00:02:30+00:00",
        consume_one_shot=False,
    )
    if persist_policy is None:
        assert after_first_retry["decision"] is None
    else:
        assert after_first_retry["decision"] is not None
    assert (
        store.resolve_policy_decision_lookup(
            "zcode",
            str(request["artifact_id"]),
            str(request["artifact_hash"]),
            now="2026-09-10T00:02:30+00:00",
            consume_one_shot=False,
        )["decision"]
        is None
    )

    second_retry, second_retry_rc = _package_payload(
        package_manager=package_manager,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:03:00+00:00",
    )
    assert second_retry_rc == expected_second_rc
    if expected_second_rc == 0:
        assert second_retry["supply_chain_evaluation"]["reasons"][0]["code"] == "saved_package_approval"
    else:
        assert second_retry["verdict"]["action"] == "require-reapproval"
        assert not any(
            isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
            for reason in second_retry["supply_chain_evaluation"]["reasons"]
        )


@pytest.mark.parametrize("package_manager", ["npm", "bun"])
@pytest.mark.parametrize("persist_policy", [True, None], ids=["remember", "once"])
def test_package_approval_does_not_reuse_after_package_context_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package_manager: str,
    persist_policy: bool | None,
    install_fake_system_keyring,
) -> None:
    install_fake_system_keyring()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_supply_chain._resolve_local_supply_chain_harness",
        lambda: "zcode",
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    baseline, baseline_rc = _package_payload(
        package_manager=package_manager,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:00:00+00:00",
    )
    request = _queue_package_approval(
        payload=baseline,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:00:00+00:00",
    )
    assert baseline_rc == 2
    apply_approval_resolution(
        store=store,
        request_id=str(request["request_id"]),
        action="allow",
        scope="artifact",
        workspace=None,
        reason="approved exact package request",
        now="2026-09-10T00:01:00+00:00",
        persist_policy=persist_policy,
        scope_contract_version=str(request["scope_contract_version"]),
        scope_contract_digest=str(request["scope_contract_digest"]),
    )

    changed = build_package_protect_payload(
        command=[package_manager, "install", "reviewpkg@2.0.0"],
        store=store,
        workspace_dir=workspace_dir,
        dry_run=True,
        now="2026-09-10T00:02:00+00:00",
        config=None,
        unsafe_raw_output=False,
        timeout_seconds=30,
    )
    assert changed is not None
    changed_payload, changed_rc = changed
    assert changed_rc == 2
    assert changed_payload["verdict"]["action"] == "require-reapproval"
    assert not any(
        isinstance(reason, dict) and reason.get("code") == "saved_package_approval"
        for reason in changed_payload["supply_chain_evaluation"]["reasons"]
    )


def test_noncanonical_package_artifact_keeps_invoking_policy_harness(
    tmp_path: Path,
    install_fake_system_keyring,
) -> None:
    install_fake_system_keyring()
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="request-noncanonical-package",
        harness="zcode",
        artifact_id="zcode:project:package-request:external",
        artifact_name="external package request",
        artifact_hash="hash-external-package",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("package_request",),
        source_scope="project",
        config_path=str(tmp_path / "workspace" / "hol-guard.toml"),
        review_command="hol-guard approvals approve request-noncanonical-package",
        approval_url="http://127.0.0.1:4455/approvals/request-noncanonical-package",
        artifact_type="package_request",
    )
    store.add_approval_request(request, "2026-09-10T00:00:00+00:00")
    stored_request = store.get_approval_request(request.request_id)
    assert stored_request is not None

    apply_approval_resolution(
        store=store,
        request_id=request.request_id,
        action="allow",
        scope="artifact",
        workspace=None,
        reason="approved external package request",
        now="2026-09-10T00:01:00+00:00",
        persist_policy=True,
        scope_contract_version=str(stored_request["scope_contract_version"]),
        scope_contract_digest=str(stored_request["scope_contract_digest"]),
    )

    assert (
        store.resolve_policy_decision_lookup(
            "zcode",
            request.artifact_id,
            request.artifact_hash,
            consume_one_shot=False,
        )["decision"]
        is not None
    )
    assert (
        store.resolve_policy_decision_lookup(
            "guard-cli",
            request.artifact_id,
            request.artifact_hash,
            consume_one_shot=False,
        )["decision"]
        is None
    )


@pytest.mark.parametrize("artifact_hash", [None, "plain-package-hash", "guard-approval-context:v1:invalid"])
def test_fresh_package_approval_requires_valid_context_token(tmp_path: Path, artifact_hash: object) -> None:
    decision = {
        "decision_id": 1,
        "harness": "guard-cli",
        "scope": "artifact",
        "action": "allow",
        "artifact_id": "guard-cli:project:package-request:reviewpkg",
        "artifact_hash": artifact_hash,
        "source": "approval-gate",
        "expires_at": "2026-09-10T00:15:00+00:00",
    }

    assert _is_fresh_artifact_approval(decision, store=GuardStore(tmp_path / "guard-home")) is False


def test_package_once_lookup_filters_expiry_before_fresh_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    install_fake_system_keyring,
) -> None:
    install_fake_system_keyring()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_supply_chain._resolve_local_supply_chain_harness",
        lambda: "zcode",
    )
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    baseline, baseline_rc = _package_payload(
        package_manager="npm",
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:00:00+00:00",
    )
    request = _queue_package_approval(
        payload=baseline,
        store=store,
        workspace_dir=workspace_dir,
        now="2026-09-10T00:00:00+00:00",
    )
    assert baseline_rc == 2
    apply_approval_resolution(
        store=store,
        request_id=str(request["request_id"]),
        action="allow",
        scope="artifact",
        workspace=None,
        reason="approved exact package request",
        now="2026-09-10T00:01:00+00:00",
        persist_policy=None,
        scope_contract_version=str(request["scope_contract_version"]),
        scope_contract_digest=str(request["scope_contract_digest"]),
    )

    artifact_id = str(request["artifact_id"])
    artifact_hash = str(request["artifact_hash"])
    before_expiry = store.resolve_policy_decision_lookup(
        "guard-cli",
        artifact_id,
        artifact_hash,
        now="2026-09-10T00:15:59+00:00",
        consume_one_shot=False,
    )
    assert before_expiry["decision"] is not None
    assert _is_fresh_artifact_approval(before_expiry["decision"], store=store) is True
    decision_id = before_expiry["decision"]["decision_id"]
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where decision_id = ?",
            ("0" * 64, decision_id),
        )
    tampered = store.resolve_policy_decision_lookup(
        "guard-cli",
        artifact_id,
        artifact_hash,
        now="2026-09-10T00:15:59+00:00",
        consume_one_shot=False,
    )
    assert tampered["decision"] is None
    assert tampered["ignored_local_integrity"] is not None
    at_expiry = store.resolve_policy_decision_lookup(
        "guard-cli",
        artifact_id,
        artifact_hash,
        now="2026-09-10T00:16:00+00:00",
        consume_one_shot=False,
    )
    assert at_expiry["decision"] is None
