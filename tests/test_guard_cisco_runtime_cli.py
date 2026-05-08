"""Tests for Guard Cisco runtime and deep-scan integration."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.receipts import build_receipt
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.cisco_evidence import cisco_finding_to_risk_signal
from codex_plugin_scanner.guard.runtime.detectors import register_default_detectors
from codex_plugin_scanner.guard.runtime.signals import GuardRiskSignalV3
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.integrations import cisco_mcp_scanner, cisco_skill_scanner
from codex_plugin_scanner.integrations.cisco_mcp_scanner import CiscoMcpScanSummary
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus, CiscoSkillScanSummary
from codex_plugin_scanner.models import Finding, Severity


def _empty_counts() -> dict[str, int]:
    return {severity.value: 0 for severity in Severity}


def _skill_summary(status: CiscoIntegrationStatus, findings: tuple[Finding, ...] = ()) -> CiscoSkillScanSummary:
    counts = _empty_counts()
    for finding in findings:
        counts[finding.severity.value] += 1
    return CiscoSkillScanSummary(
        status=status,
        message=f"skill scanner {status.value}",
        findings=findings,
        skills_scanned=1 if findings else 0,
        skills_skipped=(),
        analyzers_used=("static",),
        policy_name="balanced",
        total_findings=len(findings),
        findings_by_severity=counts,
    )


def _mcp_summary(status: CiscoIntegrationStatus, findings: tuple[Finding, ...] = ()) -> CiscoMcpScanSummary:
    counts = _empty_counts()
    for finding in findings:
        counts[finding.severity.value] += 1
    return CiscoMcpScanSummary(
        status=status,
        message=f"mcp scanner {status.value}",
        findings=findings,
        targets_scanned=1 if findings else 0,
        analyzers_used=("yara",),
        total_findings=len(findings),
        findings_by_severity=counts,
    )


def _skill_finding(severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        rule_id="CISCO-SKILL-EXFIL",
        severity=severity,
        category="skill-security",
        title="Skill exfiltration",
        description="Skill asks the agent to send secrets away.",
        remediation="Remove the exfiltration instruction.",
        file_path="demo/SKILL.md",
        line_number=4,
        source="cisco-skill-scanner",
    )


def _mcp_finding(severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        rule_id="CISCO-MCP-POISON",
        severity=severity,
        category="mcp-security",
        title="MCP tool poisoning",
        description="MCP server describes a hidden destructive tool.",
        remediation="Disable the server until reviewed.",
        file_path=".mcp.json",
        line_number=2,
        source="cisco-mcp-scanner",
    )


def _file_write_action(path: Path, workspace: Path) -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="PreToolUse",
        action_type="file_write",
        workspace="~/workspace",
        workspace_hash="workspace-hash",
        tool_name="Write",
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(str(path.relative_to(workspace)),),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={"file_path": str(path.relative_to(workspace))},
    )


def test_default_detector_registry_includes_cisco_sources() -> None:
    detector_ids = {detector.detector_id for detector in register_default_detectors()}

    assert "cisco.skill" in detector_ids
    assert "cisco.mcp" in detector_ids


def test_guard_scan_skills_deep_uses_cisco_skill_scanner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skills_dir = tmp_path / "skills" / "demo"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("# Demo\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_scan(path: Path, mode: str = "auto", policy_name: str = "balanced", timeout_seconds: float | None = None):
        captured["path"] = path
        captured["mode"] = mode
        captured["timeout_seconds"] = timeout_seconds
        return _skill_summary(CiscoIntegrationStatus.ENABLED, (_skill_finding(),))

    monkeypatch.setattr(cisco_skill_scanner, "run_cisco_skill_scan", fake_scan)

    rc = main(
        [
            "guard",
            "scan",
            "skills",
            "--deep",
            "--workspace",
            str(tmp_path),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--cisco-mode",
            "on",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert captured["path"] == tmp_path / "skills"
    assert captured["mode"] == "on"
    assert payload["scan_type"] == "skills"
    assert payload["status"] == "enabled"
    assert payload["scanner_evidence"][0]["source"] == "cisco_skill"
    assert payload["policy_action"] == "require-reapproval"


def test_guard_scan_mcp_deep_uses_cisco_mcp_scanner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_scan(path: Path, mode: str = "auto", timeout_seconds: float | None = None):
        captured["path"] = path
        captured["mode"] = mode
        captured["timeout_seconds"] = timeout_seconds
        return _mcp_summary(CiscoIntegrationStatus.ENABLED, (_mcp_finding(),))

    monkeypatch.setattr(cisco_mcp_scanner, "run_cisco_mcp_scan", fake_scan)

    rc = main(
        [
            "guard",
            "scan",
            "mcp",
            "--deep",
            "--workspace",
            str(tmp_path),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--cisco-mode",
            "on",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert captured["path"] == tmp_path
    assert captured["mode"] == "on"
    assert payload["scan_type"] == "mcp"
    assert payload["status"] == "enabled"
    assert payload["scanner_evidence"][0]["source"] == "cisco_mcp"
    assert payload["policy_action"] == "require-reapproval"


def test_cisco_preflight_changed_skill_file_produces_normalized_signal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.runtime.cisco_preflight import scan_action_for_cisco_evidence

    skill_path = tmp_path / "skills" / "demo" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text("# Demo\n", encoding="utf-8")
    monkeypatch.setattr(
        cisco_skill_scanner,
        "run_cisco_skill_scan",
        lambda *args, **kwargs: _skill_summary(CiscoIntegrationStatus.ENABLED, (_skill_finding(),)),
    )

    signals = scan_action_for_cisco_evidence(_file_write_action(skill_path, tmp_path), workspace=tmp_path)

    assert [signal.source for signal in signals] == ["cisco_skill"]
    assert signals[0].scanner_rule_id == "CISCO-SKILL-EXFIL"


def test_cisco_preflight_changed_mcp_config_produces_normalized_signal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.runtime.cisco_preflight import scan_action_for_cisco_evidence

    mcp_path = tmp_path / ".mcp.json"
    mcp_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        cisco_mcp_scanner,
        "run_cisco_mcp_scan",
        lambda *args, **kwargs: _mcp_summary(CiscoIntegrationStatus.ENABLED, (_mcp_finding(),)),
    )

    signals = scan_action_for_cisco_evidence(_file_write_action(mcp_path, tmp_path), workspace=tmp_path)

    assert [signal.source for signal in signals] == ["cisco_mcp"]
    assert signals[0].scanner_rule_id == "CISCO-MCP-POISON"


def test_cisco_policy_blocks_critical_balanced_but_not_low_confidence_info(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.cisco_preflight import policy_action_for_cisco_signals

    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)
    critical = cisco_finding_to_risk_signal(
        _mcp_finding(Severity.CRITICAL),
        scanner_status=CiscoIntegrationStatus.ENABLED,
    )
    info = cisco_finding_to_risk_signal(
        _skill_finding(Severity.INFO),
        scanner_status=CiscoIntegrationStatus.ENABLED,
    )

    assert policy_action_for_cisco_signals((critical,), config=config, harness="codex") == "require-reapproval"
    assert policy_action_for_cisco_signals((info,), config=config, harness="codex") == "require-reapproval"


def test_cisco_unavailable_and_failed_modes_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "skill_scanner" or name.startswith("skill_scanner."):
            raise ImportError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    skill_summary = cisco_skill_scanner.run_cisco_skill_scan(tmp_path, mode="on")
    monkeypatch.setattr(
        cisco_mcp_scanner,
        "_load_mcp_scanner_components",
        lambda blocked_root=None: (_ for _ in ()).throw(ImportError("missing")),
    )
    mcp_summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path, mode="on")
    monkeypatch.setattr(
        cisco_mcp_scanner,
        "_load_mcp_scanner_components",
        lambda blocked_root=None: (_ for _ in ()).throw(RuntimeError("broken")),
    )
    failed_summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path, mode="on")

    assert skill_summary.status is CiscoIntegrationStatus.UNAVAILABLE
    assert mcp_summary.status is CiscoIntegrationStatus.UNAVAILABLE
    assert failed_summary.status is CiscoIntegrationStatus.FAILED


def test_scanner_evidence_persists_on_receipts_and_approval_requests(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    signal = cisco_finding_to_risk_signal(
        _skill_finding(),
        scanner_status=CiscoIntegrationStatus.ENABLED,
    ).to_dict()
    receipt = build_receipt(
        harness="codex",
        artifact_id="artifact-1",
        artifact_hash="hash-1",
        policy_decision="block",
        capabilities_summary="skill changed",
        changed_capabilities=["skill"],
        provenance_summary="runtime request",
        artifact_name="Demo skill",
        source_scope="workspace",
        scanner_evidence=[signal],
    )
    request = GuardApprovalRequest(
        request_id="request-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Demo skill",
        artifact_hash="hash-1",
        policy_action="block",
        recommended_scope="artifact",
        changed_fields=("skill",),
        source_scope="workspace",
        config_path="skills/demo/SKILL.md",
        review_command="hol-guard approvals approve request-1",
        approval_url="http://127.0.0.1:4999/approvals/request-1",
        scanner_evidence=(signal,),
    )

    store.add_receipt(receipt)
    store.add_approval_request(request, "2026-05-08T00:00:00+00:00")

    assert store.list_receipts()[0]["scanner_evidence"] == [signal]
    assert store.get_approval_request("request-1")["scanner_evidence"] == [signal]
    assert GuardRiskSignalV3.from_dict(store.list_receipts()[0]["scanner_evidence"][0]) is not None
