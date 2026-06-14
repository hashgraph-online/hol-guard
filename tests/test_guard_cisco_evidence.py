"""Tests for Cisco scanner evidence normalization."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

from codex_plugin_scanner.guard.runtime.cisco_evidence import (
    cisco_finding_to_risk_signal,
    scanner_cache_key,
)
from codex_plugin_scanner.guard.runtime.signals import GuardRiskSignalV3
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.integrations import cisco_mcp_scanner, cisco_skill_scanner
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import Finding, Severity


def test_cisco_finding_becomes_v3_signal_with_first_class_scanner_fields() -> None:
    finding = Finding(
        rule_id="CISCO-MCP-TOOL-POISONING",
        severity=Severity.HIGH,
        category="security",
        title="Tool poisoning detected",
        description="MCP config exposes a risky tool description.",
        remediation="Review the MCP server before enabling it.",
        file_path=".mcp.json",
        line_number=12,
        source="cisco-mcp-scanner",
    )

    signal = cisco_finding_to_risk_signal(
        finding,
        scanner_status=CiscoIntegrationStatus.ENABLED,
        scanner_name="Cisco MCP scanner",
        source_version="4.6.2",
    )

    assert signal == GuardRiskSignalV3(
        signal_id="cisco-mcp-scanner:CISCO-MCP-TOOL-POISONING:.mcp.json:12",
        source="cisco_mcp",
        source_version="4.6.2",
        category="mcp",
        severity="high",
        confidence="strong",
        title="Tool poisoning detected",
        plain_language_summary="MCP config exposes a risky tool description.",
        technical_detail="Cisco MCP scanner rule CISCO-MCP-TOOL-POISONING reported security evidence.",
        evidence_ref=".mcp.json:12",
        scanner_name="Cisco MCP scanner",
        scanner_status="enabled",
        scanner_rule_id="CISCO-MCP-TOOL-POISONING",
        redaction_level="summary",
        source_path=".mcp.json",
        source_line=12,
        data_source=None,
        data_sink=None,
        recommended_action="Review the MCP server before enabling it.",
    )
    assert signal.to_dict()["scanner_status"] == "enabled"
    assert GuardRiskSignalV3.from_dict(signal.to_dict()) == signal


def test_scanner_cache_key_changes_with_content_hash_or_version() -> None:
    base_key = scanner_cache_key(
        scanner_name="cisco-mcp-scanner",
        input_content_hash="content-a",
        scanner_version="4.6.2",
    )

    assert (
        scanner_cache_key(
            scanner_name="cisco-mcp-scanner",
            input_content_hash="content-b",
            scanner_version="4.6.2",
        )
        != base_key
    )
    assert (
        scanner_cache_key(
            scanner_name="cisco-mcp-scanner",
            input_content_hash="content-a",
            scanner_version="4.7.0",
        )
        != base_key
    )


def test_guard_store_invalidates_scanner_cache_when_hash_or_version_changes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    payload = cast(dict[str, object], {"signals": [{"signal_id": "signal-1"}]})

    store.save_scanner_cache(
        scanner_name="cisco-mcp-scanner",
        target_id="workspace/.mcp.json",
        input_content_hash="hash-a",
        scanner_version="4.6.2",
        payload=payload,
        now="2026-05-08T00:00:00+00:00",
    )

    assert (
        store.get_scanner_cache(
            scanner_name="cisco-mcp-scanner",
            target_id="workspace/.mcp.json",
            input_content_hash="hash-a",
            scanner_version="4.6.2",
        )
        == payload
    )
    assert (
        store.get_scanner_cache(
            scanner_name="cisco-mcp-scanner",
            target_id="workspace/.mcp.json",
            input_content_hash="hash-b",
            scanner_version="4.6.2",
        )
        is None
    )
    assert (
        store.get_scanner_cache(
            scanner_name="cisco-mcp-scanner",
            target_id="workspace/.mcp.json",
            input_content_hash="hash-a",
            scanner_version="4.7.0",
        )
        is None
    )

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select cache_key, payload_json from scanner_cache where scanner_name = ? and target_id = ?",
            ("cisco-mcp-scanner", "workspace/.mcp.json"),
        ).fetchone()

    assert row is not None
    assert str(row[0]) == scanner_cache_key(
        scanner_name="cisco-mcp-scanner",
        input_content_hash="hash-a",
        scanner_version="4.6.2",
    )
    assert json.loads(str(row[1])) == payload


def test_skill_scanner_reports_timeout_without_marking_scan_failed(monkeypatch, tmp_path: Path) -> None:
    class SlowScanner:
        def __init__(self, policy: object) -> None:
            self.policy = policy

        def scan_directory(self, skills_dir: Path) -> object:
            time.sleep(0.05)
            return object()

    class ScanPolicy:
        def __init__(self, preset_base: str) -> None:
            self.preset_base = preset_base

    skill_scanner_module = cast(Any, ModuleType("skill_scanner"))
    skill_scanner_module.SkillScanner = SlowScanner
    scan_policy_module = cast(Any, ModuleType("skill_scanner.core.scan_policy"))
    scan_policy_module.ScanPolicy = ScanPolicy
    monkeypatch.setitem(__import__("sys").modules, "skill_scanner", skill_scanner_module)
    monkeypatch.setitem(__import__("sys").modules, "skill_scanner.core", ModuleType("skill_scanner.core"))
    monkeypatch.setitem(__import__("sys").modules, "skill_scanner.core.scan_policy", scan_policy_module)

    def _raise_timeout(skills_dir: Path, policy_name: str, timeout_seconds: float | None) -> dict[str, object]:
        raise TimeoutError("Cisco skill scanner timed out")

    monkeypatch.setattr(cisco_skill_scanner, "_scan_directory_with_timeout", _raise_timeout)

    summary = cisco_skill_scanner.run_cisco_skill_scan(tmp_path, timeout_seconds=0.001)

    assert summary.status is CiscoIntegrationStatus.TIMED_OUT
    assert "timed out" in summary.message


def test_skill_scanner_timeout_path_drains_worker_result_before_terminating(monkeypatch, tmp_path: Path) -> None:
    output_path = tmp_path / "scan-output.json"

    monkeypatch.setattr(cisco_skill_scanner.tempfile, "mkstemp", lambda prefix, suffix: (123, str(output_path)))
    monkeypatch.setattr(cisco_skill_scanner.os, "close", lambda fd: None)

    def fake_run(*args: object, **kwargs: object) -> object:
        output_path.write_text(
            json.dumps({"summary": {"total_skills_scanned": 0}, "results": []}),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(cisco_skill_scanner.subprocess, "run", fake_run)

    payload = cisco_skill_scanner._scan_directory_with_timeout(tmp_path, "balanced", 0.1)

    assert payload == {"summary": {"total_skills_scanned": 0}, "results": []}
    assert output_path.exists() is False


def test_mcp_scanner_reports_timeout_without_marking_scan_failed(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")

    class SlowAnalyzer:
        async def analyze(self, content: str, metadata: dict[str, str]) -> tuple[object, ...]:
            await cisco_mcp_scanner.asyncio.sleep(0.05)
            return ()

    monkeypatch.setattr(
        cisco_mcp_scanner,
        "_load_mcp_scanner_components",
        lambda blocked_root=None: {"YaraAnalyzer": SlowAnalyzer},
    )

    summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path, timeout_seconds=0.001)

    assert summary.status is CiscoIntegrationStatus.TIMED_OUT
    assert "timed out" in summary.message
