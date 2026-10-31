"""Tests for Cisco scanner evidence normalization."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from codex_plugin_scanner.integrations import cisco_mcp_scanner, cisco_skill_scanner
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.integrations.scanner_subprocess import ScannerProcessResult


def test_skill_scanner_reports_timeout_without_marking_scan_failed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cisco_skill_scanner.sys, "version_info", (3, 13, 0))

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


def test_skill_scanner_subprocess_run_success(monkeypatch, tmp_path: Path) -> None:
    output_path = tmp_path / "scan-output.json"

    monkeypatch.setattr(cisco_skill_scanner.tempfile, "mkstemp", lambda prefix, suffix: (123, str(output_path)))
    monkeypatch.setattr(cisco_skill_scanner.os, "close", lambda fd: None)

    def fake_run(*args: object, **kwargs: object) -> ScannerProcessResult:
        output_path.write_text(
            json.dumps({"summary": {"total_skills_scanned": 0}, "results": []}),
            encoding="utf-8",
        )
        return ScannerProcessResult(0, "", "")

    monkeypatch.setattr(cisco_skill_scanner, "run_bounded_scanner_process", fake_run)

    payload = cisco_skill_scanner._scan_directory_with_timeout(tmp_path, "balanced", 0.1)

    assert payload == {"summary": {"total_skills_scanned": 0}, "results": []}
    assert output_path.exists() is False


def test_skill_scanner_timeout_path_cleans_temp_file_on_timeout(monkeypatch, tmp_path: Path) -> None:
    output_path = tmp_path / "scan-timeout.json"

    monkeypatch.setattr(cisco_skill_scanner.tempfile, "mkstemp", lambda prefix, suffix: (123, str(output_path)))
    monkeypatch.setattr(cisco_skill_scanner.os, "close", lambda fd: None)

    def fake_run(*args: object, **kwargs: object) -> ScannerProcessResult:
        output_path.write_text("{}", encoding="utf-8")
        return ScannerProcessResult(-9, "", "", timed_out=True)

    monkeypatch.setattr(cisco_skill_scanner, "run_bounded_scanner_process", fake_run)

    with pytest.raises(TimeoutError, match="timed out"):
        cisco_skill_scanner._scan_directory_with_timeout(tmp_path, "balanced", 0.1)

    assert output_path.exists() is False


def test_skill_scanner_none_timeout_still_uses_isolated_default(monkeypatch, tmp_path: Path) -> None:
    output_path = tmp_path / "scan-result.json"
    observed_timeouts: list[float] = []
    monkeypatch.setattr(cisco_skill_scanner.tempfile, "mkstemp", lambda prefix, suffix: (123, str(output_path)))
    monkeypatch.setattr(cisco_skill_scanner.os, "close", lambda fd: None)

    def fake_run(*args: object, **kwargs: object) -> ScannerProcessResult:
        observed_timeouts.append(float(kwargs["timeout_seconds"]))
        output_path.write_text('{"summary": {}, "results": []}', encoding="utf-8")
        return ScannerProcessResult(0, "", "")

    monkeypatch.setattr(cisco_skill_scanner, "run_bounded_scanner_process", fake_run)

    cisco_skill_scanner._scan_directory_with_timeout(tmp_path, "balanced", None)

    assert observed_timeouts == [cisco_skill_scanner.DEFAULT_CISCO_SKILL_TIMEOUT_SECONDS]


def test_mcp_scanner_reports_timeout_without_marking_scan_failed(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cisco_mcp_scanner, "_cisco_mcp_scanner_runnable", lambda: True)

    monkeypatch.setattr(
        cisco_mcp_scanner,
        "run_bounded_scanner_process",
        lambda *_args, **_kwargs: ScannerProcessResult(-9, "", "", timed_out=True),
    )

    summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path, timeout_seconds=0.001)

    assert summary.status is CiscoIntegrationStatus.TIMED_OUT
    assert "timed out" in summary.message


def test_mcp_scanner_none_timeout_still_uses_isolated_default(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cisco_mcp_scanner, "_cisco_mcp_scanner_runnable", lambda: True)
    observed_timeouts: list[float] = []

    def fake_run(*_args: object, **kwargs: object) -> ScannerProcessResult:
        observed_timeouts.append(float(kwargs["timeout_seconds"]))
        return ScannerProcessResult(-9, "", "", timed_out=True)

    monkeypatch.setattr(cisco_mcp_scanner, "run_bounded_scanner_process", fake_run)

    summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path, timeout_seconds=None)

    assert summary.status is CiscoIntegrationStatus.TIMED_OUT
    assert observed_timeouts == [cisco_mcp_scanner.DEFAULT_CISCO_MCP_TIMEOUT_SECONDS]


def _refuse_scanner_child(*_args: object, **_kwargs: object) -> ScannerProcessResult:
    raise AssertionError("the scan started a child process it could not use")


def test_mcp_scanner_skips_without_a_child_when_there_is_no_mcp_configuration(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cisco_mcp_scanner, "run_bounded_scanner_process", _refuse_scanner_child)

    summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path, mode="on")

    assert summary.status is CiscoIntegrationStatus.SKIPPED
    assert summary.message == "No MCP configuration found; Cisco MCP scan skipped."


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("auto", "Cisco MCP scanner not installed; deep MCP scan skipped."),
        ("on", "Cisco MCP scanner is required but not installed. Ensure package dependencies are installed."),
    ],
)
def test_mcp_scanner_reports_a_missing_scanner_without_a_child(
    monkeypatch, tmp_path: Path, mode: str, message: str
) -> None:
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cisco_mcp_scanner, "run_bounded_scanner_process", _refuse_scanner_child)

    def missing(name: str) -> object:
        raise cisco_mcp_scanner.importlib_metadata.PackageNotFoundError(name)

    monkeypatch.setattr(cisco_mcp_scanner.importlib_metadata, "distribution", missing)

    summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path, mode=mode)

    assert summary.status is CiscoIntegrationStatus.UNAVAILABLE
    assert summary.message == message


def test_packaged_guard_reports_the_mcp_scanner_unavailable_without_a_child(monkeypatch, tmp_path: Path) -> None:
    """A onefile Guard cannot run ``-c`` code; each child re-extracted the runtime only to fail."""

    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cisco_mcp_scanner, "run_bounded_scanner_process", _refuse_scanner_child)
    monkeypatch.setattr(cisco_mcp_scanner.importlib_metadata, "distribution", lambda name: object())
    monkeypatch.setattr(cisco_mcp_scanner.sys, "frozen", True, raising=False)

    summary = cisco_mcp_scanner.run_cisco_mcp_scan(tmp_path)

    assert summary.status is CiscoIntegrationStatus.UNAVAILABLE
