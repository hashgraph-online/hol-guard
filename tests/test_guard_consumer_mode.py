"""Tests for Guard consumer-mode Cisco integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.schemas.consumer_mode import build_consumer_mode_contract
from codex_plugin_scanner.models import IntegrationResult, ScanOptions, ScanResult

FIXTURES = Path(__file__).parent / "fixtures"


class FakeCiscoFinding:
    def __init__(
        self,
        *,
        severity: str,
        summary: str,
        analyzer: str,
        threat_category: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.severity = severity
        self.summary = summary
        self.analyzer = analyzer
        self.threat_category = threat_category
        self.details = details or {}


def _write_mcp_plugin(plugin_dir: Path) -> None:
    (plugin_dir / ".codex-plugin").mkdir(parents=True)
    (plugin_dir / ".codex-plugin" / "plugin.json").write_text(
        json.dumps({"name": "mcp-plugin", "version": "1.0.0", "description": "fixture"}),
        encoding="utf-8",
    )
    (plugin_dir / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"demo": {"command": "python", "args": ["server.py"]}}}),
        encoding="utf-8",
    )
    (plugin_dir / "server.py").write_text("print('hello')\n", encoding="utf-8")


def _build_fake_cisco_components() -> dict[str, type]:
    class FakeYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            file_path = str((context or {}).get("file_path", ""))
            if file_path.endswith(".mcp.json"):
                return [
                    FakeCiscoFinding(
                        severity="HIGH",
                        summary="Detected command injection",
                        analyzer="YARA",
                        threat_category="command_injection",
                        details={"raw_response": {"rule": "MCP_COMMAND_INJECTION"}},
                    )
                ]
            return []

    return {"YaraAnalyzer": FakeYaraAnalyzer}


def _build_scan_options(mode: str) -> ScanOptions:
    return ScanOptions(cisco_skill_scan=mode, cisco_mcp_scan=mode)


def test_build_consumer_mode_contract_includes_cisco_evidence_for_local_mcp_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_mcp_plugin(plugin_dir)
    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        _build_fake_cisco_components,
    )

    payload = build_consumer_mode_contract(plugin_dir, options=_build_scan_options("on"))

    cisco_evidence = payload["cisco_evidence"]

    assert cisco_evidence["mode"] == "offline-only"
    assert cisco_evidence["status"] == "enabled"
    assert cisco_evidence["finding_count"] == 1
    assert cisco_evidence["target_count"] == 2
    assert cisco_evidence["summary"] == "1 finding across 2 local MCP target(s)"
    assert cisco_evidence["integrations"][0]["name"] == "cisco-mcp-scanner"
    assert any(
        integration["name"] == "cisco-mcp-scanner" for integration in payload["trust_evidence_bundle"]["integrations"]
    )


def test_build_consumer_mode_contract_omits_cisco_evidence_without_local_mcp_artifact() -> None:
    payload = build_consumer_mode_contract(FIXTURES / "good-plugin", options=_build_scan_options("on"))

    assert "cisco_evidence" not in payload


def test_build_consumer_mode_contract_includes_rebased_cisco_mcp_integration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "repo"
    target.mkdir()

    def fake_scan_plugin(path: Path, options: ScanOptions | None = None) -> ScanResult:
        return ScanResult(
            score=92,
            grade="A",
            categories=(),
            timestamp="2026-04-13T00:00:00+00:00",
            plugin_dir=str(path),
            findings=(),
            severity_counts={severity: 0 for severity in ("critical", "high", "medium", "low", "info")},
            integrations=(
                IntegrationResult(
                    name="workspace / cisco-mcp-scanner",
                    status="enabled",
                    message="Cisco MCP scanner completed static analysis for 2 target(s) with no findings.",
                    metadata={"scan_mode": "static", "targets_scanned": "2"},
                ),
            ),
            scope="repository",
            ecosystems=("codex",),
            packages=(),
        )

    monkeypatch.setattr("codex_plugin_scanner.guard.schemas.consumer_mode.scan_plugin", fake_scan_plugin)

    payload = build_consumer_mode_contract(target)

    assert payload["cisco_evidence"]["summary"] == "0 findings across 2 local MCP target(s)"
    assert payload["cisco_evidence"]["integrations"][0]["name"] == "workspace / cisco-mcp-scanner"


@pytest.mark.parametrize("command", ["scan", "preflight", "explain"])
def test_guard_render_surfaces_cisco_evidence_for_local_mcp_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_mcp_plugin(plugin_dir)
    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        _build_fake_cisco_components,
    )
    payload = build_consumer_mode_contract(plugin_dir, options=_build_scan_options("on"))

    emit_guard_payload(command, payload, as_json=False)
    output = capsys.readouterr().out

    assert "Cisco static scan evidence" in output
    assert "offline only" in output
    assert "1 finding across 2 local MCP target(s)" in output


@pytest.mark.parametrize(
    ("argv", "expected_harness"),
    [
        (["guard", "scan", "TARGET", "--cisco-mode", "off", "--json"], None),
        (["guard", "preflight", "TARGET", "--harness", "codex", "--cisco-mode", "on", "--json"], "codex"),
    ],
)
def test_guard_commands_thread_cisco_mode_to_consumer_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    expected_harness: str | None,
) -> None:
    captured: dict[str, object] = {}
    target = tmp_path / "target"
    target.mkdir()

    def fake_run_consumer_scan(
        path: Path,
        intended_harness: str | None = None,
        options: ScanOptions | None = None,
    ) -> dict[str, object]:
        captured["path"] = path
        captured["intended_harness"] = intended_harness
        captured["options"] = options
        return {"ok": True}

    monkeypatch.setattr(guard_commands_module, "run_consumer_scan", fake_run_consumer_scan)

    resolved_argv = [str(target) if value == "TARGET" else value for value in argv]
    rc = main(resolved_argv)
    json.loads(capsys.readouterr().out)

    options = captured["options"]

    assert rc == 0
    assert captured["path"] == target.resolve()
    assert captured["intended_harness"] == expected_harness
    assert isinstance(options, ScanOptions)
    assert options.cisco_skill_scan == resolved_argv[resolved_argv.index("--cisco-mode") + 1]
    assert options.cisco_mcp_scan == resolved_argv[resolved_argv.index("--cisco-mode") + 1]


def test_guard_explain_threads_cisco_mode_for_local_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured: dict[str, object] = {}
    target = tmp_path / "target"
    target.mkdir()

    def fake_run_consumer_scan(
        path: Path,
        intended_harness: str | None = None,
        options: ScanOptions | None = None,
    ) -> dict[str, object]:
        captured["path"] = path
        captured["intended_harness"] = intended_harness
        captured["options"] = options
        return {
            "artifact_snapshot": {"path": str(path)},
            "capability_manifest": {"ecosystems": ["codex"]},
            "policy_recommendation": {"action": "allow"},
            "cisco_evidence": {
                "mode": "offline-only",
                "status": "skipped",
                "finding_count": 0,
                "target_count": 1,
                "summary": "Cisco MCP scanning disabled for 1 local MCP target(s)",
                "integrations": [
                    {
                        "name": "cisco-mcp-scanner",
                        "status": "skipped",
                        "message": "Cisco MCP scanning disabled by configuration.",
                        "findings_count": 0,
                        "metadata": {},
                    }
                ],
            },
        }

    monkeypatch.setattr(guard_commands_module, "run_consumer_scan", fake_run_consumer_scan)

    rc = main(["guard", "explain", str(target), "--cisco-mode", "off"])
    output = capsys.readouterr().out
    options = captured["options"]

    assert rc == 0
    assert captured["path"] == target.resolve()
    assert captured["intended_harness"] is None
    assert isinstance(options, ScanOptions)
    assert options.cisco_skill_scan == "off"
    assert options.cisco_mcp_scan == "off"
    assert "Cisco static scan evidence" in output
    assert "Cisco MCP scanning disabled for 1 local MCP target(s)" in output
