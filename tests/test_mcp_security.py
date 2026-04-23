"""Tests for Cisco MCP security integration."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from codex_plugin_scanner.checks.mcp_security import resolve_mcp_security_context, run_mcp_security_checks
from codex_plugin_scanner.integrations import cisco_mcp_scanner as cisco_mcp_module
from codex_plugin_scanner.integrations.cisco_mcp_scanner import run_cisco_mcp_scan
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import ScanOptions
from codex_plugin_scanner.scanner import scan_plugin

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


def _write_plugin(plugin_dir: Path) -> None:
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


def test_scan_ignores_excluded_descendants(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)
    (plugin_dir / "node_modules").mkdir()
    (plugin_dir / "node_modules" / "ignored.py").write_text("print('ignored')\n", encoding="utf-8")
    analyzed_paths: list[str] = []

    class RecordingYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            analyzed_paths.append(str((context or {}).get("file_path", "")))
            return []

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": RecordingYaraAnalyzer},
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="on")

    assert summary.status == CiscoIntegrationStatus.ENABLED
    assert summary.targets_scanned == 2
    assert all("node_modules" not in path for path in analyzed_paths)


def test_scan_includes_dist_descendants(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)
    (plugin_dir / "dist").mkdir()
    (plugin_dir / "dist" / "server.js").write_text("console.log('dist')\n", encoding="utf-8")
    analyzed_paths: list[str] = []

    class RecordingYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            analyzed_paths.append(str((context or {}).get("file_path", "")))
            return []

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": RecordingYaraAnalyzer},
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="on")

    assert summary.status == CiscoIntegrationStatus.ENABLED
    assert summary.targets_scanned == 3
    assert any(path.endswith("dist/server.js") for path in analyzed_paths)


def test_mcp_security_auto_mode_unavailable_is_not_applicable(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)

    def _raise_import_error() -> object:
        raise ImportError("mcpscanner not installed")

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        _raise_import_error,
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="auto")
    checks = run_mcp_security_checks(plugin_dir, ScanOptions(cisco_mcp_scan="auto"))

    availability = next(check for check in checks if check.name == "Cisco MCP scan completed")
    assert summary.status == CiscoIntegrationStatus.UNAVAILABLE
    assert availability.applicable is False
    assert availability.max_points == 0


def test_mcp_security_on_mode_requires_dependency(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)

    def _raise_import_error() -> object:
        raise ImportError("mcpscanner not installed")

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        _raise_import_error,
    )

    checks = run_mcp_security_checks(plugin_dir, ScanOptions(cisco_mcp_scan="on"))

    availability = next(check for check in checks if check.name == "Cisco MCP scan completed")
    assert availability.passed is False
    assert availability.max_points > 0
    assert availability.findings[0].rule_id == "CISCO-MCP-SCANNER-UNAVAILABLE"


def test_mcp_security_handles_loader_failures(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)

    def _raise_runtime_error() -> object:
        raise RuntimeError("loader boom")

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        _raise_runtime_error,
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="auto")

    assert summary.status == CiscoIntegrationStatus.FAILED
    assert "loader boom" in summary.message


def test_mcp_security_loads_mcpscanner_from_installed_distribution(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)
    trusted_root = tmp_path / "trusted-site"
    trusted_package = trusted_root / "mcpscanner"
    trusted_package.mkdir(parents=True)
    (trusted_package / "__init__.py").write_text(
        "class YaraAnalyzer:\n    pass\n",
        encoding="utf-8",
    )
    (plugin_dir / "mcpscanner.py").write_text(
        "raise RuntimeError('workspace import hijack executed')\n",
        encoding="utf-8",
    )

    class _FakeDistribution:
        def __init__(self, package_root: Path) -> None:
            self._package_root = package_root
            self.files = (_FakeDistributionFile("mcpscanner/__init__.py", package_root / "mcpscanner" / "__init__.py"),)

        def locate_file(self, path: str) -> Path:
            return self._package_root / path

    class _FakeDistributionFile:
        def __init__(self, relative_path: str, absolute_path: Path) -> None:
            self._relative_path = relative_path
            self._absolute_path = absolute_path

        def __str__(self) -> str:
            return self._relative_path

        def locate(self) -> Path:
            return self._absolute_path

    monkeypatch.setattr(
        cisco_mcp_module.importlib_metadata,
        "distribution",
        lambda name: _FakeDistribution(trusted_root),
    )
    monkeypatch.syspath_prepend(str(plugin_dir))

    components = cisco_mcp_module._load_mcp_scanner_components()

    assert components["YaraAnalyzer"].__module__ == "mcpscanner"
    assert Path(sys.modules["mcpscanner"].__file__).resolve() == (trusted_package / "__init__.py").resolve()


def test_mcp_security_supports_editable_distribution_outside_plugin_root(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)
    trusted_root = tmp_path / "editable-src"
    trusted_package = trusted_root / "mcpscanner"
    trusted_package.mkdir(parents=True)
    trusted_init = trusted_package / "__init__.py"
    trusted_init.write_text("class YaraAnalyzer:\n    pass\n", encoding="utf-8")
    (plugin_dir / "mcpscanner.py").write_text(
        "raise RuntimeError('workspace import hijack executed')\n",
        encoding="utf-8",
    )

    class _EditableDistribution:
        files: tuple[()] = ()

    editable_spec = importlib.util.spec_from_file_location(
        "mcpscanner",
        trusted_init,
        submodule_search_locations=[str(trusted_package)],
    )

    monkeypatch.setattr(
        cisco_mcp_module.importlib_metadata,
        "distribution",
        lambda name: _EditableDistribution(),
    )
    monkeypatch.setattr(
        cisco_mcp_module.importlib.util,
        "find_spec",
        lambda name: editable_spec if name == "mcpscanner" else None,
    )
    monkeypatch.syspath_prepend(str(plugin_dir))

    module = cisco_mcp_module._load_distribution_module(
        "cisco-ai-mcp-scanner",
        "mcpscanner",
        blocked_root=plugin_dir,
    )

    assert module.__file__ == str(trusted_init)
    assert Path(sys.modules["mcpscanner"].__file__).resolve() == trusted_init.resolve()


def test_mcp_security_rejects_distribution_spec_inside_plugin_root(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)
    plugin_package = plugin_dir / "mcpscanner"
    plugin_package.mkdir()
    plugin_init = plugin_package / "__init__.py"
    plugin_init.write_text("class YaraAnalyzer:\n    pass\n", encoding="utf-8")

    class _PluginDistributionFile:
        def __str__(self) -> str:
            return "mcpscanner/__init__.py"

        def locate(self) -> Path:
            return plugin_init

    class _PluginDistribution:
        files = (_PluginDistributionFile(),)

    monkeypatch.setattr(
        cisco_mcp_module.importlib_metadata,
        "distribution",
        lambda name: _PluginDistribution(),
    )
    monkeypatch.setattr(cisco_mcp_module.importlib.util, "find_spec", lambda name: None)

    try:
        cisco_mcp_module._load_distribution_module(
            "cisco-ai-mcp-scanner",
            "mcpscanner",
            blocked_root=plugin_dir,
        )
    except ImportError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected plugin-root distribution spec to be rejected")

    assert "Unable to resolve mcpscanner" in message


def test_scan_plugin_includes_cisco_mcp_findings(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)

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
            if file_path.endswith("server.py"):
                return [
                    FakeCiscoFinding(
                        severity="LOW",
                        summary="Detected permissive server behavior",
                        analyzer="YARA",
                        threat_category="behavior",
                        details={"evidence": "server.py"},
                    )
                ]
            return []

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": FakeYaraAnalyzer},
    )

    result = scan_plugin(plugin_dir, ScanOptions(cisco_skill_scan="off", cisco_mcp_scan="on"))

    integration = next(item for item in result.integrations if item.name == "cisco-mcp-scanner")
    security = next(category for category in result.categories if category.name == "Security")
    mcp_findings = [finding for finding in result.findings if finding.source == "cisco-mcp-scanner"]

    assert integration.status == CiscoIntegrationStatus.ENABLED
    assert integration.findings_count == len(mcp_findings)
    assert integration.metadata["scan_mode"] == "static"
    assert integration.metadata["targets_scanned"] == "2"
    assert any(check.name == "Cisco MCP scan completed" for check in security.checks)
    assert {finding.file_path for finding in mcp_findings} == {".mcp.json", "server.py"}


def test_scan_uses_plugin_relative_exclusions(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "dist" / "plugin"
    plugin_dir.mkdir(parents=True)
    _write_plugin(plugin_dir)

    class RecordingYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            return []

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": RecordingYaraAnalyzer},
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="on")

    assert summary.status == CiscoIntegrationStatus.ENABLED
    assert summary.targets_scanned == 2


def test_scan_runs_safely_inside_running_event_loop(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)

    class RecordingYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            return []

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": RecordingYaraAnalyzer},
    )

    async def _run_scan() -> CiscoIntegrationStatus:
        return run_cisco_mcp_scan(plugin_dir, mode="on").status

    status = asyncio.run(_run_scan())

    assert status == CiscoIntegrationStatus.ENABLED


def test_mcp_security_skips_plugins_without_mcp_config() -> None:
    context = resolve_mcp_security_context(FIXTURES / "good-plugin", ScanOptions(cisco_mcp_scan="on"))
    checks = run_mcp_security_checks(FIXTURES / "good-plugin", ScanOptions(cisco_mcp_scan="on"), context)

    assert context.target_present is False
    assert all(check.applicable is False for check in checks)


def test_mcp_security_handles_scanner_failures(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)

    class ExplodingYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": ExplodingYaraAnalyzer},
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="on")

    assert summary.status == CiscoIntegrationStatus.FAILED
    assert "boom" in summary.message


def test_targets_scanned_counts_only_processed_targets(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)
    original_read_text = Path.read_text

    class RecordingYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            return []

    def _read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "server.py":
            raise OSError("unreadable")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _read_text)
    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": RecordingYaraAnalyzer},
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="on")

    assert summary.status == CiscoIntegrationStatus.ENABLED
    assert summary.targets_scanned == 1


def test_scan_skips_oversized_mcp_config(monkeypatch, tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin"
    _write_plugin(plugin_dir)
    config_path = plugin_dir / ".mcp.json"
    config_path.write_text("x" * 1_100_000, encoding="utf-8")
    analyzed_paths: list[str] = []

    class RecordingYaraAnalyzer:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        async def analyze(self, content: str, context: dict[str, Any] | None = None) -> list[FakeCiscoFinding]:
            analyzed_paths.append(str((context or {}).get("file_path", "")))
            return []

    monkeypatch.setattr(
        "codex_plugin_scanner.integrations.cisco_mcp_scanner._load_mcp_scanner_components",
        lambda: {"YaraAnalyzer": RecordingYaraAnalyzer},
    )

    summary = run_cisco_mcp_scan(plugin_dir, mode="on")

    assert summary.status == CiscoIntegrationStatus.ENABLED
    assert summary.targets_scanned == 1
    assert all(not path.endswith(".mcp.json") for path in analyzed_paths)
