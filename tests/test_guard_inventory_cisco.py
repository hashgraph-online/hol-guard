from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.inventory_cisco import run_cisco_inventory_scans
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import Finding, Severity


@dataclass(frozen=True, slots=True)
class _McpSummary:
    status: CiscoIntegrationStatus
    message: str
    findings: tuple[Finding, ...]
    targets_scanned: int
    analyzers_used: tuple[str, ...]
    total_findings: int
    findings_by_severity: dict[str, int]
    scan_mode: str = "static"


@dataclass(frozen=True, slots=True)
class _SkillSummary:
    status: CiscoIntegrationStatus
    message: str
    findings: tuple[Finding, ...]
    skills_scanned: int
    skills_skipped: tuple[str, ...]
    analyzers_used: tuple[str, ...]
    policy_name: str
    total_findings: int
    findings_by_severity: dict[str, int]


def _ctx(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir(parents=True)
    workspace_dir.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)


def test_cisco_inventory_scans_report_missing_targets_without_running_dependencies(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(),
    )

    runs = run_cisco_inventory_scans(
        harness="hermes",
        context=context,
        detection=detection,
        mcp_mode="auto",
        skill_mode="auto",
    )

    assert [run.source for run in runs] == ["cisco-mcp-scanner", "cisco-skill-scanner"]
    assert all(run.status == "skipped" for run in runs)
    assert all(run.duration_ms == 0 for run in runs)


def test_cisco_inventory_scans_run_mcp_and_skill_scanners_with_required_mode(tmp_path: Path, monkeypatch) -> None:
    context = _ctx(tmp_path)
    (context.workspace_dir / ".mcp.json").write_text('{"mcpServers": {}}\n')
    skill_path = context.home_dir / ".hermes" / "skills" / "ops" / "reviewer" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text("---\nname: reviewer\n---\nReview local files.\n")
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=False,
        config_paths=(str(skill_path),),
        artifacts=(
            GuardArtifact(
                artifact_id="hermes:skill:ops:reviewer",
                name="reviewer",
                harness="hermes",
                artifact_type="skill",
                source_scope="global",
                config_path=str(skill_path),
            ),
        ),
    )
    calls: list[tuple[str, Path, str, float | None]] = []

    def fake_mcp_scan(plugin_dir: Path, mode: str, timeout_seconds: float | None = None) -> _McpSummary:
        calls.append(("mcp", plugin_dir, mode, timeout_seconds))
        return _McpSummary(
            status=CiscoIntegrationStatus.ENABLED,
            message="MCP scanner completed.",
            findings=(),
            targets_scanned=1,
            analyzers_used=("yara",),
            total_findings=0,
            findings_by_severity={severity.value: 0 for severity in Severity},
        )

    def fake_skill_scan(skills_dir: Path, mode: str, timeout_seconds: float | None = None) -> _SkillSummary:
        calls.append(("skill", skills_dir, mode, timeout_seconds))
        return _SkillSummary(
            status=CiscoIntegrationStatus.ENABLED,
            message="Skill scanner completed.",
            findings=(),
            skills_scanned=1,
            skills_skipped=(),
            analyzers_used=("prompt-injection",),
            policy_name="balanced",
            total_findings=0,
            findings_by_severity={severity.value: 0 for severity in Severity},
        )

    monkeypatch.setattr("codex_plugin_scanner.guard.inventory_cisco.run_cisco_mcp_scan", fake_mcp_scan)
    monkeypatch.setattr("codex_plugin_scanner.guard.inventory_cisco.run_cisco_skill_scan", fake_skill_scan)

    runs = run_cisco_inventory_scans(
        harness="hermes",
        context=context,
        detection=detection,
        mcp_mode="on",
        skill_mode="on",
        timeout_seconds=3.5,
    )

    assert [call[0] for call in calls] == ["mcp", "skill"]
    assert calls[0][1] == context.workspace_dir
    assert calls[1][1] == context.home_dir / ".hermes" / "skills"
    assert all(call[2] == "on" and call[3] == 3.5 for call in calls)
    assert all(run.status == "enabled" for run in runs)


def test_cisco_inventory_scans_preserve_timeout_status(tmp_path: Path, monkeypatch) -> None:
    context = _ctx(tmp_path)
    (context.workspace_dir / ".mcp.json").write_text('{"mcpServers": {}}\n')
    detection = HarnessDetection(
        harness="openclaw",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=(),
    )

    def fake_mcp_scan(plugin_dir: Path, mode: str, timeout_seconds: float | None = None) -> object:
        del plugin_dir, mode, timeout_seconds
        return SimpleNamespace(
            status=CiscoIntegrationStatus.TIMED_OUT,
            message="Cisco MCP scanner timed out.",
            findings=(),
            targets_scanned=0,
            analyzers_used=(),
            total_findings=0,
            findings_by_severity={severity.value: 0 for severity in Severity},
            scan_mode="static",
        )

    monkeypatch.setattr("codex_plugin_scanner.guard.inventory_cisco.run_cisco_mcp_scan", fake_mcp_scan)

    runs = run_cisco_inventory_scans(
        harness="openclaw",
        context=context,
        detection=detection,
        mcp_mode="on",
    )

    assert runs[0].source == "cisco-mcp-scanner"
    assert runs[0].status == "timed_out"
    assert runs[0].metadata["targetsScanned"] == 0


def test_cisco_inventory_scans_use_detected_nonstandard_skill_roots(tmp_path: Path, monkeypatch) -> None:
    context = _ctx(tmp_path)
    extra_root = context.home_dir / "shared-openclaw-skills"
    skill_path = extra_root / "reviewer" / "SKILL.md"
    skill_path.parent.mkdir(parents=True)
    skill_path.write_text("---\nname: reviewer\n---\nReview local files.\n")
    detection = HarnessDetection(
        harness="openclaw",
        installed=True,
        command_available=False,
        config_paths=(str(skill_path),),
        artifacts=(
            GuardArtifact(
                artifact_id="openclaw:skill:extra:reviewer",
                name="reviewer",
                harness="openclaw",
                artifact_type="skill",
                source_scope="global",
                config_path=str(skill_path),
                metadata={"skill_root": str(extra_root)},
            ),
        ),
    )
    calls: list[Path] = []

    def fake_skill_scan(skills_dir: Path, mode: str, timeout_seconds: float | None = None) -> _SkillSummary:
        del mode, timeout_seconds
        calls.append(skills_dir)
        return _SkillSummary(
            status=CiscoIntegrationStatus.ENABLED,
            message="Skill scanner completed.",
            findings=(),
            skills_scanned=1,
            skills_skipped=(),
            analyzers_used=("prompt-injection",),
            policy_name="balanced",
            total_findings=0,
            findings_by_severity={severity.value: 0 for severity in Severity},
        )

    monkeypatch.setattr("codex_plugin_scanner.guard.inventory_cisco.run_cisco_skill_scan", fake_skill_scan)

    run_cisco_inventory_scans(
        harness="openclaw",
        context=context,
        detection=detection,
        skill_mode="on",
    )

    assert calls == [extra_root]
