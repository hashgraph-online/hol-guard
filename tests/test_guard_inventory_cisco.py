"""The Cisco inventory pass runs what the resident chose, and says when it could not.

Choosing the targets moved into the ``inventory_scan_targets`` resident op, so
what is pinned here is the pass itself: that every chosen target is scanned,
that one timeout budget is shared across the whole pass, and that a resident
that cannot answer leaves a reported non-result rather than a clean inventory
of configurations nothing opened.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import chain, repeat
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.inventory_cisco as inventory_cisco
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.inventory_cisco import run_cisco_inventory_scans
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.native_inventory_scan_targets import (
    CiscoMcpScanTarget,
    CiscoScanTargets,
    InventoryScanTargetsUnavailableError,
)
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


def _detection(*artifacts: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=False,
        config_paths=(),
        artifacts=artifacts,
    )


def _no_severities() -> dict[str, int]:
    return {severity.value: 0 for severity in Severity}


def _mcp_enabled(targets_scanned: int = 1) -> _McpSummary:
    return _McpSummary(
        status=CiscoIntegrationStatus.ENABLED,
        message="MCP scanner completed.",
        findings=(),
        targets_scanned=targets_scanned,
        analyzers_used=("yara",),
        total_findings=0,
        findings_by_severity=_no_severities(),
    )


def _skill_enabled() -> _SkillSummary:
    return _SkillSummary(
        status=CiscoIntegrationStatus.ENABLED,
        message="Skill scanner completed.",
        findings=(),
        skills_scanned=1,
        skills_skipped=(),
        analyzers_used=("prompt-injection",),
        policy_name="balanced",
        total_findings=0,
        findings_by_severity=_no_severities(),
    )


def _chosen(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mcp_targets: tuple[CiscoMcpScanTarget, ...] = (),
    skill_roots: tuple[Path, ...] = (),
) -> list[dict[str, object]]:
    """Answer for the resident; the returned list records every ask."""

    asked: list[dict[str, object]] = []

    def fake(**kwargs: object) -> CiscoScanTargets:
        asked.append(kwargs)
        return CiscoScanTargets(mcp_targets=mcp_targets, skill_roots=skill_roots)

    monkeypatch.setattr(inventory_cisco, "native_inventory_scan_targets", fake)
    return asked


def _unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(**_kwargs: object) -> CiscoScanTargets:
        raise InventoryScanTargetsUnavailableError

    monkeypatch.setattr(inventory_cisco, "native_inventory_scan_targets", fake)


def test_a_pass_with_both_scanners_off_asks_the_resident_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked = _chosen(monkeypatch)
    runs = run_cisco_inventory_scans(
        harness="codex",
        context=_ctx(tmp_path),
        detection=_detection(),
        mcp_mode="off",
        skill_mode="off",
    )
    assert runs == ()
    assert asked == []


def test_the_resident_is_asked_once_with_the_passs_own_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _ctx(tmp_path)
    artifact = GuardArtifact(
        artifact_id="codex:skill:reviewer",
        name="reviewer",
        harness="codex",
        artifact_type="skill",
        source_scope="global",
        config_path=str(context.home_dir / "skills" / "reviewer" / "SKILL.md"),
    )
    asked = _chosen(monkeypatch)

    run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=_detection(artifact),
        mcp_mode="auto",
        skill_mode="auto",
    )

    (ask,) = asked
    assert ask["harness"] == "codex"
    assert ask["home_dir"] == context.home_dir
    assert ask["workspace_dir"] == context.workspace_dir
    assert ask["guard_home"] == context.guard_home
    assert ask["artifacts"] == (artifact,)


def test_nothing_chosen_reports_a_skipped_scan_rather_than_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _chosen(monkeypatch)
    runs = run_cisco_inventory_scans(
        harness="codex",
        context=_ctx(tmp_path),
        detection=_detection(),
        mcp_mode="auto",
        skill_mode="auto",
    )

    assert [run.source for run in runs] == ["cisco-mcp-scanner", "cisco-skill-scanner"]
    assert all(run.status == "skipped" for run in runs)
    assert all(run.duration_ms == 0 for run in runs)


def test_a_resident_that_cannot_choose_reports_an_unavailable_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A clean report would describe configurations nothing opened."""

    _unavailable(monkeypatch)

    def never(*args: object, **kwargs: object) -> object:
        raise AssertionError("no scanner may run without a chosen target")

    monkeypatch.setattr(inventory_cisco, "run_cisco_mcp_scan", never)
    monkeypatch.setattr(inventory_cisco, "run_cisco_skill_scan", never)

    runs = run_cisco_inventory_scans(
        harness="codex",
        context=_ctx(tmp_path),
        detection=_detection(),
        mcp_mode="auto",
        skill_mode="auto",
    )

    assert [run.source for run in runs] == ["cisco-mcp-scanner", "cisco-skill-scanner"]
    assert all(run.status == "unavailable" for run in runs)
    assert all(run.metadata["target"] == "unavailable" for run in runs)
    assert runs[0].metadata["targetsScanned"] == 0
    assert runs[1].metadata["skillsScanned"] == 0


def test_an_unavailable_resident_reports_only_the_scanners_that_were_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _unavailable(monkeypatch)
    runs = run_cisco_inventory_scans(
        harness="codex",
        context=_ctx(tmp_path),
        detection=_detection(),
        mcp_mode="on",
        skill_mode="off",
    )
    assert [run.source for run in runs] == ["cisco-mcp-scanner"]


def test_every_chosen_configuration_is_scanned_under_the_root_it_was_chosen_with(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _ctx(tmp_path)
    workspace_dir = context.workspace_dir
    assert workspace_dir is not None
    config = workspace_dir / ".cursor" / "mcp.json"
    target = CiscoMcpScanTarget(root=workspace_dir, config_path=config, label=".cursor/mcp.json")
    _chosen(monkeypatch, mcp_targets=(target,))
    calls: list[tuple[Path, Path | None, str]] = []

    def fake_mcp_scan(
        plugin_dir: Path,
        mode: str,
        timeout_seconds: float | None = None,
        config_path: Path | None = None,
    ) -> _McpSummary:
        del timeout_seconds
        calls.append((plugin_dir, config_path, mode))
        return _mcp_enabled()

    monkeypatch.setattr(inventory_cisco, "run_cisco_mcp_scan", fake_mcp_scan)

    runs = run_cisco_inventory_scans(
        harness="cursor",
        context=context,
        detection=_detection(),
        mcp_mode="on",
        skill_mode="off",
    )

    assert calls == [(workspace_dir, config, "on")]
    (run,) = runs
    assert run.status == "enabled"
    assert run.metadata["target"] == ".cursor/mcp.json"
    assert run.metadata["_targetPath"] == str(workspace_dir)
    assert run.metadata["_configPath"] == str(config)


def test_a_findings_target_is_the_label_the_resident_chose_not_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The label never spells out a directory above the scan."""

    context = _ctx(tmp_path)
    outside = tmp_path / "elsewhere"
    target = CiscoMcpScanTarget(
        root=outside,
        config_path=outside / ".mcp.json",
        label=".mcp.json",
    )
    _chosen(monkeypatch, mcp_targets=(target,))
    monkeypatch.setattr(
        inventory_cisco,
        "run_cisco_mcp_scan",
        lambda *args, **kwargs: _mcp_enabled(),
    )

    (run,) = run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=_detection(),
        mcp_mode="on",
        skill_mode="off",
    )

    assert run.metadata["target"] == ".mcp.json"


def test_every_chosen_skill_collection_is_walked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _ctx(tmp_path)
    home_dir = context.home_dir
    assert home_dir is not None
    roots = (home_dir / ".agents" / "skills", home_dir / ".claude" / "skills")
    _chosen(monkeypatch, skill_roots=roots)
    calls: list[Path] = []

    def fake_skill_scan(skills_dir: Path, mode: str, timeout_seconds: float | None = None) -> _SkillSummary:
        del mode, timeout_seconds
        calls.append(skills_dir)
        return _skill_enabled()

    monkeypatch.setattr(inventory_cisco, "run_cisco_skill_scan", fake_skill_scan)

    runs = run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=_detection(),
        skill_mode="auto",
    )

    assert calls == list(roots)
    assert [run.metadata["target"] for run in runs] == [str(root) for root in roots]


def test_a_scanners_own_timeout_status_is_reported_as_it_came_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _ctx(tmp_path)
    workspace_dir = context.workspace_dir
    assert workspace_dir is not None
    target = CiscoMcpScanTarget(
        root=workspace_dir,
        config_path=workspace_dir / ".mcp.json",
        label=".mcp.json",
    )
    _chosen(monkeypatch, mcp_targets=(target,))
    monkeypatch.setattr(
        inventory_cisco,
        "run_cisco_mcp_scan",
        lambda *args, **kwargs: _McpSummary(
            status=CiscoIntegrationStatus.TIMED_OUT,
            message="Cisco MCP scanner timed out.",
            findings=(),
            targets_scanned=0,
            analyzers_used=(),
            total_findings=0,
            findings_by_severity=_no_severities(),
        ),
    )

    (run,) = run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=_detection(),
        mcp_mode="on",
    )

    assert run.status == "timed_out"
    assert run.metadata["targetsScanned"] == 0


def test_one_timeout_budget_is_shared_across_the_whole_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _ctx(tmp_path)
    workspace_dir = context.workspace_dir
    home_dir = context.home_dir
    assert workspace_dir is not None and home_dir is not None
    _chosen(
        monkeypatch,
        mcp_targets=(
            CiscoMcpScanTarget(
                root=workspace_dir,
                config_path=workspace_dir / ".mcp.json",
                label=".mcp.json",
            ),
        ),
        skill_roots=(home_dir / ".agents" / "skills",),
    )
    timeouts: list[tuple[str, float | None]] = []
    # The clock stands still while the MCP scan runs and then jumps once, so
    # the skill scanner is handed whatever the MCP half left behind.
    clock = chain([0.0, 0.0, 0.0, 0.0], repeat(1.0))
    monkeypatch.setattr(inventory_cisco.time, "perf_counter", lambda: next(clock))

    def fake_mcp_scan(
        plugin_dir: Path,
        mode: str,
        timeout_seconds: float | None = None,
        config_path: Path | None = None,
    ) -> _McpSummary:
        del plugin_dir, mode, config_path
        timeouts.append(("mcp", timeout_seconds))
        return _mcp_enabled()

    def fake_skill_scan(skills_dir: Path, mode: str, timeout_seconds: float | None = None) -> _SkillSummary:
        del skills_dir, mode
        timeouts.append(("skill", timeout_seconds))
        return _skill_enabled()

    monkeypatch.setattr(inventory_cisco, "run_cisco_mcp_scan", fake_mcp_scan)
    monkeypatch.setattr(inventory_cisco, "run_cisco_skill_scan", fake_skill_scan)

    run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=_detection(),
        mcp_mode="on",
        skill_mode="on",
        timeout_seconds=10.0,
    )

    assert [name for name, _ in timeouts] == ["mcp", "skill"]
    assert timeouts[0][1] == 10.0
    assert timeouts[1][1] is not None
    assert 0 < timeouts[1][1] < 10.0


def test_a_target_the_budget_no_longer_covers_is_reported_not_quietly_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _ctx(tmp_path)
    workspace_dir = context.workspace_dir
    assert workspace_dir is not None
    first = CiscoMcpScanTarget(
        root=workspace_dir,
        config_path=workspace_dir / ".mcp.json",
        label=".mcp.json",
    )
    second = CiscoMcpScanTarget(
        root=workspace_dir,
        config_path=workspace_dir / ".cursor" / "mcp.json",
        label=".cursor/mcp.json",
    )
    _chosen(monkeypatch, mcp_targets=(first, second))
    scanned: list[Path] = []
    # The first scan consumes the whole budget.
    clock = chain([0.0, 0.0, 0.0, 0.0], repeat(9.0))
    monkeypatch.setattr(inventory_cisco.time, "perf_counter", lambda: next(clock))

    def fake_mcp_scan(
        plugin_dir: Path,
        mode: str,
        timeout_seconds: float | None = None,
        config_path: Path | None = None,
    ) -> _McpSummary:
        del plugin_dir, mode, timeout_seconds
        assert config_path is not None
        scanned.append(config_path)
        return _mcp_enabled()

    monkeypatch.setattr(inventory_cisco, "run_cisco_mcp_scan", fake_mcp_scan)

    runs = run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=_detection(),
        mcp_mode="on",
        timeout_seconds=1.0,
    )

    assert scanned == [first.config_path]
    assert [run.status for run in runs] == ["enabled", "timed_out"]
    assert runs[1].metadata["target"] == ".cursor/mcp.json"
    assert runs[1].metadata["_configPath"] == str(second.config_path)


def test_a_skill_collection_the_budget_no_longer_covers_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _ctx(tmp_path)
    home_dir = context.home_dir
    assert home_dir is not None
    first = home_dir / ".agents" / "skills"
    second = home_dir / ".claude" / "skills"
    _chosen(monkeypatch, skill_roots=(first, second))
    scanned: list[Path] = []
    # The first collection consumes the whole budget.
    clock = chain([0.0, 0.0, 0.0], repeat(9.0))
    monkeypatch.setattr(inventory_cisco.time, "perf_counter", lambda: next(clock))

    def fake_skill_scan(skills_dir: Path, mode: str, timeout_seconds: float | None = None) -> _SkillSummary:
        del mode, timeout_seconds
        scanned.append(skills_dir)
        return _skill_enabled()

    monkeypatch.setattr(inventory_cisco, "run_cisco_skill_scan", fake_skill_scan)

    runs = run_cisco_inventory_scans(
        harness="codex",
        context=context,
        detection=_detection(),
        skill_mode="on",
        timeout_seconds=1.0,
    )

    assert scanned == [first]
    assert [run.status for run in runs] == ["enabled", "timed_out"]
    assert runs[1].metadata["target"] == str(second)


def test_every_run_is_marked_as_a_local_unverified_scanner_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _unavailable(monkeypatch)
    runs = run_cisco_inventory_scans(
        harness="codex",
        context=_ctx(tmp_path),
        detection=_detection(),
        mcp_mode="auto",
        skill_mode="auto",
    )
    for run in runs:
        assert run.metadata["evidenceProvenance"] == "client_unverified"
        assert run.metadata["scannerResolutionSource"] == "local_reported"
        assert run.metadata["scannerVerificationRequired"] == "guard_cloud"
