"""AIBOM local trust metadata tests."""

from __future__ import annotations

import builtins
import json
from pathlib import Path

from codex_plugin_scanner.guard.aibom_trust_metadata import trust_resolution_from_domain
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.trust_models import TrustDomainScore


def _write_good_plugin(plugin_dir: Path) -> None:
    manifest_dir = plugin_dir / ".codex-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text(
        json.dumps(
            {
                "name": "trust-demo",
                "version": "1.0.0",
                "description": "Trust scoring demo plugin",
                "author": {"name": "Hashgraph Online"},
                "homepage": "https://example.com/plugin",
                "repository": "https://github.com/hashgraph-online/hol-guard",
                "skills": "skills",
            }
        ),
        encoding="utf-8",
    )
    (plugin_dir / "README.md").write_text("# Demo\n", encoding="utf-8")
    (plugin_dir / "SECURITY.md").write_text("Report issues privately.\n", encoding="utf-8")
    (plugin_dir / "LICENSE").write_text("MIT\n", encoding="utf-8")


def test_trust_resolution_captured_at_uses_utc_z_suffix() -> None:
    domain = TrustDomainScore(
        domain="plugin",
        profile_id="plugin-default",
        profile_version="1",
        score=42.0,
        spec_id="hol-guard-trust",
        spec_version="1",
        adapters=(),
    )

    trust = trust_resolution_from_domain(
        domain,
        captured_at="2026-06-11T23:09:11.718707+00:00",
    )

    assert trust["capturedAt"] == "2026-06-11T23:09:11.718707Z"


def test_inventory_snapshot_attaches_local_plugin_trust_resolution(tmp_path: Path) -> None:
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(plugin_dir / ".codex-plugin" / "plugin.json"),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:project:plugin:trust-demo",
                name="trust-demo",
                harness="codex",
                artifact_type="plugin",
                source_scope="project",
                config_path=str(plugin_dir),
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    plugin_item = next(item for item in snapshot.items if item.item_kind == "plugin")
    trust = plugin_item.metadata.get("trustResolution")
    assert isinstance(trust, dict)
    assert trust.get("resolutionSource") == "local"
    assert trust.get("status") == "local"
    assert trust.get("capturedAt") == "2026-06-10T12:00:00Z"
    assert isinstance(trust.get("trustScore"), int)
    assert trust.get("trustScore", 0) > 0
    metadata = trust.get("metadata")
    assert isinstance(metadata, dict)
    assert metadata.get("trustDomain") == "plugin"
    assert metadata.get("scorer") == "hol-guard-local"
    components = trust.get("trustComponents")
    assert isinstance(components, list)
    assert components


def test_inventory_skill_trust_enrichment_disables_cisco_scan(
    monkeypatch,
    tmp_path: Path,
) -> None:
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    skills_dir = plugin_dir / "skills" / "demo-skill"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: demo-skill\ndescription: Demo\n---\n", encoding="utf-8")
    cisco_modes: list[str] = []
    original_import = builtins.__import__

    def _guard_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "skill_scanner" or name.startswith("skill_scanner."):
            raise AssertionError("inventory trust enrichment must not import skill_scanner")
        return original_import(name, *args, **kwargs)

    def _record_cisco_mode(**kwargs: object) -> object:
        from codex_plugin_scanner.integrations.cisco_skill_scanner import (
            CiscoIntegrationStatus,
            CiscoSkillScanSummary,
        )

        mode = kwargs.get("mode")
        assert isinstance(mode, str)
        cisco_modes.append(mode)
        return CiscoSkillScanSummary(
            status=CiscoIntegrationStatus.SKIPPED,
            message="Cisco skill scanning disabled by configuration.",
            findings=(),
            skills_scanned=0,
            skills_skipped=(),
            analyzers_used=(),
            policy_name="balanced",
            total_findings=0,
            findings_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
        )

    monkeypatch.setattr(builtins, "__import__", _guard_import)
    monkeypatch.setattr(
        "codex_plugin_scanner.checks.skill_security.run_cisco_skill_scan",
        _record_cisco_mode,
    )

    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(skills_dir / "SKILL.md"),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:project:skill:demo-skill",
                name="demo-skill",
                harness="codex",
                artifact_type="skill",
                source_scope="project",
                config_path=str(skills_dir / "SKILL.md"),
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    skill_item = next(item for item in snapshot.items if item.item_kind == "skill")
    trust = skill_item.metadata.get("trustResolution")
    assert isinstance(trust, dict)
    assert trust.get("resolutionSource") == "local"
    assert cisco_modes == ["off"]


def test_inventory_snapshot_attaches_local_skill_trust_resolution(tmp_path: Path) -> None:
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    skills_dir = plugin_dir / "skills" / "demo-skill"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: demo-skill\ndescription: Demo\n---\n", encoding="utf-8")
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(skills_dir / "SKILL.md"),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:project:skill:demo-skill",
                name="demo-skill",
                harness="codex",
                artifact_type="skill",
                source_scope="project",
                config_path=str(skills_dir / "SKILL.md"),
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    skill_item = next(item for item in snapshot.items if item.item_kind == "skill")
    trust = skill_item.metadata.get("trustResolution")
    assert isinstance(trust, dict)
    metadata = trust.get("metadata")
    assert isinstance(metadata, dict)
    assert metadata.get("trustDomain") == "skills"
    components = trust.get("trustComponents")
    assert isinstance(components, list)
    assert len(components) > 0
    assert all(isinstance(component.get("componentId"), str) for component in components)


def test_inventory_snapshot_attaches_local_mcp_trust_resolution(tmp_path: Path) -> None:
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    (plugin_dir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local-demo": {
                        "command": "python",
                        "args": ["-m", "demo_server"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(plugin_dir / ".mcp.json"),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:project:mcp:local-demo",
                name="local-demo",
                harness="codex",
                artifact_type="mcp_server",
                source_scope="project",
                config_path=str(plugin_dir / ".mcp.json"),
                transport="stdio",
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    mcp_item = next(item for item in snapshot.items if item.item_kind == "mcp_server")
    trust = mcp_item.metadata.get("trustResolution")
    assert isinstance(trust, dict)
    assert trust.get("resolutionSource") == "local"
    metadata = trust.get("metadata")
    assert isinstance(metadata, dict)
    assert metadata.get("trustDomain") == "mcp"
