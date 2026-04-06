"""Trust scoring integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.reporting import build_json_payload
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def write_minimal_plugin(plugin_dir: Path) -> None:
    manifest_dir = plugin_dir / ".codex-plugin"
    manifest_dir.mkdir()
    (manifest_dir / "plugin.json").write_text(
        json.dumps(
            {
                "name": "trust-demo",
                "version": "1.0.0",
                "description": "Trust scoring demo plugin",
                "author": {"name": "Hashgraph Online"},
                "homepage": "https://example.com/plugin",
                "repository": "https://github.com/hashgraph-online/codex-plugin-scanner",
            }
        ),
        encoding="utf-8",
    )
    (plugin_dir / "README.md").write_text("# Demo\n", encoding="utf-8")
    (plugin_dir / "SECURITY.md").write_text("Report issues privately.\n", encoding="utf-8")
    (plugin_dir / "LICENSE").write_text("MIT\nPermission is hereby granted\n", encoding="utf-8")
    (plugin_dir / ".codexignore").write_text("dist/\n", encoding="utf-8")


def test_good_plugin_emits_skill_and_plugin_trust_domains():
    result = scan_plugin(FIXTURES / "good-plugin")

    assert result.trust_report is not None
    assert result.trust_report.total > 0

    domains = {domain.domain: domain for domain in result.trust_report.domains}
    assert set(domains) >= {"plugin", "skills"}

    plugin_domain = domains["plugin"]
    assert plugin_domain.spec_id == "HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT"
    security_adapter = next(adapter for adapter in plugin_domain.adapters if adapter.adapter_id == "security")
    disclosure_component = next(
        component for component in security_adapter.components if component.key == "disclosure"
    )
    assert disclosure_component.score == 100

    skill_domain = domains["skills"]
    assert skill_domain.spec_id == "HOL-HCS-28-SKILL-TRUST-LOCAL-DRAFT"
    assert {adapter.adapter_id for adapter in skill_domain.adapters} == {"verified", "safety", "metadata"}


def test_safe_mcp_config_emits_mcp_trust_domain(tmp_path: Path):
    plugin_dir = tmp_path
    write_minimal_plugin(plugin_dir)
    (plugin_dir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "local-demo": {
                        "command": "python",
                        "args": ["-m", "demo_server"],
                    }
                },
                "remotes": [{"url": "https://example.com/mcp"}],
            }
        ),
        encoding="utf-8",
    )

    result = scan_plugin(plugin_dir)

    assert result.trust_report is not None
    domains = {domain.domain: domain for domain in result.trust_report.domains}
    assert "mcp" in domains
    verification_adapter = next(adapter for adapter in domains["mcp"].adapters if adapter.adapter_id == "verification")
    assert verification_adapter.score > 0


def test_invalid_skill_frontmatter_reduces_manifest_integrity(tmp_path: Path):
    plugin_dir = tmp_path
    write_minimal_plugin(plugin_dir)
    skills_dir = plugin_dir / "skills" / "demo-skill"
    skills_dir.mkdir(parents=True)
    (plugin_dir / ".codex-plugin" / "plugin.json").write_text(
        json.dumps(
            {
                "name": "trust-demo",
                "version": "1.0.0",
                "description": "Trust scoring demo plugin",
                "skills": "skills",
                "author": {"name": "Hashgraph Online"},
                "homepage": "https://example.com/plugin",
                "repository": "https://github.com/hashgraph-online/codex-plugin-scanner",
                "interface": {"category": "developer-tools"},
            }
        ),
        encoding="utf-8",
    )
    (skills_dir / "SKILL.md").write_text(
        "---\nname: Demo Skill\n---\n\nMissing description field.\n",
        encoding="utf-8",
    )

    result = scan_plugin(plugin_dir)

    skill_domain = next(domain for domain in result.trust_report.domains if domain.domain == "skills")
    verified_adapter = next(adapter for adapter in skill_domain.adapters if adapter.adapter_id == "verified")
    manifest_integrity = next(
        component for component in verified_adapter.components if component.key == "manifestIntegrity"
    )
    assert manifest_integrity.score == 0


def test_invalid_mcp_json_zeroes_config_integrity(tmp_path: Path):
    plugin_dir = tmp_path
    write_minimal_plugin(plugin_dir)
    (plugin_dir / ".mcp.json").write_text("{invalid json\n", encoding="utf-8")

    result = scan_plugin(plugin_dir)

    mcp_domain = next(domain for domain in result.trust_report.domains if domain.domain == "mcp")
    verification_adapter = next(adapter for adapter in mcp_domain.adapters if adapter.adapter_id == "verification")
    config_integrity = next(
        component for component in verification_adapter.components if component.key == "configIntegrity"
    )
    config_shape = next(
        component
        for adapter in mcp_domain.adapters
        if adapter.adapter_id == "metadata"
        for component in adapter.components
        if component.key == "configShape"
    )
    assert config_integrity.score == 0
    assert config_shape.score == 0


def test_json_payload_includes_trust_provenance():
    result = scan_plugin(FIXTURES / "good-plugin")

    payload = build_json_payload(result)

    assert payload["trust"]["total"] == result.trust_report.total
    plugin_domain = next(domain for domain in payload["trust"]["domains"] if domain["domain"] == "plugin")
    assert plugin_domain["spec"]["id"] == "HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT"
