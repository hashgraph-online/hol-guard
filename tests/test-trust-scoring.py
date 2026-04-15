"""Trust scoring integration tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.reporting import build_json_payload
from codex_plugin_scanner.scanner import scan_plugin
from codex_plugin_scanner.trust_mcp_scoring import build_mcp_domain
from codex_plugin_scanner.trust_plugin_scoring import build_plugin_domain

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
                "repository": "https://github.com/hashgraph-online/ai-plugin-scanner",
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
    assert result.trust_report.include_external is False

    domains = {domain.domain: domain for domain in result.trust_report.domains}
    assert set(domains) >= {"plugin", "skills"}

    plugin_domain = domains["plugin"]
    assert plugin_domain.spec_id == "HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT"
    security_adapter = next(
        adapter for adapter in plugin_domain.adapters if adapter.adapter_id == "security.disclosure"
    )
    disclosure_component = next(
        component for component in security_adapter.components if component.key == "score"
    )
    assert disclosure_component.score == 100

    skill_domain = domains["skills"]
    assert skill_domain.spec_id == "HCS-28"
    assert skill_domain.profile_id == "hcs-28/baseline"
    assert "verification.review-status" in {adapter.adapter_id for adapter in skill_domain.adapters}
    assert "safety.cisco-scan" in {adapter.adapter_id for adapter in skill_domain.adapters}


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
    verification_adapter = next(
        adapter for adapter in domains["mcp"].adapters if adapter.adapter_id == "verification.config-integrity"
    )
    assert verification_adapter.score > 0


def test_missing_mcp_security_evidence_defaults_execution_safety_to_zero(tmp_path: Path):
    plugin_dir = tmp_path
    write_minimal_plugin(plugin_dir)
    (plugin_dir / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"local-demo": {"command": "python"}}}),
        encoding="utf-8",
    )

    mcp_domain = build_mcp_domain(plugin_dir, ())

    assert mcp_domain is not None
    execution_safety = next(
        adapter for adapter in mcp_domain.adapters if adapter.adapter_id == "verification.execution-safety"
    )
    assert execution_safety.score == 0


def test_missing_manifest_validation_evidence_defaults_manifest_integrity_to_zero(tmp_path: Path):
    plugin_dir = tmp_path
    write_minimal_plugin(plugin_dir)

    plugin_domain = build_plugin_domain(plugin_dir, ())

    manifest_integrity = next(
        adapter for adapter in plugin_domain.adapters if adapter.adapter_id == "verification.manifest-integrity"
    )
    assert manifest_integrity.score == 0


def test_missing_marketplace_file_excludes_marketplace_alignment_from_denominator(tmp_path: Path):
    plugin_dir = tmp_path
    write_minimal_plugin(plugin_dir)

    plugin_domain = build_plugin_domain(plugin_dir, ())

    marketplace_alignment = next(
        adapter for adapter in plugin_domain.adapters if adapter.adapter_id == "verification.marketplace-alignment"
    )
    assert marketplace_alignment.applicable is False
    assert marketplace_alignment.included_in_denominator is False


def test_declared_invalid_interface_keeps_interface_integrity_applicable(tmp_path: Path):
    plugin_dir = tmp_path
    write_minimal_plugin(plugin_dir)
    (plugin_dir / ".codex-plugin" / "plugin.json").write_text(
        json.dumps(
            {
                "name": "trust-demo",
                "version": "1.0.0",
                "description": "Trust scoring demo plugin",
                "interface": "invalid",
                "author": {"name": "Hashgraph Online"},
                "homepage": "https://example.com/plugin",
                "repository": "https://github.com/hashgraph-online/ai-plugin-scanner",
            }
        ),
        encoding="utf-8",
    )

    plugin_domain = build_plugin_domain(plugin_dir, ())

    interface_integrity = next(
        adapter for adapter in plugin_domain.adapters if adapter.adapter_id == "verification.interface-integrity"
    )
    assert interface_integrity.applicable is True
    assert interface_integrity.included_in_denominator is True
    assert interface_integrity.score == 0


def test_json_payload_includes_trust_provenance():
    result = scan_plugin(FIXTURES / "good-plugin")

    payload = build_json_payload(result)

    assert payload["trust"]["total"] == result.trust_report.total
    assert payload["trust"]["execution"]["includeExternal"] is False
    plugin_domain = next(domain for domain in payload["trust"]["domains"] if domain["domain"] == "plugin")
    assert plugin_domain["spec"]["id"] == "HOL-HCS-CODEX-PLUGIN-TRUST-DRAFT"
    assert plugin_domain["profile"]["id"] == "hol-codex-plugin-trust/baseline"
