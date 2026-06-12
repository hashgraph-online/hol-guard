"""AIBOM local trust metadata tests."""

from __future__ import annotations

import builtins
import json
from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.aibom_trust_metadata import trust_resolution_from_domain
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.trust_attestation import (
    GuardTrustAttestationVerificationKey,
    build_trust_attestation_payload,
    verify_trust_attestation,
)
from codex_plugin_scanner.trust_models import TrustDomainScore


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


def _trust_layer_types(item_metadata: dict[str, object]) -> set[str]:
    layers = item_metadata.get("trustLayers")
    if not isinstance(layers, list):
        return set()
    return {
        str(layer.get("layerType"))
        for layer in layers
        if isinstance(layer, dict) and isinstance(layer.get("layerType"), str)
    }


def _install_test_attestation_key(monkeypatch) -> GuardTrustAttestationVerificationKey:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )
    fingerprint = __import__("hashlib").sha256(public_key_pem.encode("utf-8")).hexdigest()
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID", "guard-test-key-1")
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY", private_key_pem)
    return GuardTrustAttestationVerificationKey(
        key_id="guard-test-key-1",
        public_key_pem=public_key_pem,
        fingerprint_sha256=fingerprint,
    )


def test_trust_resolution_captured_at_uses_utc_z_suffix() -> None:
    domain = TrustDomainScore(
        domain="plugin",
        label="Plugin",
        spec_id="hol-guard-trust",
        spec_version="1",
        spec_path="trust/plugin.json",
        derived_from=(),
        profile_id="plugin-default",
        profile_version="1",
        score=42.0,
        adapters=(),
    )

    trust = trust_resolution_from_domain(
        domain,
        captured_at="2026-06-11T18:09:11+05:30",
    )

    assert trust["capturedAt"] == "2026-06-11T12:39:11Z"


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
    assert metadata.get("attestationStatus") == "unsigned"
    assert isinstance(metadata.get("evidenceHash"), str)
    components = trust.get("trustComponents")
    assert isinstance(components, list)
    assert components
    assert "local_baseline" in _trust_layer_types(plugin_item.metadata)


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

    def _guard_import(
        name: str,
        global_vars: Mapping[str, object] | None = None,
        local_vars: Mapping[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "skill_scanner" or name.startswith("skill_scanner."):
            raise AssertionError("inventory trust enrichment must not import skill_scanner")
        return original_import(name, global_vars, local_vars, fromlist, level)

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
    assert "local_baseline" in _trust_layer_types(skill_item.metadata)


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
    assert metadata.get("attestationStatus") == "unsigned"
    assert isinstance(metadata.get("evidenceHash"), str)
    components = trust.get("trustComponents")
    assert isinstance(components, list)
    assert len(components) > 0
    assert all(isinstance(component.get("componentId"), str) for component in components)
    assert "local_baseline" in _trust_layer_types(skill_item.metadata)


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
    assert "local_baseline" in _trust_layer_types(mcp_item.metadata)


def test_inventory_snapshot_signs_local_trust_metadata_when_configured(monkeypatch, tmp_path: Path) -> None:
    verification_key = _install_test_attestation_key(monkeypatch)
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
    metadata = trust.get("metadata")
    assert isinstance(metadata, dict)
    assert metadata.get("attestationStatus") == "signed"
    attestation = metadata.get("attestation")
    assert isinstance(attestation, dict)
    verify_trust_attestation(
        payload=build_trust_attestation_payload(
            agent_id=snapshot.agent_id,
            item_id=plugin_item.item_id,
            item_kind=plugin_item.item_kind,
            content_hash=plugin_item.content_hash,
            captured_at=str(trust.get("capturedAt")),
            evidence_hash=str(metadata.get("evidenceHash")),
            scope="trust_resolution",
        ),
        envelope=attestation,
        trusted_keys=(verification_key,),
    )
    trust_layers = plugin_item.metadata.get("trustLayers")
    assert isinstance(trust_layers, list)
    local_layer = next(
        layer
        for layer in trust_layers
        if isinstance(layer, dict) and layer.get("layerType") == "local_baseline"
    )
    layer_metadata = local_layer.get("metadata")
    assert isinstance(layer_metadata, dict)
    assert layer_metadata.get("attestationStatus") == "signed"
    layer_attestation = layer_metadata.get("attestation")
    assert isinstance(layer_attestation, dict)
    verify_trust_attestation(
        payload=build_trust_attestation_payload(
            agent_id=snapshot.agent_id,
            item_id=plugin_item.item_id,
            item_kind=plugin_item.item_kind,
            content_hash=plugin_item.content_hash,
            captured_at=str(local_layer.get("capturedAt")),
            evidence_hash=str(layer_metadata.get("evidenceHash")),
            scope="trust_layer",
            layer_id=str(local_layer.get("layerId")),
            layer_type=str(local_layer.get("layerType")),
        ),
        envelope=layer_attestation,
        trusted_keys=(verification_key,),
    )


def test_registry_identified_skill_still_gets_local_baseline(tmp_path: Path) -> None:
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    skills_dir = plugin_dir / "skills" / "registry-skill"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: registry-skill\ndescription: Demo\n---\n", encoding="utf-8")

    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(skills_dir / "SKILL.md"),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:project:skill:registry-skill",
                name="registry-skill",
                harness="codex",
                artifact_type="skill",
                source_scope="project",
                config_path=str(skills_dir / "SKILL.md"),
                metadata={
                    "registryIdentity": {
                        "entityId": "hol-skill-registry-skill",
                        "entityType": "skill",
                        "name": "registry-skill",
                        "version": "1.0.0",
                    }
                },
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

    trust_resolution = skill_item.metadata.get("trustResolution")
    assert isinstance(trust_resolution, dict)
    assert trust_resolution.get("resolutionSource") == "local"
    assert "local_baseline" in _trust_layer_types(skill_item.metadata)


def test_inventory_snapshot_attaches_instruction_trust_resolution(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    design_doc = workspace / "DESIGN.md"
    design_doc.write_text(
        "# Design\n\n## Scope\nOnly write reviewed changes.\n\n## Governance\nOwner: Platform. Review required.\n",
        encoding="utf-8",
    )

    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(design_doc),),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:project:instruction:design",
                name="DESIGN.md",
                harness="codex",
                artifact_type="instruction",
                source_scope="project",
                config_path=str(design_doc),
            ),
        ),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    overlay_item = next(item for item in snapshot.items if item.item_kind == "overlay")
    trust = overlay_item.metadata.get("trustResolution")

    assert overlay_item.metadata.get("instructionRole") == "design_md"
    assert isinstance(trust, dict)
    assert trust.get("resolutionSource") == "local"
    trust_metadata = trust.get("metadata")
    assert isinstance(trust_metadata, dict)
    assert trust_metadata.get("trustDomain") == "instructions"
    assert "local_baseline" in _trust_layer_types(overlay_item.metadata)
