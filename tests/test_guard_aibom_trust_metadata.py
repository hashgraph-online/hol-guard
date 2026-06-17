"""AIBOM local trust metadata tests."""

from __future__ import annotations

import builtins
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from codex_plugin_scanner.guard.aibom_trust_metadata import trust_resolution_from_domain
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.trust_attestation import (
    GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    GuardTrustAttestationSigningConfig,
    GuardTrustAttestationVerificationKey,
    build_trust_attestation_payload,
    build_trust_attestation_verification_key,
    resolve_guard_oauth_trust_attestation_signing_config,
    resolve_trust_attestation_signing_config,
    sign_trust_attestation,
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


def _snapshot_for_artifact(
    *,
    artifact: GuardArtifact,
    generated_at: str,
    home_dir: Path,
    workspace_dir: Path,
    trust_attestation_context: Mapping[str, object] | None = None,
) -> Any:
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(artifact.config_path),),
        artifacts=(artifact,),
    )
    return inventory_snapshot_from_detection(
        detection,
        generated_at=generated_at,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        trust_attestation_context=trust_attestation_context,
    )


def _assert_local_trust(
    item_metadata: dict[str, object],
    *,
    trust_domain: str | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    trust = item_metadata.get("trustResolution")
    assert isinstance(trust, dict)
    assert trust.get("resolutionSource") == "local"
    metadata = trust.get("metadata")
    assert isinstance(metadata, dict)
    if trust_domain is not None:
        assert metadata.get("trustDomain") == trust_domain
    assert "local_baseline" in _trust_layer_types(item_metadata)
    return trust, metadata


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
    fingerprint = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()
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
    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:project:plugin:trust-demo",
            name="trust-demo",
            harness="codex",
            artifact_type="plugin",
            source_scope="project",
            config_path=str(plugin_dir),
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    plugin_item = next(item for item in snapshot.items if item.item_kind == "plugin")
    trust, metadata = _assert_local_trust(plugin_item.metadata, trust_domain="plugin")
    assert trust.get("status") == "local"
    assert trust.get("capturedAt") == "2026-06-10T12:00:00Z"
    trust_score = trust.get("trustScore")
    assert isinstance(trust_score, int)
    assert trust_score > 0
    assert metadata.get("scorer") == "hol-guard-local"
    assert metadata.get("attestationStatus") == "unsigned"
    assert isinstance(metadata.get("evidenceHash"), str)
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

    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:project:skill:demo-skill",
            name="demo-skill",
            harness="codex",
            artifact_type="skill",
            source_scope="project",
            config_path=str(skills_dir / "SKILL.md"),
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    skill_item = next(item for item in snapshot.items if item.item_kind == "skill")
    _assert_local_trust(skill_item.metadata)
    assert cisco_modes == ["off"]


def test_inventory_snapshot_attaches_local_skill_trust_resolution(tmp_path: Path) -> None:
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    skills_dir = plugin_dir / "skills" / "demo-skill"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: demo-skill\ndescription: Demo\n---\n", encoding="utf-8")
    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:project:skill:demo-skill",
            name="demo-skill",
            harness="codex",
            artifact_type="skill",
            source_scope="project",
            config_path=str(skills_dir / "SKILL.md"),
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    skill_item = next(item for item in snapshot.items if item.item_kind == "skill")
    trust, metadata = _assert_local_trust(skill_item.metadata, trust_domain="skills")
    assert metadata.get("attestationStatus") == "unsigned"
    assert isinstance(metadata.get("evidenceHash"), str)
    components = trust.get("trustComponents")
    assert isinstance(components, list)
    assert len(components) > 0
    assert all(isinstance(component.get("componentId"), str) for component in components)


def test_inventory_snapshot_attaches_local_standalone_skill_trust_resolution(tmp_path: Path) -> None:
    skill_dir = tmp_path / ".agents" / "skills" / "adapt"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: adapt\ndescription: Responsive helper\nrepo: https://github.com/hashgraph-online/test\n---\n",
        encoding="utf-8",
    )
    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:global:skill:.agents/skills:adapt",
            name="adapt",
            harness="codex",
            artifact_type="skill",
            source_scope="global",
            config_path=str(skill_dir / "SKILL.md"),
            metadata={"skill_root": ".agents/skills"},
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=tmp_path,
    )
    skill_item = next(item for item in snapshot.items if item.item_kind == "skill")
    _assert_local_trust(skill_item.metadata, trust_domain="skills")


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
    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:project:mcp:local-demo",
            name="local-demo",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(plugin_dir / ".mcp.json"),
            transport="stdio",
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    mcp_item = next(item for item in snapshot.items if item.item_kind == "mcp_server")
    _assert_local_trust(mcp_item.metadata, trust_domain="mcp")


def test_inventory_snapshot_attaches_local_config_defined_mcp_trust_resolution(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[mcp_servers.demo]\ncommand = "node"\nargs = ["server.js"]\n',
        encoding="utf-8",
    )
    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:global:mcp:demo",
            name="demo",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="global",
            config_path=str(config_path),
            command="node",
            args=("server.js",),
            transport="stdio",
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=tmp_path,
    )
    mcp_item = next(item for item in snapshot.items if item.item_kind == "mcp_server")
    _assert_local_trust(mcp_item.metadata, trust_domain="mcp")


def test_inventory_snapshot_signs_local_trust_metadata_when_configured(monkeypatch, tmp_path: Path) -> None:
    verification_key = _install_test_attestation_key(monkeypatch)
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:project:plugin:trust-demo",
            name="trust-demo",
            harness="codex",
            artifact_type="plugin",
            source_scope="project",
            config_path=str(plugin_dir),
        ),
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


def test_inventory_snapshot_signs_local_trust_metadata_with_workspace_device_binding(
    tmp_path: Path,
) -> None:
    dpop_key_material = generate_dpop_key_pair()
    signing_config = resolve_guard_oauth_trust_attestation_signing_config(
        {
            "dpop_private_key_pem": dpop_key_material.private_key_pem,
            "dpop_public_jwk_thumbprint": dpop_key_material.public_jwk_thumbprint,
        }
    )
    assert signing_config is not None
    verification_key = build_trust_attestation_verification_key(signing_config)
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:project:plugin:trust-demo",
            name="trust-demo",
            harness="codex",
            artifact_type="plugin",
            source_scope="project",
            config_path=str(plugin_dir),
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
        trust_attestation_context={
            "analyzerId": "hol-guard",
            "analyzerSpecVersion": "guard-aibom-trust-spec.v1",
            "analyzerVersion": "2.0.345",
            "challengeId": "guard-aibom-challenge-1",
            "deviceId": "device-alpha",
            "policyVersion": "guard-aibom-trust-policy.v1",
            "expiresAt": "2026-06-10T12:15:00Z",
            "installationId": "device-alpha",
            "nonce": "nonce-alpha",
            "sequence": 7,
            "signingConfig": signing_config,
            "uploadId": "guard-aibom-upload-1",
            "workspaceId": "workspace-alpha",
        },
    )
    plugin_item = next(item for item in snapshot.items if item.item_kind == "plugin")
    trust = plugin_item.metadata.get("trustResolution")
    assert isinstance(trust, dict)
    metadata = trust.get("metadata")
    assert isinstance(metadata, dict)
    attestation = metadata.get("attestation")
    assert isinstance(attestation, dict)
    assert attestation.get("signatureAlgorithm") == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256
    assert attestation.get("publicJwkThumbprint") == dpop_key_material.public_jwk_thumbprint
    assert metadata.get("attestationBindings") == {
        "analyzerId": "hol-guard",
        "analyzerSpecVersion": "guard-aibom-trust-spec.v1",
        "analyzerVersion": "2.0.345",
        "challengeId": "guard-aibom-challenge-1",
        "deviceId": "device-alpha",
        "evidenceSchemaVersion": "guard-aibom-trust-evidence.v1",
        "expiresAt": "2026-06-10T12:15:00Z",
        "installationId": "device-alpha",
        "nonce": "nonce-alpha",
        "policyVersion": "guard-aibom-trust-policy.v1",
        "sequence": 7,
        "uploadId": "guard-aibom-upload-1",
        "workspaceId": "workspace-alpha",
    }
    verify_trust_attestation(
        payload=build_trust_attestation_payload(
            agent_id=snapshot.agent_id,
            analyzer_id="hol-guard",
            analyzer_spec_version="guard-aibom-trust-spec.v1",
            analyzer_version="2.0.345",
            challenge_id="guard-aibom-challenge-1",
            item_id=plugin_item.item_id,
            item_kind=plugin_item.item_kind,
            content_hash=plugin_item.content_hash,
            captured_at=str(trust.get("capturedAt")),
            evidence_schema_version="guard-aibom-trust-evidence.v1",
            expires_at="2026-06-10T12:15:00Z",
            evidence_hash=str(metadata.get("evidenceHash")),
            installation_id="device-alpha",
            nonce="nonce-alpha",
            policy_version="guard-aibom-trust-policy.v1",
            sequence=7,
            scope="trust_resolution",
            upload_id="guard-aibom-upload-1",
            workspace_id="workspace-alpha",
            device_id="device-alpha",
        ),
        envelope=attestation,
        trusted_keys=(verification_key,),
    )
    trust_layers = plugin_item.metadata.get("trustLayers")
    assert isinstance(trust_layers, list)
    local_layer = next(
        layer for layer in trust_layers if isinstance(layer, dict) and layer.get("layerType") == "local_baseline"
    )
    layer_metadata = local_layer.get("metadata")
    assert isinstance(layer_metadata, dict)
    assert layer_metadata.get("attestationStatus") == "signed"
    layer_attestation = layer_metadata.get("attestation")
    assert isinstance(layer_attestation, dict)
    verify_trust_attestation(
        payload=build_trust_attestation_payload(
            agent_id=snapshot.agent_id,
            analyzer_id="hol-guard",
            analyzer_spec_version="guard-aibom-trust-spec.v1",
            analyzer_version="2.0.345",
            challenge_id="guard-aibom-challenge-1",
            item_id=plugin_item.item_id,
            item_kind=plugin_item.item_kind,
            content_hash=plugin_item.content_hash,
            captured_at=str(local_layer.get("capturedAt")),
            evidence_schema_version="guard-aibom-trust-evidence.v1",
            expires_at="2026-06-10T12:15:00Z",
            evidence_hash=str(layer_metadata.get("evidenceHash")),
            installation_id="device-alpha",
            nonce="nonce-alpha",
            policy_version="guard-aibom-trust-policy.v1",
            sequence=7,
            scope="trust_layer",
            upload_id="guard-aibom-upload-1",
            workspace_id="workspace-alpha",
            device_id="device-alpha",
            layer_id=str(local_layer.get("layerId")),
            layer_type=str(local_layer.get("layerType")),
        ),
        envelope=layer_attestation,
        trusted_keys=(verification_key,),
    )


def test_p384_key_is_rejected_for_p256_attestation() -> None:
    private_key = ec.generate_private_key(ec.SECP384R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    with pytest.raises(ValueError, match="P-256"):
        sign_trust_attestation(
            payload=build_trust_attestation_payload(
                agent_id="agent-1",
                item_id="plugin:trust-demo",
                item_kind="plugin",
                content_hash="sha256:plugin-local",
                captured_at="2026-06-10T12:00:00+00:00",
                evidence_hash="resolution-hash",
                scope="trust_resolution",
                workspace_id="workspace-alpha",
                device_id="device-alpha",
            ),
            config=GuardTrustAttestationSigningConfig(
                active_key_id="p384-key",
                private_key_pem=private_key_pem,
                public_jwk_thumbprint="p384-key",
                signature_algorithm=GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
            ),
            signed_at="2026-06-10T12:00:00+00:00",
        )


def test_invalid_oauth_private_key_disables_attestation_signing_config() -> None:
    assert (
        resolve_guard_oauth_trust_attestation_signing_config(
            {
                "dpop_private_key_pem": "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
                "dpop_public_jwk_thumbprint": "thumbprint-123",
            }
        )
        is None
    )


def test_headless_short_lived_attestation_generates_ephemeral_ec_key(monkeypatch) -> None:
    monkeypatch.delenv("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_HEADLESS_SHORT_LIVED", "1")

    config = resolve_trust_attestation_signing_config(
        {
            "GUARD_AIBOM_TRUST_ATTESTATION_HEADLESS_SHORT_LIVED": "1",
            "GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID": "ci-short-lived",
        }
    )

    assert config is not None
    assert config.active_key_id == "ci-short-lived"
    assert config.signature_algorithm == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256
    verification_key = build_trust_attestation_verification_key(config)
    assert verification_key.public_jwk_thumbprint is not None


def test_registry_identified_skill_still_gets_local_baseline(tmp_path: Path) -> None:
    plugin_dir = tmp_path
    _write_good_plugin(plugin_dir)
    skills_dir = plugin_dir / "skills" / "registry-skill"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: registry-skill\ndescription: Demo\n---\n", encoding="utf-8")

    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
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
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=plugin_dir,
    )
    skill_item = next(item for item in snapshot.items if item.item_kind == "skill")
    trust_resolution, _ = _assert_local_trust(skill_item.metadata)
    assert trust_resolution.get("resolutionSource") == "local"


def test_inventory_snapshot_attaches_instruction_trust_resolution(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    design_doc = workspace / "DESIGN.md"
    design_doc.write_text(
        "# Design\n\n## Scope\nOnly write reviewed changes.\n\n## Governance\nOwner: Platform. Review required.\n",
        encoding="utf-8",
    )

    snapshot = _snapshot_for_artifact(
        artifact=GuardArtifact(
            artifact_id="codex:project:instruction:design",
            name="DESIGN.md",
            harness="codex",
            artifact_type="instruction",
            source_scope="project",
            config_path=str(design_doc),
        ),
        generated_at="2026-06-10T12:00:00+00:00",
        home_dir=tmp_path,
        workspace_dir=workspace,
    )
    overlay_item = next(item for item in snapshot.items if item.item_kind == "overlay")

    assert overlay_item.metadata.get("instructionRole") == "design_md"
    _assert_local_trust(overlay_item.metadata, trust_domain="instructions")
