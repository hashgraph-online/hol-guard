from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.evidence_hash import guard_evidence_hash
from codex_plugin_scanner.guard.runtime.trust_attestation import (
    GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    GuardTrustAttestationSigningConfig,
    GuardTrustAttestationVerificationPolicy,
    apply_trust_attestation_metadata,
    build_trust_attestation_payload,
    build_trust_attestation_verification_key,
    sign_trust_attestation,
    trust_claim_hash,
    verify_trust_attestation,
)
from codex_plugin_scanner.guard.trust_metadata_boundary import separate_untrusted_adapter_trust_metadata


def _signing_config(key_id: str = "test-key") -> GuardTrustAttestationSigningConfig:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return GuardTrustAttestationSigningConfig(
        active_key_id=key_id,
        private_key_pem=private_key_pem,
        signature_algorithm=GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    )


def _payload(
    *,
    repository_id: str = "sha256:repo-a",
    sequence: int = 8,
    claim_hash: str = "sha256:claim",
) -> dict[str, object]:
    return build_trust_attestation_payload(
        agent_id="codex:local",
        adapter_id="codex",
        adapter_version="2.0.0",
        item_id="plugin:test",
        item_kind="plugin",
        content_hash="sha256:content",
        captured_at="2026-07-16T12:00:00Z",
        claim_hash=claim_hash,
        config_path_hash="sha256:config",
        evidence_hash="sha256:evidence",
        evidence_schema_version="guard-aibom-local-baseline-evidence.v1",
        expires_at="2026-07-16T12:05:00Z",
        nonce="nonce-1",
        policy_version="guard-policy.v1",
        repository_id=repository_id,
        sequence=sequence,
        scope="trust_resolution",
    )


def test_adapter_trust_aliases_and_prior_proofs_are_quarantined() -> None:
    parsed = json.loads(
        """{
          "trustResolution": {"status": "first"},
          "trustResolution": {"status": "second", "metadata": {"signature": "copied-proof"}},
          "trust_layers": [{"layerType": "adapter", "attestation": {"signature": "copied-proof"}}],
          "signature": "copied-proof",
          "verified": true,
          "description": "adapter description"
        }"""
    )

    clean = separate_untrusted_adapter_trust_metadata(parsed)

    assert clean["description"] == "adapter description"
    assert "trustResolution" not in clean
    assert "trust_layers" not in clean
    assert "signature" not in clean
    evidence = clean["unverifiedAdapterEvidence"]
    assert isinstance(evidence, dict)
    assert evidence["verificationStatus"] == "unverified"
    assert evidence["affectsTrustScore"] is False
    assert evidence["trustClaims"]["trustResolution"]["status"] == "second"
    assert "copied-proof" not in json.dumps(evidence)


def test_inventory_reconstructs_trust_and_never_signs_adapter_claim(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_HEADLESS_SHORT_LIVED", "1")
    plugin_dir = tmp_path / "plugin"
    manifest_dir = plugin_dir / ".codex-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text(
        json.dumps({"name": "test", "version": "1.0.0", "description": "test"}),
        encoding="utf-8",
    )
    (plugin_dir / "README.md").write_text("# Test\n", encoding="utf-8")
    artifact = GuardArtifact(
        artifact_id="codex:project:plugin:test",
        name="test",
        harness="codex",
        artifact_type="plugin",
        source_scope="project",
        config_path=str(plugin_dir),
        metadata={
            "trustResolution": {
                "resolutionSource": "adapter",
                "status": "trusted",
                "capturedAt": "2020-01-01T00:00:00Z",
                "metadata": {"evidenceHash": "attacker-selected", "signature": "copied-proof"},
            },
            "trustLayers": [
                {
                    "layerId": "adapter",
                    "layerType": "adapter",
                    "capturedAt": "2020-01-01T00:00:00Z",
                    "metadata": {"evidenceHash": "attacker-selected"},
                }
            ],
        },
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(str(plugin_dir),),
        artifacts=(artifact,),
    )

    snapshot = inventory_snapshot_from_detection(
        detection,
        generated_at="2026-07-16T12:00:00Z",
        home_dir=tmp_path,
        workspace_dir=tmp_path,
    )

    item = next(candidate for candidate in snapshot.items if candidate.item_kind == "plugin")
    resolution = item.metadata["trustResolution"]
    assert isinstance(resolution, dict)
    assert resolution["resolutionSource"] == "local"
    assert resolution["status"] == "local"
    assert resolution["provenance"]["verificationStatus"] == "locally_derived"
    resolution_metadata = resolution["metadata"]
    assert isinstance(resolution_metadata, dict)
    assert resolution_metadata["evidenceHash"] != "attacker-selected"
    assert resolution_metadata["attestationStatus"] == "signed"
    unverified = item.metadata["unverifiedAdapterEvidence"]
    assert isinstance(unverified, dict)
    assert unverified["verificationStatus"] == "unverified"
    assert "copied-proof" not in json.dumps(unverified)


@pytest.mark.parametrize(
    "raw_resolution",
    ["trusted", ["trusted"], {"status": "trusted"}],
)
def test_type_confused_or_unproven_trust_resolution_is_not_signed(
    raw_resolution: object,
) -> None:
    metadata = {"trustResolution": raw_resolution}
    clean = separate_untrusted_adapter_trust_metadata(metadata)

    assert "trustResolution" not in clean
    assert clean["unverifiedAdapterEvidence"]["verificationStatus"] == "unverified"


def test_stale_locally_marked_evidence_hash_is_rejected() -> None:
    evidence = {"source": "hol-guard-local-baseline", "capturedAt": "2026-07-16T12:00:00Z"}
    result = apply_trust_attestation_metadata(
        {
            "trustResolution": {
                "resolutionSource": "local",
                "status": "local",
                "evidenceAuthority": "device_claim",
                "affectsV4Score": False,
                "capturedAt": "2026-07-16T12:00:00Z",
                "provenance": {
                    "origin": "hol-guard-local",
                    "verificationStatus": "locally_derived",
                    "derivation": "test",
                },
                "metadata": {
                    "evidence": evidence,
                    "evidenceHash": guard_evidence_hash({"different": True}),
                    "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
                },
            }
        },
        agent_id="codex:local",
        adapter_id="codex",
        adapter_version="2.0.0",
        item_id="plugin:test",
        item_kind="plugin",
        content_hash="sha256:content",
        config_path_hash="sha256:config",
        repository_id="sha256:repository",
        signing_config=_signing_config(),
    )

    assert "trustResolution" not in result


def test_attestation_schema_replay_revocation_and_monotonic_rules() -> None:
    config = _signing_config("active-key")
    verification_key = build_trust_attestation_verification_key(config)
    rotated_verification_key = build_trust_attestation_verification_key(_signing_config("next-key"))
    evidence = {"source": "hol-guard-local-baseline", "capturedAt": "2026-07-16T12:00:00Z"}
    claim: dict[str, object] = {
        "resolutionSource": "local",
        "status": "local",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": False,
        "trustScore": 90,
        "capturedAt": "2026-07-16T12:00:00Z",
        "provenance": {
            "origin": "hol-guard-local",
            "verificationStatus": "locally_derived",
            "derivation": "test",
        },
        "metadata": {
            "evidence": evidence,
            "evidenceHash": guard_evidence_hash(evidence),
            "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
        },
    }
    payload = _payload(claim_hash=trust_claim_hash(claim, require_layer_identity=False))
    envelope = sign_trust_attestation(
        payload=payload,
        config=config,
        signed_at="2026-07-16T12:00:00Z",
    )
    now = datetime(2026, 7, 16, 12, 1, tzinfo=timezone.utc)
    replay_key = verify_trust_attestation(
        payload=payload,
        envelope=envelope,
        trusted_keys=(verification_key, rotated_verification_key),
        policy=GuardTrustAttestationVerificationPolicy(now=now.isoformat(), minimum_sequence=7),
        claim=claim,
    )

    with pytest.raises(ValueError, match="claim hash mismatch"):
        verify_trust_attestation(
            payload=payload,
            envelope=envelope,
            trusted_keys=(verification_key,),
            claim={**claim, "trustScore": 100},
        )

    with pytest.raises(ValueError, match="replay"):
        verify_trust_attestation(
            payload=payload,
            envelope=envelope,
            trusted_keys=(verification_key,),
            policy=GuardTrustAttestationVerificationPolicy(seen_replay_keys=frozenset({replay_key})),
        )
    with pytest.raises(ValueError, match="revoked"):
        verify_trust_attestation(
            payload=payload,
            envelope=envelope,
            trusted_keys=(verification_key,),
            policy=GuardTrustAttestationVerificationPolicy(revoked_key_ids=frozenset({"active-key"})),
        )
    with pytest.raises(ValueError, match="expired"):
        verify_trust_attestation(
            payload=payload,
            envelope=envelope,
            trusted_keys=(verification_key,),
            policy=GuardTrustAttestationVerificationPolicy(now="2026-07-16T12:06:00Z"),
        )
    with pytest.raises(ValueError, match="monotonic"):
        verify_trust_attestation(
            payload=payload,
            envelope=envelope,
            trusted_keys=(verification_key,),
            policy=GuardTrustAttestationVerificationPolicy(minimum_sequence=8),
        )
    with pytest.raises(ValueError, match="predates"):
        verify_trust_attestation(
            payload=payload,
            envelope=envelope,
            trusted_keys=(verification_key,),
            policy=GuardTrustAttestationVerificationPolicy(
                key_not_before=(("active-key", (now + timedelta(minutes=1)).isoformat()),)
            ),
        )
    with pytest.raises(ValueError, match="payload hash mismatch"):
        verify_trust_attestation(
            payload={**payload, "repositoryId": "sha256:repo-b"},
            envelope=envelope,
            trusted_keys=(verification_key,),
        )
    with pytest.raises(ValueError, match="Unknown trust attestation payload fields"):
        sign_trust_attestation(
            payload={**payload, "trustResolution": {"status": "trusted"}},
            config=config,
            signed_at="2026-07-16T12:00:00Z",
        )
