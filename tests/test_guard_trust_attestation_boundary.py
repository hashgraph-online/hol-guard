from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner.guard.aibom_trust_metadata import separate_untrusted_adapter_trust_metadata
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.native_runner_authority import (
    NativeRunnerAuthorityError,
    NativeRunnerAuthorityRefusalError,
)
from codex_plugin_scanner.guard.runtime import trust_attestation
from codex_plugin_scanner.guard.runtime.evidence_hash import guard_evidence_hash
from codex_plugin_scanner.guard.runtime.trust_attestation import (
    GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    GuardTrustAttestationSigningConfig,
    apply_trust_attestation_metadata,
    build_trust_attestation_payload,
    sign_trust_attestation,
    trust_claim_hash,
)
from tests.trust_attestation_verify_support import (
    GuardTrustAttestationVerificationPolicy,
    build_trust_attestation_verification_key,
    verify_trust_attestation,
)


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


def _local_claim(**identity: str) -> dict[str, object]:
    evidence = {"source": "hol-guard-local-baseline", "capturedAt": "2026-07-16T12:00:00Z", **identity}
    return {
        "resolutionSource": "local",
        "status": "local",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": False,
        "capturedAt": "2026-07-16T12:00:00Z",
        **identity,
        "provenance": {"origin": "hol-guard-local", "verificationStatus": "locally_derived", "derivation": "test"},
        "metadata": {
            "evidence": evidence,
            "evidenceHash": guard_evidence_hash(evidence),
            "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
        },
    }


def _apply_local_claims(metadata: dict[str, object]) -> dict[str, object]:
    return apply_trust_attestation_metadata(
        metadata,
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


def test_a_claim_the_encoder_refuses_drops_alone(monkeypatch) -> None:
    real = trust_attestation.native_runner_authority

    def refuse_marked(kind: str, args: dict[str, object]) -> dict[str, object]:
        if "refuse-me" in json.dumps(args):
            raise NativeRunnerAuthorityRefusalError("native_runner_authority_request_too_large")
        return real(kind, args)

    monkeypatch.setattr(trust_attestation, "native_runner_authority", refuse_marked)
    refused = _local_claim(layerId="refuse-me", layerType="adapter")
    kept = _local_claim(layerId="layer-kept", layerType="adapter")

    result = _apply_local_claims({"trustResolution": _local_claim(), "trustLayers": [refused, kept]})

    assert result["trustResolution"]["metadata"]["attestationStatus"] == "signed"
    assert [layer["layerId"] for layer in result["trustLayers"]] == ["layer-kept"]
    assert result["trustLayers"][0]["metadata"]["attestationStatus"] == "signed"


def test_shared_fields_the_encoder_refuses_fail_the_item(monkeypatch) -> None:
    real = trust_attestation.native_runner_authority

    def refuse_marked(kind: str, args: dict[str, object]) -> dict[str, object]:
        if "refuse-shared" in json.dumps(args):
            raise NativeRunnerAuthorityRefusalError("native_runner_authority_request_unencodable")
        return real(kind, args)

    monkeypatch.setattr(trust_attestation, "native_runner_authority", refuse_marked)

    with pytest.raises(NativeRunnerAuthorityRefusalError, match="unencodable"):
        apply_trust_attestation_metadata(
            {"trustResolution": _local_claim(), "trustLayers": [_local_claim(layerId="layer", layerType="adapter")]},
            agent_id="codex:local",
            adapter_id="codex",
            adapter_version="2.0.0",
            item_id="plugin:test",
            item_kind="plugin",
            content_hash="sha256:content",
            config_path_hash="sha256:config",
            repository_id="refuse-shared",
            signing_config=_signing_config(),
        )


def test_an_unavailable_runtime_still_fails_the_item(monkeypatch) -> None:
    def unavailable(kind: str, args: dict[str, object]) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(trust_attestation, "native_runner_authority", unavailable)

    with pytest.raises(NativeRunnerAuthorityError, match="unavailable"):
        _apply_local_claims({"trustResolution": _local_claim()})


def test_every_signed_claim_of_an_item_is_checked_in_one_call(monkeypatch) -> None:
    real = trust_attestation.native_runner_authority
    ops: list[object] = []

    def record(kind: str, args: dict[str, object]) -> dict[str, object]:
        ops.append(args.get("op"))
        return real(kind, args)

    monkeypatch.setattr(trust_attestation, "native_runner_authority", record)
    layers = [_local_claim(layerId=f"layer-{index}", layerType="adapter") for index in range(3)]

    result = _apply_local_claims({"trustResolution": _local_claim(), "trustLayers": layers})

    assert ops == ["sign_plan"]
    assert all(layer["metadata"]["attestationStatus"] == "signed" for layer in result["trustLayers"])


# The verifier is the native runtime's, so this test needs a provisioned
# resident. `native_context_digest` forces the compiled runtime against the
# session's keyed home and skips where no binary was built, which keeps the
# rest of this module running on the jobs that do not build Rust.
@pytest.mark.usefixtures("native_context_digest")
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
    with pytest.raises(ValueError, match="monotonic"):
        # A limit wider than any fixed-width field is still a limit, and it
        # comes back as the verifier's own refusal rather than as a runtime
        # that could not read the request at all.
        verify_trust_attestation(
            payload=payload,
            envelope=envelope,
            trusted_keys=(verification_key,),
            policy=GuardTrustAttestationVerificationPolicy(minimum_sequence=2**80),
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
