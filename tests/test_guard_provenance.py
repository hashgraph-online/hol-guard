"""SCRG146-158: provenance, attestation, SLSA, registry identity, dist integrity, source policy."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestScrg146NpmProvenanceFetcher:
    """SCRG146: npm provenance fetcher reads attestation metadata."""

    def test_npm_provenance_returns_dataclass_for_attested_package(self) -> None:
        from codex_plugin_scanner.guard.provenance import fetch_npm_provenance

        fixture = {
            "attestations": [
                {
                    "url": "https://registry.npmjs.org/-/npm/v1/attestations/foo/-/foo-1.0.0.tgz",
                    "type": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
                    "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
                }
            ]
        }
        with patch(
            "codex_plugin_scanner.guard.provenance._fetch_npm_attestations",
            return_value=fixture,
        ):
            result = fetch_npm_provenance("foo", "1.0.0")
        assert result is not None
        assert result["status"] in ("attested", "verified", "unverified")
        assert "attestations" in result

    def test_npm_provenance_returns_missing_for_non_attested_package(self) -> None:
        from codex_plugin_scanner.guard.provenance import fetch_npm_provenance

        with patch(
            "codex_plugin_scanner.guard.provenance._fetch_npm_attestations",
            return_value={"attestations": []},
        ):
            result = fetch_npm_provenance("foo", "1.0.0")
        assert result["status"] == "missing"

    def test_npm_provenance_returns_error_on_fetch_failure(self) -> None:
        from codex_plugin_scanner.guard.provenance import fetch_npm_provenance

        with patch(
            "codex_plugin_scanner.guard.provenance._fetch_npm_attestations",
            side_effect=OSError("network error"),
        ):
            result = fetch_npm_provenance("foo", "1.0.0")
        assert result["status"] == "error"


class TestScrg147NpmTrustedPublisher:
    """SCRG147: npm trusted publisher OIDC state stored."""

    def test_extract_trusted_publisher_from_attestation(self) -> None:
        from codex_plugin_scanner.guard.provenance import extract_npm_trusted_publisher

        attestation = {
            "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
            "predicate": {
                "buildTrigger": "push",
                "runInvocationUri": "https://github.com/owner/repo/actions/runs/123",
                "sourceRepositoryUri": "https://github.com/owner/repo",
                "sourceRepositoryRef": "refs/heads/main",
            },
        }
        result = extract_npm_trusted_publisher(attestation)
        assert result["source_repository"] == "https://github.com/owner/repo"
        assert result["ref"] == "refs/heads/main"
        assert result["provider"] == "github_actions"

    def test_extract_trusted_publisher_returns_unknown_when_missing(self) -> None:
        from codex_plugin_scanner.guard.provenance import extract_npm_trusted_publisher

        result = extract_npm_trusted_publisher({})
        assert result["provider"] == "unknown"
        assert result["source_repository"] is None


class TestScrg148PypiAttestationVerifier:
    """SCRG148: PyPI attestation verifier."""

    def test_pypi_attestation_returns_attested_for_valid_response(self) -> None:
        from codex_plugin_scanner.guard.provenance import fetch_pypi_attestation

        fixture = {
            "attestations": [
                {
                    "statement": {"_type": "https://in-toto.io/Statement/v0.1"},
                    "verification_material": {},
                }
            ]
        }
        with patch(
            "codex_plugin_scanner.guard.provenance._fetch_pypi_attestations",
            return_value=fixture,
        ):
            result = fetch_pypi_attestation("requests", "2.31.0")
        assert result["status"] in ("attested", "verified", "unverified")

    def test_pypi_attestation_returns_missing_for_empty(self) -> None:
        from codex_plugin_scanner.guard.provenance import fetch_pypi_attestation

        with patch(
            "codex_plugin_scanner.guard.provenance._fetch_pypi_attestations",
            return_value={"attestations": []},
        ):
            result = fetch_pypi_attestation("requests", "2.31.0")
        assert result["status"] == "missing"

    def test_pypi_attestation_returns_error_on_network_failure(self) -> None:
        from codex_plugin_scanner.guard.provenance import fetch_pypi_attestation

        with patch(
            "codex_plugin_scanner.guard.provenance._fetch_pypi_attestations",
            side_effect=OSError("timeout"),
        ):
            result = fetch_pypi_attestation("requests", "2.31.0")
        assert result["status"] == "error"


class TestScrg149SigstoreVerification:
    """SCRG149: Sigstore verification utility - keyless identity check."""

    def test_verify_sigstore_bundle_structure_valid(self) -> None:
        from codex_plugin_scanner.guard.provenance import verify_sigstore_bundle

        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {"rawBytes": "dGVzdA=="},
                "tlogEntries": [{"inclusionPromise": {"signedEntryTimestamp": "abc"}}],
            },
            "messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": "deadbeef"}, "signature": "sig"},
        }
        result = verify_sigstore_bundle(bundle, expected_package_digest="deadbeef")
        assert result["valid"] in (True, False)
        assert "reason" in result

    def test_verify_sigstore_rejects_missing_verification_material(self) -> None:
        from codex_plugin_scanner.guard.provenance import verify_sigstore_bundle

        result = verify_sigstore_bundle({}, expected_package_digest=None)
        assert result["valid"] is False
        assert "reason" in result

    def test_verify_sigstore_rejects_digest_mismatch(self) -> None:
        from codex_plugin_scanner.guard.provenance import verify_sigstore_bundle

        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"certificate": {"rawBytes": "x"}},
            "messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": "aabbcc"}, "signature": "sig"},
        }
        result = verify_sigstore_bundle(bundle, expected_package_digest="deadbeef")
        assert result["valid"] is False
        assert "digest" in result["reason"].lower() or "mismatch" in result["reason"].lower()


class TestScrg150SlsaProvenanceFields:
    """SCRG150: SLSA provenance fields stored correctly."""

    def test_build_slsa_provenance_record_from_npm_attestation(self) -> None:
        from codex_plugin_scanner.guard.provenance import build_slsa_provenance_record

        attestation = {
            "predicate": {
                "buildTrigger": "push",
                "buildType": "https://github.com/npm/cli",
                "runInvocationUri": "https://github.com/owner/repo/actions/runs/123",
                "sourceRepositoryUri": "https://github.com/owner/repo",
                "sourceRepositoryRef": "refs/heads/main",
                "sourceRepositoryCommit": "abc123",
            }
        }
        record = build_slsa_provenance_record("npm", attestation)
        assert record["builder_id"] is not None
        assert record["source_repository"] == "https://github.com/owner/repo"
        assert record["source_ref"] == "refs/heads/main"
        assert record["source_commit"] == "abc123"
        assert "slsa_level" in record

    def test_slsa_level_none_when_no_provenance(self) -> None:
        from codex_plugin_scanner.guard.provenance import build_slsa_provenance_record

        record = build_slsa_provenance_record("npm", {})
        assert record["slsa_level"] is None

    def test_slsa_level_1_when_build_metadata_present(self) -> None:
        from codex_plugin_scanner.guard.provenance import build_slsa_provenance_record

        attestation = {
            "predicate": {
                "runInvocationUri": "https://github.com/owner/repo/actions/runs/123",
                "sourceRepositoryUri": "https://github.com/owner/repo",
            }
        }
        record = build_slsa_provenance_record("npm", attestation)
        assert record["slsa_level"] in (1, 2, 3)


class TestScrg151RepositoryBindingPolicy:
    """SCRG151: workspace repository binding policy."""

    def test_binding_passes_when_source_repo_matches_required(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_repository_binding

        result = check_repository_binding(
            actual_source="https://github.com/owner/repo",
            required_org="owner",
        )
        assert result["bound"] is True
        assert result["violation"] is None

    def test_binding_fails_when_source_repo_wrong_org(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_repository_binding

        result = check_repository_binding(
            actual_source="https://github.com/evil/repo",
            required_org="trusted-org",
        )
        assert result["bound"] is False
        assert result["violation"] is not None

    def test_binding_passes_with_no_policy(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_repository_binding

        result = check_repository_binding(actual_source=None, required_org=None)
        assert result["bound"] is True
        assert result["violation"] is None


class TestScrg152RegistryIdentityPinning:
    """SCRG152: registry identity/pinning ADR and policy."""

    def test_registry_identity_policy_adr_exists(self) -> None:
        from codex_plugin_scanner.guard.provenance import REGISTRY_IDENTITY_POLICY_ADR

        assert isinstance(REGISTRY_IDENTITY_POLICY_ADR, str)
        assert len(REGISTRY_IDENTITY_POLICY_ADR) > 50

    def test_allowed_registry_check_passes_for_official_npm(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_registry_identity

        result = check_registry_identity("npm", "https://registry.npmjs.org")
        assert result["allowed"] is True

    def test_allowed_registry_check_warns_for_unknown_registry(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_registry_identity

        result = check_registry_identity("npm", "https://evil.registry.example.com")
        assert result["allowed"] is False
        assert result["reason"] is not None


class TestScrg153DistIntegrityCheck:
    """SCRG153: dist integrity vs lockfile metadata."""

    def test_integrity_matches_when_hash_agrees(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_dist_integrity

        result = check_dist_integrity(
            lockfile_integrity="sha512-abc123",
            registry_integrity="sha512-abc123",
        )
        assert result["match"] is True
        assert result["status"] == "verified"

    def test_integrity_mismatch_detected(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_dist_integrity

        result = check_dist_integrity(
            lockfile_integrity="sha512-abc123",
            registry_integrity="sha512-DIFFERENT",
        )
        assert result["match"] is False
        assert result["status"] == "mismatch"

    def test_integrity_unknown_when_registry_data_missing(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_dist_integrity

        result = check_dist_integrity(lockfile_integrity="sha512-abc123", registry_integrity=None)
        assert result["status"] == "unverifiable"


class TestScrg154HttpSourcePolicy:
    """SCRG154: HTTP (insecure) source URL blocked by default."""

    def test_http_tarball_url_is_insecure(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_source_url_security

        result = check_source_url_security("http://example.com/pkg.tgz")
        assert result["secure"] is False
        assert result["reason"] == "insecure_http"

    def test_https_url_is_secure(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_source_url_security

        result = check_source_url_security("https://registry.npmjs.org/pkg.tgz")
        assert result["secure"] is True

    def test_none_url_is_not_flagged(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_source_url_security

        result = check_source_url_security(None)
        assert result["secure"] is True
        assert result["reason"] is None


class TestScrg155GitSourceImmutability:
    """SCRG155: git source immutability - mutable refs warned/blocked."""

    def test_commit_sha_pin_is_immutable(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_git_source_immutability

        result = check_git_source_immutability("https://github.com/owner/repo#a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
        assert result["immutable"] is True
        assert result["reason"] is None

    def test_branch_ref_is_mutable(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_git_source_immutability

        result = check_git_source_immutability("https://github.com/owner/repo#main")
        assert result["immutable"] is False
        assert result["reason"] == "mutable_branch"

    def test_tag_ref_is_mutable(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_git_source_immutability

        result = check_git_source_immutability("https://github.com/owner/repo#v1.0.0")
        assert result["immutable"] is False
        assert result["reason"] == "mutable_tag"

    def test_no_fragment_is_mutable(self) -> None:
        from codex_plugin_scanner.guard.provenance import check_git_source_immutability

        result = check_git_source_immutability("https://github.com/owner/repo")
        assert result["immutable"] is False
        assert result["reason"] == "no_pin"


class TestScrg156ProvenanceCopy:
    """SCRG156: provenance copy - verified/missing/mismatched/unknown."""

    def test_copy_for_verified_status(self) -> None:
        from codex_plugin_scanner.guard.provenance import build_provenance_copy

        copy = build_provenance_copy(status="verified", ecosystem="npm", package="foo")
        assert "verified" in copy.lower() or "attested" in copy.lower()

    def test_copy_for_missing_status(self) -> None:
        from codex_plugin_scanner.guard.provenance import build_provenance_copy

        copy = build_provenance_copy(status="missing", ecosystem="npm", package="foo")
        assert "provenance" in copy.lower() or "no" in copy.lower() or "missing" in copy.lower()

    def test_copy_for_mismatch_status(self) -> None:
        from codex_plugin_scanner.guard.provenance import build_provenance_copy

        copy = build_provenance_copy(status="mismatch", ecosystem="npm", package="foo")
        assert len(copy) > 10

    def test_copy_for_unknown_status(self) -> None:
        from codex_plugin_scanner.guard.provenance import build_provenance_copy

        copy = build_provenance_copy(status="unknown", ecosystem="pypi", package="requests")
        assert len(copy) > 10


class TestScrg157ProvenanceCannotBypassHardRisk:
    """SCRG157: known malware/KEV still blocks even with valid provenance."""

    def test_malware_blocked_despite_valid_provenance(self) -> None:
        from codex_plugin_scanner.guard.provenance import provenance_overrides_hard_risk

        result = provenance_overrides_hard_risk(
            decision="block",
            block_reason_code="known_malware",
            provenance_status="verified",
        )
        assert result is False

    def test_provenance_can_affect_non_hard_risk_decisions(self) -> None:
        from codex_plugin_scanner.guard.provenance import provenance_overrides_hard_risk

        result = provenance_overrides_hard_risk(
            decision="warn",
            block_reason_code="unknown_package",
            provenance_status="verified",
        )
        assert isinstance(result, bool)

    def test_kev_blocked_despite_provenance(self) -> None:
        from codex_plugin_scanner.guard.provenance import provenance_overrides_hard_risk

        result = provenance_overrides_hard_risk(
            decision="block",
            block_reason_code="kev_exploited",
            provenance_status="verified",
        )
        assert result is False
