from __future__ import annotations

import base64
import copy
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.ci.final_release_evidence import (
    REQUIRED_GATES,
    FinalEvidenceError,
    canonical_bytes,
    validate_final_evidence,
)

VERSION = "3.0.1"
SOURCE_SHA = "a" * 40
RULE_DIGEST = "b" * 64
TEST_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TEST_PUBLIC_KEY = base64.b64encode(TEST_PRIVATE_KEY.public_key().public_bytes_raw()).decode("ascii")


def _payload() -> dict[str, object]:
    return {
        "schema": "hol-guard-final-release-evidence.v1",
        "release": {
            "version": VERSION,
            "source_sha": SOURCE_SHA,
            "rule_digest": RULE_DIGEST,
            "commit_sha": SOURCE_SHA,
            "base_sha": "d" * 40,
        },
        "evidence": {
            "artifacts": {"name": "artifacts.json", "sha256": "1" * 64, "status": "pass"},
            "desktop_core": {"name": "desktop-core.json", "sha256": "2" * 64, "status": "pass"},
            "installed_matrix": {"name": "installed-matrix.json", "sha256": "3" * 64, "status": "pass"},
        },
        "gates": {key: True for key in REQUIRED_GATES},
        "review": {
            "ci_run": "run-123",
            "exact_head": True,
            "unresolved_non_outdated": 0,
            "pending_required": 0,
        },
        "coverage": {
            "platforms": ["manylinux-x64", "macos-arm64", "macos-x64"],
            "windows": {"status": "waived", "reason": "user-waived-for-this-run"},
        },
        "approval": {
            "capable": False,
            "status": "fail_closed_external_provisioning_required",
            "root_configured": False,
            "signer_ceremony": False,
        },
        "reproducibility": {
            "deterministic": True,
            "commands": ["python scripts/ci/validate_release_artifacts.py --help"],
        },
    }


def _validate(
    payload: dict[str, object], *, require_signature: bool = False, trusted_public_key: str | None = None
) -> dict[str, object]:
    return validate_final_evidence(
        payload,
        expected_version=VERSION,
        expected_source_sha=SOURCE_SHA,
        expected_rule_digest=RULE_DIGEST,
        require_signature=require_signature,
        trusted_public_key=base64.b64decode(trusted_public_key) if trusted_public_key is not None else None,
        trusted_key_id="release-evidence-key" if trusted_public_key is not None else None,
    )


def _signed_payload(signer: Ed25519PrivateKey = TEST_PRIVATE_KEY) -> dict[str, object]:
    payload = _payload()
    unsigned_projection = _validate(payload)
    signed_bytes = canonical_bytes(unsigned_projection)
    payload["signature"] = {
        "status": "verified",
        "algorithm": "ed25519",
        "key_id": "release-evidence-key",
        "public_key": base64.b64encode(signer.public_key().public_bytes_raw()).decode("ascii"),
        "signature": base64.b64encode(signer.sign(signed_bytes)).decode("ascii"),
        "manifest_sha256": hashlib.sha256(signed_bytes).hexdigest(),
    }
    return payload


def test_final_evidence_records_windows_waiver_and_external_approval_blocker() -> None:
    normalized = _validate(_payload())

    assert normalized["release_ready"] is False
    assert normalized["coverage"]["windows"]["status"] == "waived"
    assert normalized["approval"]["status"] == "fail_closed_external_provisioning_required"


def test_final_evidence_requires_every_named_gate() -> None:
    payload = _payload()
    del payload["gates"]["privacy"]

    with pytest.raises(FinalEvidenceError, match="gate set is incomplete"):
        _validate(payload)


def test_final_evidence_rejects_actionable_review_state() -> None:
    payload = _payload()
    payload["review"]["unresolved_non_outdated"] = 1

    with pytest.raises(FinalEvidenceError, match="actionable review"):
        _validate(payload)


def test_final_evidence_rejects_claimed_approval_without_external_ceremony() -> None:
    payload = _payload()
    payload["approval"] = {
        "capable": True,
        "root_configured": False,
        "signer_ceremony": False,
    }

    with pytest.raises(FinalEvidenceError, match="root/signer ceremony"):
        _validate(payload)


def test_final_evidence_rejects_local_paths() -> None:
    payload = _payload()
    payload["reproducibility"]["commands"] = ["python /Users/example/release.py"]

    with pytest.raises(FinalEvidenceError, match="workstation path"):
        _validate(payload)


def test_final_evidence_can_bind_external_detached_signature() -> None:
    payload = _signed_payload()

    normalized = _validate(payload, require_signature=True, trusted_public_key=TEST_PUBLIC_KEY)

    assert normalized["release_ready"] is True


def test_final_evidence_rejects_invalid_detached_signature() -> None:
    payload = _signed_payload()
    payload["signature"]["signature"] = base64.b64encode(b"x" * 64).decode("ascii")

    with pytest.raises(FinalEvidenceError, match="signature is invalid"):
        _validate(payload, require_signature=True, trusted_public_key=TEST_PUBLIC_KEY)


def test_final_evidence_signature_binds_canonical_unsigned_projection() -> None:
    payload = _signed_payload()
    payload["signature"]["manifest_sha256"] = "e" * 64

    with pytest.raises(FinalEvidenceError, match="does not bind"):
        _validate(payload, require_signature=True, trusted_public_key=TEST_PUBLIC_KEY)


def test_final_evidence_rejects_commit_from_another_source() -> None:
    payload = _payload()
    payload["release"]["commit_sha"] = "c" * 40

    with pytest.raises(FinalEvidenceError, match="commit does not match"):
        _validate(payload)


def test_final_evidence_rejects_untrusted_embedded_signer() -> None:
    attacker = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    payload = _signed_payload(attacker)

    with pytest.raises(FinalEvidenceError, match="signer is not trusted"):
        _validate(payload, require_signature=True, trusted_public_key=TEST_PUBLIC_KEY)


def test_final_evidence_validation_does_not_mutate_source() -> None:
    payload = _payload()
    original = copy.deepcopy(payload)

    _validate(payload)

    assert payload == original


def test_final_evidence_normalization_drops_unvalidated_fields() -> None:
    payload = _payload()
    payload["operator_note"] = "untrusted-but-not-sensitive"
    payload["release"]["future_field"] = "also-not-validated"

    normalized = _validate(payload)

    assert "operator_note" not in normalized
    assert "future_field" not in normalized["release"]


def test_final_evidence_signature_matches_normalized_output_projection() -> None:
    payload = _signed_payload()
    payload["operator_note"] = "ignored-after-signing"

    normalized = _validate(payload, require_signature=True, trusted_public_key=TEST_PUBLIC_KEY)

    assert normalized["signature"]["manifest_sha256"] == hashlib.sha256(canonical_bytes(normalized)).hexdigest()
