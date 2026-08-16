from __future__ import annotations

from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.outcome_receipt import (
    GuardOutcomeReceipt,
    assert_privacy_safe_receipt,
    build_outcome_receipt,
    receipt_digest,
    sha256_digest,
)


def test_verified_install_receipt_requires_verified_handoff() -> None:
    evidence = sha256_digest(b"binary-version-and-self-check")
    receipt = build_outcome_receipt(
        outcome="local_install_verified",
        hol_guard_version="3.0.0a1",
        verification="binary_verified_handoff",
        evidence_digest=evidence,
        handoff_id="handoff-safe-id",
        occurred_at=datetime(2026, 8, 9, 16, 0, tzinfo=timezone.utc),
    )
    assert receipt.sensitive_content_included is False
    assert receipt.handoff_id == "handoff-safe-id"
    assert len(receipt_digest(receipt)) == 64


def test_first_local_proof_receipt_contains_digest_not_evidence() -> None:
    raw_sensitive_evidence = b"/private/path secret-looking-content"
    digest = sha256_digest(raw_sensitive_evidence)
    receipt = build_outcome_receipt(
        outcome="first_local_proof_generated",
        hol_guard_version="3.0.0a1",
        verification="privacy_safe_local_receipt",
        evidence_digest=digest,
        proof_kind="runtime_decision_receipt",
        occurred_at=datetime(2026, 8, 9, 16, 1, tzinfo=timezone.utc),
    )
    serialized = str(receipt.to_dict())
    assert "/private/path" not in serialized
    assert "secret-looking-content" not in serialized
    assert digest in serialized


def test_install_receipt_rejects_unlinked_local_claim() -> None:
    with pytest.raises(ValueError, match="handoff_id"):
        build_outcome_receipt(
            outcome="local_install_verified",
            hol_guard_version="3.0.0a1",
            verification="binary_verified_handoff",
            evidence_digest="a" * 64,
        )


def test_first_proof_requires_proof_kind() -> None:
    with pytest.raises(ValueError, match="proof_kind"):
        build_outcome_receipt(
            outcome="first_local_proof_generated",
            hol_guard_version="3.0.0a1",
            verification="privacy_safe_local_receipt",
            evidence_digest="b" * 64,
        )


def test_direct_dataclass_construction_enforces_privacy_boundary() -> None:
    with pytest.raises(ValueError, match="opaque identifier format"):
        GuardOutcomeReceipt(
            schema_version="1",
            outcome="local_install_verified",
            occurred_at="2026-08-09T16:00:00Z",
            hol_guard_version="3.0.0a1",
            verification="binary_verified_handoff",
            evidence_digest="c" * 64,
            handoff_id="/private/path secret",
            proof_kind=None,
        )


def test_allowed_identifier_fields_reject_sensitive_markers() -> None:
    with pytest.raises(ValueError, match="sensitive-content markers"):
        build_outcome_receipt(
            outcome="local_install_verified",
            hol_guard_version="3.0.0a1",
            verification="binary_verified_handoff",
            evidence_digest="d" * 64,
            handoff_id="secret-token",
            occurred_at=datetime(2026, 8, 9, 16, 2, tzinfo=timezone.utc),
        )


def test_receipt_rejects_unbounded_or_unstructured_metadata() -> None:
    with pytest.raises(ValueError, match="PEP 440"):
        build_outcome_receipt(
            outcome="first_local_proof_generated",
            hol_guard_version="not-a-version",
            verification="privacy_safe_local_receipt",
            evidence_digest="e" * 64,
            proof_kind="runtime_decision_receipt",
        )
    with pytest.raises(ValueError, match="lowercase identifier format"):
        build_outcome_receipt(
            outcome="first_local_proof_generated",
            hol_guard_version="3.0.0a1",
            verification="privacy_safe_local_receipt",
            evidence_digest="f" * 64,
            proof_kind="../../private/path",
        )


def test_privacy_guard_rejects_extra_sensitive_fields() -> None:
    with pytest.raises(ValueError, match="unsupported fields"):
        assert_privacy_safe_receipt(
            {
                "schema_version": "1",
                "outcome": "first_local_proof_generated",
                "occurred_at": "2026-08-09T16:00:00Z",
                "hol_guard_version": "3.0.0a1",
                "verification": "privacy_safe_local_receipt",
                "evidence_digest": "a" * 64,
                "handoff_id": None,
                "proof_kind": "runtime_decision_receipt",
                "sensitive_content_included": False,
                "raw_prompt": "do not serialize me",
            }
        )


def test_privacy_guard_validates_required_fields_and_values() -> None:
    with pytest.raises(ValueError, match="missing required fields"):
        assert_privacy_safe_receipt({"schema_version": "1"})

    with pytest.raises(ValueError, match="sensitive-content markers"):
        assert_privacy_safe_receipt(
            {
                "schema_version": "1",
                "outcome": "local_install_verified",
                "occurred_at": "2026-08-09T16:00:00Z",
                "hol_guard_version": "3.0.0a1",
                "verification": "binary_verified_handoff",
                "evidence_digest": "b" * 64,
                "handoff_id": "private-token",
                "proof_kind": None,
                "sensitive_content_included": False,
            }
        )
