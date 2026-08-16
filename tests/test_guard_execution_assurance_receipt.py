"""Tests for ExecutionAssuranceReceipt — schema version, typed fields, privacy, immutability."""

from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from hashlib import sha256
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    AtomicGuaranteeKind,
    GuardExecutionAssuranceBoundary,
    GuardExecutionAttestationTrust,
)
from codex_plugin_scanner.guard.runtime.execution_assurance_receipt import (
    SCHEMA_VERSION,
    ExecutionAssuranceReceipt,
    receipt_assurance_payload,
    validate_assurance_receipt_schema_version,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DIGEST = sha256(b"test-context").hexdigest()
DIGEST2 = sha256(b"test-terminal").hexdigest()
GOOD = {
    "achieved_boundary": GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
    "attestation_trust": GuardExecutionAttestationTrust.SELF_ATTESTED,
    "execution_context_digest": DIGEST,
    "enforced_guarantee_kinds": ("filesystem",),
    "absent_guarantee_kinds": (),
    "terminal_statement_digest": DIGEST2,
    "proof_lines": ("line1", "line2"),
}


# ---------------------------------------------------------------------------
# Schema version validation
# ---------------------------------------------------------------------------


class TestSchemaVersionValidation:
    def test_current_version_accepted_str(self) -> None:
        assert validate_assurance_receipt_schema_version(SCHEMA_VERSION) == SCHEMA_VERSION

    def test_current_version_accepted_dict(self) -> None:
        result = validate_assurance_receipt_schema_version({"_schema_version": SCHEMA_VERSION})
        assert result == SCHEMA_VERSION

    def test_wrong_version_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be"):
            validate_assurance_receipt_schema_version("0.0.0")

    def test_wrong_version_rejected_dict(self) -> None:
        with pytest.raises(ValueError, match="must be"):
            validate_assurance_receipt_schema_version({"_schema_version": "0.0.0"})

    def test_missing_schema_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be a non-empty string"):
            validate_assurance_receipt_schema_version({})

    def test_none_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_assurance_receipt_schema_version(None)

    def test_int_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_assurance_receipt_schema_version(123)


# ---------------------------------------------------------------------------
# Typed boundary / attestation fields
# ---------------------------------------------------------------------------


class TestTypedFields:
    def test_minimal_valid(self) -> None:
        rec = ExecutionAssuranceReceipt(
            **{
                "achieved_boundary": GuardExecutionAssuranceBoundary.OS_ISOLATED,
                "attestation_trust": GuardExecutionAttestationTrust.SELF_ATTESTED,
                "execution_context_digest": DIGEST,
            }
        )
        assert rec.achieved_boundary == GuardExecutionAssuranceBoundary.OS_ISOLATED
        assert rec.attestation_trust == GuardExecutionAttestationTrust.SELF_ATTESTED
        assert rec.execution_context_digest == DIGEST
        assert rec.enforced_guarantee_kinds == ()
        assert rec.absent_guarantee_kinds == ()
        assert rec.terminal_statement_digest is None
        assert rec.proof_lines == ()

    def test_all_fields_populated(self) -> None:
        rec = ExecutionAssuranceReceipt(**GOOD)
        assert rec.enforced_guarantee_kinds == ("filesystem",)

    def test_invalid_boundary_rejected(self) -> None:
        with pytest.raises(ValueError):
            ExecutionAssuranceReceipt(
                achieved_boundary="bogus",
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
                execution_context_digest=DIGEST,
            )

    def test_invalid_attestation_rejected(self) -> None:
        with pytest.raises(ValueError):
            ExecutionAssuranceReceipt(
                achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
                attestation_trust="bogus",
                execution_context_digest=DIGEST,
            )

    def test_invalid_sha256_rejected(self) -> None:
        with pytest.raises(ValueError):
            ExecutionAssuranceReceipt(
                achieved_boundary=GuardExecutionAssuranceBoundary.OBSERVED_HOST,
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
                execution_context_digest="not-a-hash",
            )

    def test_invalid_guarantee_kind_rejected(self) -> None:
        with pytest.raises(ValueError):
            ExecutionAssuranceReceipt(
                achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
                execution_context_digest=DIGEST,
                enforced_guarantee_kinds=("bogus_kind",),
            )

    def test_terminal_digest_none_ok_for_unverified(self) -> None:
        rec = ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
            execution_context_digest=DIGEST,
        )
        assert rec.terminal_statement_digest is None

    def test_terminal_digest_invalid_rejected(self) -> None:
        with pytest.raises(ValueError):
            ExecutionAssuranceReceipt(
                achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
                execution_context_digest=DIGEST,
                terminal_statement_digest="bad",
            )

    def test_schema_version_property(self) -> None:
        rec = ExecutionAssuranceReceipt(**GOOD)
        assert rec.schema_version == SCHEMA_VERSION

    def test_duplicate_guarantee_kinds_deduplicated(self) -> None:
        rec = ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
            execution_context_digest=DIGEST,
            enforced_guarantee_kinds=("filesystem", "filesystem", "network"),
        )
        assert rec.enforced_guarantee_kinds == ("filesystem", "network")

    def test_proof_lines_max_count_rejected(self) -> None:
        lines = tuple(f"line{i}" for i in range(65))
        with pytest.raises(ValueError, match="must have <= 64"):
            ExecutionAssuranceReceipt(
                achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
                execution_context_digest=DIGEST,
                proof_lines=lines,
            )

    def test_proof_lines_too_long_rejected(self) -> None:
        long_line = "x" * 257
        with pytest.raises(ValueError, match="must be a non-empty string"):
            ExecutionAssuranceReceipt(
                achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
                execution_context_digest=DIGEST,
                proof_lines=(long_line,),
            )


# ---------------------------------------------------------------------------
# Absent vs enforced guarantee lists
# ---------------------------------------------------------------------------


class TestAbsentVsEnforced:
    def test_both_lists(self) -> None:
        rec = ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
            execution_context_digest=DIGEST,
            enforced_guarantee_kinds=("filesystem", "network"),
            absent_guarantee_kinds=("kernel_hardware",),
        )
        assert rec.enforced_guarantee_kinds == ("filesystem", "network")
        assert rec.absent_guarantee_kinds == ("kernel_hardware",)

    def test_total_kinds_capped(self) -> None:
        all_kinds = sorted(AtomicGuaranteeKind(value).value for value in AtomicGuaranteeKind.__members__.values())
        # We only have 11 kinds; repeat to exceed 64 total
        repeated = tuple(k for k in all_kinds for _ in range(7))  # 77 total
        with pytest.raises(ValueError, match="must be <= 64"):
            ExecutionAssuranceReceipt(
                achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
                attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
                execution_context_digest=DIGEST,
                enforced_guarantee_kinds=repeated,
            )


# ---------------------------------------------------------------------------
# Privacy-safe to_receipt_fields
# ---------------------------------------------------------------------------


class TestPrivacySafeReceiptFields:
    def _make_receipt_with_sensitive_proof(self) -> ExecutionAssuranceReceipt:
        """Create a receipt whose proof_lines contain path-like and secret-like content."""
        return ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
            execution_context_digest=DIGEST,
            enforced_guarantee_kinds=("filesystem",),
            proof_lines=(
                "/home/user/project/file.txt",
                "aws-secret-key-abc",
                "malicious-directive: do something bad",
            ),
        )

    def test_fields_no_path_or_secret(self) -> None:
        rec = self._make_receipt_with_sensitive_proof()
        fields_dict = receipt_assurance_payload(rec)
        # All values concatenated as strings must not contain path separators or secrets
        for key, val in fields_dict.items():
            if isinstance(val, str):
                assert "/home/" not in val, f"raw path found in {key}: {val!r}"
                assert "secret" not in val.lower(), f"secret literal found in {key}: {val!r}"
                assert "aws-secret-key" not in val, f"secret leak in {key}: {val!r}"
                assert "malicious-directive" not in val, f"directive leak in {key}: {val!r}"

    def test_proof_lines_excluded_from_fields(self) -> None:
        """proof_lines should not appear in to_receipt_fields output."""
        rec = self._make_receipt_with_sensitive_proof()
        fields_dict = receipt_assurance_payload(rec)
        assert "proof_lines" not in fields_dict, "proof_lines leaked into receipt fields"

    def test_fields_includes_expected_keys(self) -> None:
        rec = ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
            attestation_trust=GuardExecutionAttestationTrust.VERIFIED,
            execution_context_digest=DIGEST,
            enforced_guarantee_kinds=("filesystem",),
            absent_guarantee_kinds=("kernel_hardware",),
            terminal_statement_digest=DIGEST2,
            proof_lines=("safe_line",),
        )
        fields_dict = receipt_assurance_payload(rec)
        assert "achieved_boundary" in fields_dict
        assert "attestation_trust" in fields_dict
        assert "execution_context_digest" in fields_dict
        assert "enforced_guarantee_kinds" in fields_dict
        assert "absent_guarantee_kinds" in fields_dict
        assert "terminal_statement_digest" in fields_dict
        assert "_schema_version" in fields_dict
        assert fields_dict["_schema_version"] == SCHEMA_VERSION

    def test_fields_no_raw_command_or_path(self) -> None:
        """Assert no field value contains a raw path separator sequence."""
        rec = ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.CONTROLLED_HOST,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
            execution_context_digest=DIGEST,
            proof_lines=(
                "/home/user/secret/data.json",
                "AWS_SECRET_ACCESS_KEY=foo",
            ),
        )
        fields_dict = receipt_assurance_payload(rec)
        for val in fields_dict.values():
            if isinstance(val, str):
                assert "/home/" not in val
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        assert "/home/" not in item


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_mutation_raises_frozen_instance_error(self) -> None:
        rec = ExecutionAssuranceReceipt(**GOOD)
        with pytest.raises(FrozenInstanceError):
            rec.achieved_boundary = GuardExecutionAssuranceBoundary.HARDWARE_ISOLATED

    def test_assignment_mutation_raises_frozen_instance_error(self) -> None:
        """Direct attribute assignment raises FrozenInstanceError (standard dataclass freeze)."""
        rec = ExecutionAssuranceReceipt(**GOOD)
        with pytest.raises(FrozenInstanceError):
            rec.execution_context_digest = "changed"

    def test_tuple_field_is_immutably_copied(self) -> None:
        """Guarantee kind tuples returned are independent copies (sorted/deduped internally)."""
        rec = ExecutionAssuranceReceipt(**GOOD)
        enforced = rec.enforced_guarantee_kinds
        with pytest.raises(AttributeError):
            # tuples are immutable; this verifies we got a tuple, not a mutable list
            enforced.append("anything")


def test_overlapping_enforced_and_absent_kinds_rejected() -> None:
    with pytest.raises(ValueError, match="both enforced and absent"):
        ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
            attestation_trust=GuardExecutionAttestationTrust.SELF_ATTESTED,
            execution_context_digest=DIGEST,
            enforced_guarantee_kinds=("filesystem",),
            absent_guarantee_kinds=("filesystem",),
        )


def test_verified_receipt_requires_digest_or_proof() -> None:
    with __import__("pytest").raises(ValueError, match="VERIFIED"):
        ExecutionAssuranceReceipt(
            achieved_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
            attestation_trust=GuardExecutionAttestationTrust.VERIFIED,
            execution_context_digest=DIGEST,
        )
    # valid when bound
    ExecutionAssuranceReceipt(
        achieved_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
        attestation_trust=GuardExecutionAttestationTrust.VERIFIED,
        execution_context_digest=DIGEST,
        terminal_statement_digest=DIGEST,
    )
