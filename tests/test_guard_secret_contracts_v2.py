from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.contracts_v2 import (
    FIXTURE_JUSTIFICATION_CODES_V2,
    IGNORE_REASON_CODES_V2,
    OUTCOME_SURFACE_MAPPING,
    REASON_CODE_CATEGORIES_V2,
    REASON_CODE_RULES_V2,
    REASON_CODES_V2,
    SOURCE_CAPABILITY_STATUS_VALUES_V2,
    CapabilityEvidenceV2,
    ParityState,
    PreventionOutcome,
    SecretContractError,
    SecretCustomRuleV2,
    SecretIgnoreDecisionV2,
    SecretIgnoreScope,
    SecretIgnoreState,
    SecretRolloutState,
    SecretRuleCompileState,
    SecretRuleMatcherKind,
    SecretScanCoverageV2,
    parse_capability_evidence_manifest,
    parse_product_boundaries_manifest,
    parse_reason_codes_manifest,
    parse_source_capabilities_manifest,
    reject_prohibited_fields,
    validate_capability_manifest,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-capability-evidence.v2.json"
_PRODUCT_BOUNDARY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-product-boundaries.v2.json"
_SOURCE_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-source-capabilities.v2.json"
_REASON_CODE_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-reason-codes.v2.json"
_FIXTURE_OPENAI_KEY = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _coverage(**overrides: object) -> SecretScanCoverageV2:
    payload: dict[str, object] = {
        "schema": "guard-secret-coverage.v2",
        "source_set": ["working_tree"],
        "requested_refs": ["refs/heads/main"],
        "completed_refs": ["refs/heads/main"],
        "files_scanned": 4,
        "bytes_scanned": 1024,
        "commits_visited": 0,
        "blobs_scanned": 4,
        "skipped_codes": [],
        "truncation_codes": [],
        "detector_version": "guard-secrets-v2",
        "model_version": None,
        "cache_hits": 0,
        "cache_misses": 4,
        "partial": False,
        "degraded": False,
        "error_code": None,
    }
    payload.update(overrides)
    return SecretScanCoverageV2.from_mapping(payload)


def _direct_coverage(**overrides: object) -> SecretScanCoverageV2:
    values: dict[str, object] = {
        "source_set": ("working_tree",),
        "requested_refs": ("refs/heads/main",),
        "completed_refs": ("refs/heads/main",),
        "files_scanned": 4,
        "bytes_scanned": 1024,
        "commits_visited": 0,
        "blobs_scanned": 4,
        "skipped_codes": (),
        "truncation_codes": (),
        "detector_version": "guard-secrets-v2",
    }
    values.update(overrides)
    return SecretScanCoverageV2(**values)  # type: ignore[arg-type]


def _capability(**overrides: object) -> CapabilityEvidenceV2:
    values: dict[str, object] = {
        "capability_id": "secret:cli",
        "product_boundary": "free-local",
        "surfaces": ("cli",),
        "plans": ("free",),
        "state": ParityState.TESTED,
        "acceptance_tests": ("test_cli",),
        "evidence_artifacts": (),
        "gap_label": "release evidence pending",
    }
    values.update(overrides)
    return CapabilityEvidenceV2(**values)  # type: ignore[arg-type]


def _manifest(**capability_overrides: object) -> dict[str, object]:
    capability: dict[str, object] = {
        "capability_id": "cli_precommit",
        "product_boundary": "free-local",
        "surfaces": ["cli", "pre_commit"],
        "plans": ["free", "solo", "pro", "team"],
        "owner": "hol-guard",
        "state": "tested",
        "acceptance_tests": ["tests/test_guard_secrets_native_cli.py"],
        "evidence_artifacts": [],
        "release_commit": None,
        "gap_label": "release-candidate evidence pending",
    }
    capability.update(capability_overrides)
    return {
        "schema": "guard-secrets-capability-evidence.v2",
        "generated_at": "2026-08-14",
        "parity_states": [state.value for state in ParityState],
        "claim_policy": {
            "public_parity_requires": "verified_on_release_candidate",
            "exact_release_commit_required": True,
            "remaining_gaps_must_be_labeled": True,
            "public_parity_claim_enabled": False,
            "required_capabilities": ["cli_precommit"],
        },
        "capabilities": [capability],
    }


def _ignore_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "guard-secret-ignore-decision.v2",
        "decision_id": "ignore:1",
        "state": "requested",
        "requested_scope": "occurrence",
        "durable_match_key": "a" * 64,
        "reason": "pending_review",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "detector_version": "guard-secrets-v2",
        "model_version": None,
        "requester_id": "user:1",
        "approver_id": None,
        "policy_source": "personal",
        "propagation": ["cli"],
        "permanent_fixture_justification": None,
    }
    payload.update(overrides)
    return payload


def _direct_ignore(**overrides: object) -> SecretIgnoreDecisionV2:
    values: dict[str, object] = {
        "decision_id": "ignore:direct",
        "state": SecretIgnoreState.REQUESTED,
        "requested_scope": SecretIgnoreScope.OCCURRENCE,
        "durable_match_key": "a" * 64,
        "reason": "pending_review",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "detector_version": "guard-secrets-v2",
        "model_version": None,
        "requester_id": "user:1",
        "approver_id": None,
        "policy_source": "personal",
        "propagation": ("cli",),
    }
    values.update(overrides)
    return SecretIgnoreDecisionV2(**values)  # type: ignore[arg-type]


def _direct_custom_rule(**overrides: object) -> SecretCustomRuleV2:
    values: dict[str, object] = {
        "rule_id": "rule:direct",
        "version": "1.0.0",
        "matcher_kind": SecretRuleMatcherKind.REGEX,
        "matcher_digest": "a" * 64,
        "safe_fixture_digest": "b" * 64,
        "provenance_digest": "c" * 64,
        "compile_state": SecretRuleCompileState.VALID,
        "complexity_budget": 100,
        "rollout_state": SecretRolloutState.DRAFT,
        "surfaces": ("cli",),
    }
    values.update(overrides)
    return SecretCustomRuleV2(**values)  # type: ignore[arg-type]


def test_direct_ignore_rejects_mutable_propagation() -> None:
    mutable = ["cli"]
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_ignore(propagation=mutable)
    mutable.append("github")
    assert mutable == ["cli", "github"]


def test_direct_ignore_rejects_string_propagation() -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_ignore(propagation="cli")


def test_direct_ignore_rejects_duplicate_propagation() -> None:
    with pytest.raises(SecretContractError, match="values must be unique"):
        _direct_ignore(propagation=("cli", "cli"))


def test_direct_ignore_rejects_blank_propagation() -> None:
    with pytest.raises(SecretContractError, match="must not be blank"):
        _direct_ignore(propagation=(" ",))


def test_direct_ignore_rejects_empty_propagation() -> None:
    with pytest.raises(SecretContractError, match="must not be empty"):
        _direct_ignore(propagation=())


def test_direct_custom_rule_rejects_mutable_surfaces() -> None:
    mutable = ["cli"]
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_custom_rule(surfaces=mutable)
    mutable.append("pre_commit")
    assert mutable == ["cli", "pre_commit"]


def test_direct_custom_rule_rejects_string_surfaces() -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_custom_rule(surfaces="cli")


def test_direct_custom_rule_rejects_duplicate_surfaces() -> None:
    with pytest.raises(SecretContractError, match="values must be unique"):
        _direct_custom_rule(surfaces=("cli", "cli"))


def test_direct_custom_rule_rejects_blank_surfaces() -> None:
    with pytest.raises(SecretContractError, match="must not be blank"):
        _direct_custom_rule(surfaces=(" ",))


def test_direct_custom_rule_rejects_empty_surfaces() -> None:
    with pytest.raises(SecretContractError, match="must not be empty"):
        _direct_custom_rule(surfaces=())


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("surfaces", ["cli"]),
        ("plans", ["free"]),
        ("acceptance_tests", ["test_cli"]),
        ("evidence_artifacts", ["sha256:evidence"]),
    ],
)
def test_direct_capability_rejects_mutable_sequence_fields(
    field_name: str,
    value: list[str],
) -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _capability(**{field_name: value})
    value.append("mutated")
    assert value[-1] == "mutated"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("surfaces", "cli"),
        ("plans", "free"),
        ("acceptance_tests", "test_cli"),
        ("evidence_artifacts", "sha256:evidence"),
    ],
)
def test_direct_capability_rejects_string_sequence_fields(
    field_name: str,
    value: str,
) -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _capability(**{field_name: value})


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("surfaces", ("cli", "cli")),
        ("plans", ("free", "free")),
        ("acceptance_tests", ("test_cli", "test_cli")),
        ("evidence_artifacts", ("sha256:evidence", "sha256:evidence")),
    ],
)
def test_direct_capability_rejects_duplicate_sequence_fields(
    field_name: str,
    value: tuple[str, ...],
) -> None:
    with pytest.raises(SecretContractError, match="values must be unique"):
        _capability(**{field_name: value})


@pytest.mark.parametrize(
    "field_name",
    ["surfaces", "plans", "acceptance_tests", "evidence_artifacts"],
)
def test_direct_capability_rejects_blank_sequence_fields(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="must not be blank"):
        _capability(**{field_name: (" ",)})


@pytest.mark.parametrize("field_name", ["surfaces", "plans"])
def test_direct_capability_rejects_empty_required_sequence_fields(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="must not be empty"):
        _capability(**{field_name: ()})


def test_complete_coverage_is_clean_eligible() -> None:
    coverage = _coverage()
    coverage.assert_outcome(PreventionOutcome.CLEAN)
    assert coverage.clean_eligible is True
    assert coverage.to_public_dict()["clean_eligible"] is True


def test_partial_coverage_cannot_claim_clean() -> None:
    coverage = _coverage(partial=True, truncation_codes=["max_bytes"])
    with pytest.raises(SecretContractError, match="cannot produce a clean"):
        coverage.assert_outcome(PreventionOutcome.CLEAN)


def test_missing_requested_ref_cannot_claim_clean() -> None:
    coverage = _coverage(completed_refs=[], partial=True)
    assert coverage.clean_eligible is False
    with pytest.raises(SecretContractError, match="cannot produce a clean"):
        coverage.assert_outcome(PreventionOutcome.CLEAN)


@pytest.mark.parametrize(
    "field_name",
    [
        "files_scanned",
        "bytes_scanned",
        "commits_visited",
        "blobs_scanned",
        "cache_hits",
        "cache_misses",
    ],
)
def test_direct_coverage_rejects_negative_counters(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="non-negative integer"):
        _direct_coverage(**{field_name: -1})


@pytest.mark.parametrize(
    "field_name",
    ["files_scanned", "bytes_scanned", "commits_visited", "blobs_scanned", "cache_hits", "cache_misses"],
)
def test_direct_coverage_rejects_boolean_counters(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="non-negative integer"):
        _direct_coverage(**{field_name: True})


@pytest.mark.parametrize("field_name", ["partial", "degraded"])
def test_direct_coverage_rejects_non_boolean_flags(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="expected a boolean"):
        _direct_coverage(**{field_name: 1})


@pytest.mark.parametrize(
    "field_name", ["source_set", "requested_refs", "completed_refs", "skipped_codes", "truncation_codes"]
)
def test_direct_coverage_rejects_non_tuple_string_fields(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_coverage(**{field_name: ["value"]})


@pytest.mark.parametrize("field_name", ["source_set", "requested_refs", "completed_refs"])
def test_coverage_rejects_duplicate_identity_fields(field_name: str) -> None:
    value = ["duplicate", "duplicate"]
    with pytest.raises(SecretContractError, match="values must be unique"):
        _coverage(**{field_name: value})


@pytest.mark.parametrize("field_name", ["source_set", "requested_refs", "completed_refs"])
def test_coverage_rejects_blank_identity_fields(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="must not be blank"):
        _coverage(**{field_name: [" "]})


def test_direct_coverage_rejects_blank_detector_version() -> None:
    with pytest.raises(SecretContractError, match="invalid length"):
        _direct_coverage(detector_version=" ")


def test_direct_coverage_rejects_empty_source_set() -> None:
    with pytest.raises(SecretContractError, match="source_set must not be empty"):
        _direct_coverage(source_set=())


def test_mapping_coverage_rejects_empty_source_set() -> None:
    with pytest.raises(SecretContractError, match="source_set: must not be empty"):
        _coverage(source_set=[])


def test_direct_coverage_rejects_empty_refs_without_partial() -> None:
    with pytest.raises(SecretContractError, match="empty requested_refs requires partial=true"):
        _direct_coverage(requested_refs=(), completed_refs=())


def test_mapping_coverage_rejects_empty_refs_without_partial() -> None:
    with pytest.raises(SecretContractError, match="empty requested_refs requires partial=true"):
        _coverage(requested_refs=[], completed_refs=[])


def test_empty_ref_partial_coverage_cannot_claim_clean() -> None:
    coverage = _coverage(requested_refs=[], completed_refs=[], partial=True)
    assert coverage.clean_eligible is False
    with pytest.raises(SecretContractError, match="cannot produce a clean"):
        coverage.assert_outcome(PreventionOutcome.CLEAN)


def test_direct_complete_coverage_requires_every_requested_ref() -> None:
    with pytest.raises(SecretContractError, match="complete every requested ref"):
        _direct_coverage(
            requested_refs=("refs/heads/main", "refs/tags/v3"),
            completed_refs=("refs/heads/main",),
        )


def test_mapping_complete_coverage_requires_every_requested_ref() -> None:
    with pytest.raises(SecretContractError, match="complete every requested ref"):
        _coverage(
            requested_refs=["refs/heads/main", "refs/tags/v3"],
            completed_refs=["refs/heads/main"],
        )


def test_direct_coverage_rejects_skipped_work_without_partial() -> None:
    with pytest.raises(SecretContractError, match="skipped work requires partial=true"):
        _direct_coverage(skipped_codes=("binary_skipped",))


def test_mapping_coverage_rejects_skipped_work_without_partial() -> None:
    with pytest.raises(SecretContractError, match="skipped work requires partial=true"):
        _coverage(skipped_codes=["binary_skipped"])


def test_skipped_partial_coverage_cannot_claim_clean() -> None:
    coverage = _coverage(partial=True, skipped_codes=["binary_skipped"])
    assert coverage.clean_eligible is False
    with pytest.raises(SecretContractError, match="cannot produce a clean"):
        coverage.assert_outcome(PreventionOutcome.CLEAN)


def test_direct_coverage_rejects_truncation_without_partial() -> None:
    with pytest.raises(SecretContractError, match="partial=true"):
        _direct_coverage(truncation_codes=("max_bytes",))


def test_direct_coverage_rejects_completed_ref_outside_request() -> None:
    with pytest.raises(SecretContractError, match="subset"):
        _direct_coverage(completed_refs=("refs/heads/other",))


def test_unknown_reason_code_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="unknown reason codes"):
        _direct_coverage(skipped_codes=("future_unknown",), partial=True)


def test_future_coverage_schema_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="unsupported"):
        _coverage(schema="guard-secret-coverage.v3")


def test_unknown_coverage_field_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="unknown fields"):
        _coverage(unreviewed="value")


@pytest.mark.parametrize("key", ["raw_value", "rawValue", "raw-value"])
def test_raw_value_key_spellings_are_rejected(key: str) -> None:
    with pytest.raises(SecretContractError, match="prohibited"):
        reject_prohibited_fields({key: "arbitrary plaintext"})


@pytest.mark.parametrize("key", ["raw_value", "rawValue", "raw-value"])
def test_nested_raw_value_key_spellings_are_rejected(key: str) -> None:
    with pytest.raises(SecretContractError, match="prohibited"):
        reject_prohibited_fields({"safe": {key: "arbitrary plaintext"}})


def test_nested_raw_value_like_field_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="prohibited"):
        reject_prohibited_fields({"safe": {"candidateValue": "not-serialized"}})


def test_nested_secret_like_value_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="secret-like"):
        reject_prohibited_fields({"reason": _FIXTURE_OPENAI_KEY})


@pytest.mark.parametrize(
    ("field_name", "value", "expected_type"),
    [
        ("state", "requested", "SecretIgnoreState"),
        ("requested_scope", "occurrence", "SecretIgnoreScope"),
    ],
)
def test_direct_ignore_rejects_raw_enum_values(
    field_name: str,
    value: str,
    expected_type: str,
) -> None:
    with pytest.raises(SecretContractError, match=f"expected {expected_type}"):
        _direct_ignore(**{field_name: value})


def test_approved_ignore_requires_approver() -> None:
    with pytest.raises(SecretContractError, match="approver"):
        SecretIgnoreDecisionV2(
            decision_id="ignore:1",
            state=SecretIgnoreState.APPROVED,
            requested_scope=SecretIgnoreScope.OCCURRENCE,
            durable_match_key="a" * 64,
            reason="approved_fixture",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            detector_version="guard-secrets-v2",
            model_version=None,
            requester_id="user:1",
            approver_id=None,
            policy_source="personal",
            propagation=("cli", "github"),
        )


@pytest.mark.parametrize(
    "state",
    [SecretIgnoreState.EXPIRED, SecretIgnoreState.REVOKED, SecretIgnoreState.DENIED],
)
def test_terminal_ignore_state_retains_past_expiry(state: SecretIgnoreState) -> None:
    decision = SecretIgnoreDecisionV2(
        decision_id="ignore:terminal",
        state=state,
        requested_scope=SecretIgnoreScope.OCCURRENCE,
        durable_match_key="c" * 64,
        reason="historical_decision",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        detector_version="guard-secrets-v2",
        model_version=None,
        requester_id="user:1",
        approver_id=None,
        policy_source="personal",
        propagation=("cli",),
    )
    assert decision.expires_at is not None


def test_active_ignore_rejects_past_expiry() -> None:
    with pytest.raises(SecretContractError, match="must be in the future"):
        SecretIgnoreDecisionV2(
            decision_id="ignore:active",
            state=SecretIgnoreState.REQUESTED,
            requested_scope=SecretIgnoreScope.OCCURRENCE,
            durable_match_key="d" * 64,
            reason="pending_review",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            detector_version="guard-secrets-v2",
            model_version=None,
            requester_id="user:1",
            approver_id=None,
            policy_source="personal",
            propagation=("cli",),
        )


def test_non_expiring_ignore_requires_fixture_justification() -> None:
    with pytest.raises(SecretContractError, match="justification"):
        SecretIgnoreDecisionV2(
            decision_id="ignore:2",
            state=SecretIgnoreState.REQUESTED,
            requested_scope=SecretIgnoreScope.FIXTURE,
            durable_match_key="b" * 64,
            reason="test_fixture",
            expires_at=None,
            detector_version="guard-secrets-v2",
            model_version=None,
            requester_id="user:1",
            approver_id=None,
            policy_source="personal",
            propagation=("cli",),
        )


def test_ignore_reason_must_be_registered() -> None:
    with pytest.raises(SecretContractError, match="registered reason code"):
        SecretIgnoreDecisionV2(
            decision_id="ignore:3",
            state=SecretIgnoreState.REQUESTED,
            requested_scope=SecretIgnoreScope.OCCURRENCE,
            durable_match_key="e" * 64,
            reason=_FIXTURE_OPENAI_KEY,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            detector_version="guard-secrets-v2",
            model_version=None,
            requester_id="user:1",
            approver_id=None,
            policy_source="personal",
            propagation=("cli",),
        )


def test_ignore_deserialization_rejects_secret_in_reason() -> None:
    with pytest.raises(SecretContractError, match="secret-like"):
        SecretIgnoreDecisionV2.from_mapping(_ignore_payload(reason=_FIXTURE_OPENAI_KEY))


def test_ignore_contract_round_trips_registered_codes() -> None:
    decision = SecretIgnoreDecisionV2.from_mapping(_ignore_payload())
    assert decision.reason in IGNORE_REASON_CODES_V2
    assert SecretIgnoreDecisionV2.from_mapping(decision.to_public_dict()) == decision


def test_non_expiring_fixture_uses_registered_justification_code() -> None:
    payload = _ignore_payload(
        requested_scope="fixture",
        reason="test_fixture",
        expires_at=None,
        permanent_fixture_justification="fixture_is_synthetic",
    )
    decision = SecretIgnoreDecisionV2.from_mapping(payload)
    assert decision.permanent_fixture_justification in FIXTURE_JUSTIFICATION_CODES_V2


@pytest.mark.parametrize(
    ("field_name", "value", "expected_type"),
    [
        ("matcher_kind", "regex", "SecretRuleMatcherKind"),
        ("compile_state", "valid", "SecretRuleCompileState"),
        ("rollout_state", "active", "SecretRolloutState"),
    ],
)
def test_direct_custom_rule_rejects_raw_enum_values(
    field_name: str,
    value: str,
    expected_type: str,
) -> None:
    with pytest.raises(SecretContractError, match=f"expected {expected_type}"):
        _direct_custom_rule(**{field_name: value})


def test_raw_active_invalid_custom_rule_cannot_bypass_compile_check() -> None:
    with pytest.raises(SecretContractError, match="expected SecretRuleCompileState"):
        _direct_custom_rule(compile_state="invalid", rollout_state="active")


def test_active_custom_rule_must_compile_validly() -> None:
    with pytest.raises(SecretContractError, match="valid compiled"):
        SecretCustomRuleV2(
            rule_id="rule:custom:1",
            version="1.0.0",
            matcher_kind=SecretRuleMatcherKind.REGEX,
            matcher_digest="a" * 64,
            safe_fixture_digest="b" * 64,
            provenance_digest="c" * 64,
            compile_state=SecretRuleCompileState.TOO_COMPLEX,
            complexity_budget=100,
            rollout_state=SecretRolloutState.ACTIVE,
            surfaces=("cli",),
        )


def test_custom_rule_complexity_is_bounded() -> None:
    with pytest.raises(SecretContractError, match="complexity_budget"):
        SecretCustomRuleV2(
            rule_id="rule:custom:2",
            version="1.0.0",
            matcher_kind=SecretRuleMatcherKind.PREFIX,
            matcher_digest="a" * 64,
            safe_fixture_digest="b" * 64,
            provenance_digest="c" * 64,
            compile_state=SecretRuleCompileState.VALID,
            complexity_budget=100_001,
            rollout_state=SecretRolloutState.DRAFT,
            surfaces=("cli",),
        )


def test_custom_rule_rejects_unknown_surface() -> None:
    with pytest.raises(SecretContractError, match="unknown rule surface"):
        SecretCustomRuleV2(
            rule_id="rule:custom:3",
            version="1.0.0",
            matcher_kind=SecretRuleMatcherKind.PREFIX,
            matcher_digest="a" * 64,
            safe_fixture_digest="b" * 64,
            provenance_digest="c" * 64,
            compile_state=SecretRuleCompileState.VALID,
            complexity_budget=100,
            rollout_state=SecretRolloutState.DRAFT,
            surfaces=("unknown",),
        )


def test_direct_capability_rejects_raw_parity_state() -> None:
    with pytest.raises(SecretContractError, match="expected ParityState"):
        _capability(
            state="verified_on_release_candidate",
            release_commit="d" * 40,
            evidence_artifacts=("sha256:evidence",),
            gap_label=None,
        )


def test_release_claim_rejects_unverified_capability() -> None:
    with pytest.raises(SecretContractError, match="not verified"):
        validate_capability_manifest(
            [_capability()],
            required_capability_ids=frozenset({"secret:cli"}),
            exact_release_commit="d" * 40,
        )


def test_release_claim_accepts_exact_commit_evidence() -> None:
    commit = "d" * 40
    capability = _capability(
        state=ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
        evidence_artifacts=("sha256:benchmark",),
        release_commit=commit,
        gap_label=None,
    )
    validate_capability_manifest(
        [capability],
        required_capability_ids=frozenset({"secret:cli"}),
        exact_release_commit=commit,
    )


def test_malformed_release_commit_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="full commit SHA"):
        validate_capability_manifest(
            [],
            required_capability_ids=frozenset(),
            exact_release_commit="D" * 40,
        )


def test_duplicate_capability_ids_are_rejected() -> None:
    capability = _capability()
    with pytest.raises(SecretContractError, match="must be unique"):
        validate_capability_manifest(
            [capability, capability],
            required_capability_ids=frozenset({"secret:cli"}),
            exact_release_commit="d" * 40,
        )


def test_missing_required_capability_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="required capabilities are unmapped"):
        validate_capability_manifest(
            [],
            required_capability_ids=frozenset({"secret:ide"}),
            exact_release_commit="d" * 40,
        )


def test_capability_rejects_unknown_product_boundary() -> None:
    with pytest.raises(SecretContractError, match="unknown product boundary"):
        _capability(product_boundary="undeclared")


def test_capability_rejects_plan_outside_product_boundary() -> None:
    with pytest.raises(SecretContractError, match="plans outside"):
        _capability(product_boundary="organization-governance", plans=("free",), surfaces=("portal",))


def test_capability_rejects_surface_outside_product_boundary() -> None:
    with pytest.raises(SecretContractError, match="surfaces outside"):
        _capability(product_boundary="free-local", surfaces=("portal",))


def test_capability_rejects_secret_in_gap_label_on_direct_construction() -> None:
    with pytest.raises(SecretContractError, match="secret-like"):
        _capability(gap_label=_FIXTURE_OPENAI_KEY)


def test_capability_manifest_rejects_secret_in_gap_label() -> None:
    with pytest.raises(SecretContractError, match="secret-like"):
        parse_capability_evidence_manifest(_manifest(gap_label=_FIXTURE_OPENAI_KEY))


def test_every_outcome_has_a_surface_mapping() -> None:
    assert set(OUTCOME_SURFACE_MAPPING) == set(PreventionOutcome)


def test_repository_reason_code_manifest_matches_runtime() -> None:
    manifest = parse_reason_codes_manifest(_load(_REASON_CODE_PATH))
    assert manifest.category_ids == tuple(REASON_CODE_CATEGORIES_V2)
    assert manifest.codes == REASON_CODES_V2
    assert manifest.rule_ids == tuple(REASON_CODE_RULES_V2)


def test_reason_code_manifest_rejects_schema_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    payload["schema"] = "guard-secrets-reason-codes.v3"
    with pytest.raises(SecretContractError, match="unsupported reason-code"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_category_registry_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    categories["unreviewed"] = ["unreviewed_reason"]
    with pytest.raises(SecretContractError, match="category registry"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_code_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    coverage = categories["coverage"]
    assert isinstance(coverage, list)
    coverage[0] = "unreviewed_reason"
    with pytest.raises(SecretContractError, match="codes do not match"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_duplicate_code_in_category() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    coverage = categories["coverage"]
    assert isinstance(coverage, list)
    coverage.append(coverage[0])
    with pytest.raises(SecretContractError, match="must be unique"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_code_in_multiple_categories() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    coverage = categories["coverage"]
    detector = categories["detector"]
    assert isinstance(coverage, list)
    assert isinstance(detector, list)
    detector.insert(0, coverage[0])
    with pytest.raises(SecretContractError, match="exactly one category"):
        parse_reason_codes_manifest(payload)


@pytest.mark.parametrize("rule_id", tuple(REASON_CODE_RULES_V2))
def test_reason_code_manifest_rejects_rule_weakening(rule_id: str) -> None:
    payload = _load(_REASON_CODE_PATH)
    rules = payload["rules"]
    assert isinstance(rules, dict)
    rules[rule_id] = False
    with pytest.raises(SecretContractError, match="policy does not match"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_rule_registry_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    rules = payload["rules"]
    assert isinstance(rules, dict)
    rules["unreviewed"] = True
    with pytest.raises(SecretContractError, match="rule registry"):
        parse_reason_codes_manifest(payload)


def test_repository_product_boundary_manifest_matches_runtime() -> None:
    manifest = parse_product_boundaries_manifest(_load(_PRODUCT_BOUNDARY_PATH))
    assert manifest.plan_ids == frozenset({"free", "solo", "pro", "team"})
    assert "shared-detection" in manifest.boundary_ids
    assert "cli" in manifest.surface_ids


def test_product_boundary_manifest_rejects_unknown_plan() -> None:
    payload = _load(_PRODUCT_BOUNDARY_PATH)
    plans = payload["plans"]
    assert isinstance(plans, dict)
    plans["enterprise"] = copy.deepcopy(plans["team"])
    with pytest.raises(SecretContractError, match="plan registry"):
        parse_product_boundaries_manifest(payload)


def test_product_boundary_manifest_rejects_unknown_surface() -> None:
    payload = _load(_PRODUCT_BOUNDARY_PATH)
    surfaces = payload["surface_values"]
    assert isinstance(surfaces, list)
    surfaces.append("unreviewed")
    with pytest.raises(SecretContractError, match="surface_values"):
        parse_product_boundaries_manifest(payload)


def test_product_boundary_manifest_rejects_policy_drift() -> None:
    payload = _load(_PRODUCT_BOUNDARY_PATH)
    boundaries = payload["product_boundaries"]
    assert isinstance(boundaries, dict)
    free_local = boundaries["free-local"]
    assert isinstance(free_local, dict)
    free_local["allowed_plans"] = ["free"]
    with pytest.raises(SecretContractError, match="allowed plans"):
        parse_product_boundaries_manifest(payload)


def test_product_boundary_manifest_rejects_invariant_drift() -> None:
    payload = _load(_PRODUCT_BOUNDARY_PATH)
    payload["invariants"] = ["local_detection_unmetered"]
    with pytest.raises(SecretContractError, match="invariants"):
        parse_product_boundaries_manifest(payload)


def test_repository_source_capability_manifest_matches_runtime() -> None:
    manifest = parse_source_capabilities_manifest(_load(_SOURCE_CAPABILITY_PATH))
    assert manifest.status_values == SOURCE_CAPABILITY_STATUS_VALUES_V2
    assert "operating_systems" in manifest.sections


def test_source_capability_manifest_rejects_invalid_status_value() -> None:
    payload = _load(_SOURCE_CAPABILITY_PATH)
    operating_systems = payload["operating_systems"]
    assert isinstance(operating_systems, dict)
    operating_systems["linux"] = "complete"
    with pytest.raises(SecretContractError, match="invalid status"):
        parse_source_capabilities_manifest(payload)


def test_source_capability_manifest_rejects_unknown_capability() -> None:
    payload = _load(_SOURCE_CAPABILITY_PATH)
    operating_systems = payload["operating_systems"]
    assert isinstance(operating_systems, dict)
    operating_systems["plan9"] = "planned"
    with pytest.raises(SecretContractError, match="capability keys"):
        parse_source_capabilities_manifest(payload)


def test_source_capability_manifest_rejects_policy_status_drift() -> None:
    payload = _load(_SOURCE_CAPABILITY_PATH)
    operating_systems = payload["operating_systems"]
    assert isinstance(operating_systems, dict)
    operating_systems["linux"] = "partial"
    with pytest.raises(SecretContractError, match="statuses"):
        parse_source_capabilities_manifest(payload)


def test_manifest_parser_consumes_declared_policy() -> None:
    manifest = parse_capability_evidence_manifest(_manifest())
    assert manifest.row_errors == ()
    assert manifest.public_parity_requires is ParityState.VERIFIED_ON_RELEASE_CANDIDATE
    assert manifest.exact_release_commit_required is True
    assert manifest.remaining_gaps_must_be_labeled is True
    assert manifest.public_parity_claim_enabled is False
    assert manifest.required_capability_ids == frozenset({"cli_precommit"})


def test_manifest_parser_rejects_parity_state_drift() -> None:
    payload = _manifest()
    payload["parity_states"] = ["unmapped", "tested"]
    with pytest.raises(SecretContractError, match="do not match"):
        parse_capability_evidence_manifest(payload)


def test_manifest_parser_rejects_claim_policy_weakening() -> None:
    payload = _manifest()
    policy = payload["claim_policy"]
    assert isinstance(policy, dict)
    policy["exact_release_commit_required"] = False
    with pytest.raises(SecretContractError, match="must require"):
        parse_capability_evidence_manifest(payload)


def test_manifest_parser_rejects_unlabeled_gap_policy_weakening() -> None:
    payload = _manifest()
    policy = payload["claim_policy"]
    assert isinstance(policy, dict)
    policy["remaining_gaps_must_be_labeled"] = False
    with pytest.raises(SecretContractError, match="must require labels"):
        parse_capability_evidence_manifest(payload)


def test_manifest_parser_rejects_duplicate_required_capabilities() -> None:
    payload = _manifest()
    policy = payload["claim_policy"]
    assert isinstance(policy, dict)
    policy["required_capabilities"] = ["cli_precommit", "cli_precommit"]
    with pytest.raises(SecretContractError, match="must be unique"):
        parse_capability_evidence_manifest(payload)


def test_manifest_parser_reports_unmapped_claim_policy_capability() -> None:
    payload = _manifest()
    policy = payload["claim_policy"]
    assert isinstance(policy, dict)
    policy["required_capabilities"] = ["cli_precommit", "ide_prevention"]
    manifest = parse_capability_evidence_manifest(payload)
    assert manifest.row_errors == ("claim policy capabilities are unmapped: ide_prevention",)
