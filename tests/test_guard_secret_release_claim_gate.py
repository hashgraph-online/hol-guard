from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_GATE_PATH = _REPOSITORY_ROOT / "scripts/ci/guard_secrets_release_claim_gate.py"
_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-capability-evidence.v2.json"
_PRODUCT_BOUNDARY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-product-boundaries.v2.json"
_SOURCE_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-source-capabilities.v2.json"
_REASON_CODE_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-reason-codes.v2.json"
_SPEC = importlib.util.spec_from_file_location("guard_secrets_release_claim_gate", _GATE_PATH)
assert _SPEC and _SPEC.loader
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)

ClaimGateError = _GATE.ClaimGateError
load_manifest = _GATE.load_manifest
validate_manifest = _GATE.validate_manifest


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest(**overrides: object) -> dict[str, object]:
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
    capability.update(overrides)
    return {
        "schema": "guard-secrets-capability-evidence.v2",
        "generated_at": "2026-08-14",
        "parity_states": [
            "unmapped",
            "designed",
            "implemented",
            "tested",
            "verified_on_release_candidate",
            "generally_available",
        ],
        "claim_policy": {
            "public_parity_requires": "verified_on_release_candidate",
            "exact_release_commit_required": True,
            "remaining_gaps_must_be_labeled": True,
            "public_parity_claim_enabled": False,
            "required_capabilities": ["cli_precommit"],
        },
        "capabilities": [capability],
    }


def _validate(
    capability_payload: dict[str, object],
    *,
    release_commit: str = "a" * 40,
    require_parity: bool = False,
    required_capabilities: frozenset[str] = frozenset({"cli_precommit"}),
    product_boundary_payload: dict[str, object] | None = None,
    source_capability_payload: dict[str, object] | None = None,
    reason_code_payload: dict[str, object] | None = None,
) -> tuple[str, ...]:
    return validate_manifest(
        capability_payload,
        product_boundary_payload=(
            product_boundary_payload if product_boundary_payload is not None else _load(_PRODUCT_BOUNDARY_PATH)
        ),
        source_capability_payload=(
            source_capability_payload if source_capability_payload is not None else _load(_SOURCE_CAPABILITY_PATH)
        ),
        reason_code_payload=(reason_code_payload if reason_code_payload is not None else _load(_REASON_CODE_PATH)),
        exact_release_commit=release_commit,
        require_parity=require_parity,
        required_capabilities=required_capabilities,
    )


def _write_manifest(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_repository_manifests_are_structurally_valid() -> None:
    capability_payload = load_manifest(_CAPABILITY_PATH)
    required = capability_payload["claim_policy"]["required_capabilities"]
    assert isinstance(required, list)
    errors = validate_manifest(
        capability_payload,
        product_boundary_payload=load_manifest(_PRODUCT_BOUNDARY_PATH),
        source_capability_payload=load_manifest(_SOURCE_CAPABILITY_PATH),
        reason_code_payload=load_manifest(_REASON_CODE_PATH),
        exact_release_commit="a" * 40,
        require_parity=False,
        required_capabilities=frozenset(required),
    )
    assert errors == ()


def test_unknown_capability_state_is_rejected() -> None:
    assert _validate(_manifest(state="complete")) == ("cli_precommit: invalid parity state",)


def test_non_release_state_requires_gap_label() -> None:
    assert _validate(_manifest(gap_label=None)) == ("cli_precommit: non-release state requires an explicit gap label",)


def test_release_state_requires_exact_evidence() -> None:
    assert _validate(
        _manifest(
            state="verified_on_release_candidate",
            release_commit=None,
            evidence_artifacts=[],
            gap_label=None,
        )
    ) == ("release-candidate capability requires an exact commit SHA",)


def test_parity_claim_requires_same_release_commit() -> None:
    payload = _manifest(
        state="verified_on_release_candidate",
        release_commit="a" * 40,
        evidence_artifacts=["sha256:evidence"],
        gap_label=None,
    )
    policy = payload["claim_policy"]
    assert isinstance(policy, dict)
    policy["public_parity_claim_enabled"] = True
    assert _validate(payload, release_commit="b" * 40, require_parity=True) == (
        "cli_precommit: evidence is bound to a different commit",
    )


def test_public_parity_policy_cannot_be_bypassed() -> None:
    payload = _manifest()
    policy = payload["claim_policy"]
    assert isinstance(policy, dict)
    policy["public_parity_claim_enabled"] = True
    with pytest.raises(ClaimGateError, match="cannot be omitted"):
        _validate(payload, require_parity=False)


def test_disabled_public_parity_policy_cannot_be_overridden() -> None:
    with pytest.raises(ClaimGateError, match="not authorized"):
        _validate(_manifest(), require_parity=True)


def test_required_capability_list_must_match_policy() -> None:
    with pytest.raises(ClaimGateError, match="missing: cli_precommit"):
        _validate(_manifest(), required_capabilities=frozenset())


def test_required_capability_list_rejects_unexpected_values() -> None:
    with pytest.raises(ClaimGateError, match="unexpected: ide_prevention"):
        _validate(
            _manifest(),
            required_capabilities=frozenset({"cli_precommit", "ide_prevention"}),
        )


def test_release_commit_is_always_required() -> None:
    with pytest.raises(ClaimGateError, match="requires an exact release commit"):
        validate_manifest(
            _manifest(),
            product_boundary_payload=_load(_PRODUCT_BOUNDARY_PATH),
            source_capability_payload=_load(_SOURCE_CAPABILITY_PATH),
            reason_code_payload=_load(_REASON_CODE_PATH),
            exact_release_commit=None,
            require_parity=False,
            required_capabilities=frozenset({"cli_precommit"}),
        )


def test_invalid_release_sha_is_rejected() -> None:
    with pytest.raises(ClaimGateError, match="full lowercase SHA"):
        _validate(_manifest(), release_commit="short")


def test_future_manifest_schema_is_rejected(tmp_path: Path) -> None:
    path = _write_manifest(
        tmp_path / "manifest.json",
        {"schema": "guard-secrets-capability-evidence.v3"},
    )
    with pytest.raises(ClaimGateError, match="unsupported"):
        _validate(dict(load_manifest(path)))


def test_parity_state_declaration_drift_is_rejected() -> None:
    payload = _manifest()
    payload["parity_states"] = ["unmapped", "tested"]
    with pytest.raises(ClaimGateError, match="do not match"):
        _validate(payload)


def test_claim_policy_drift_is_rejected() -> None:
    payload = _manifest()
    policy = payload["claim_policy"]
    assert isinstance(policy, dict)
    policy["public_parity_requires"] = "tested"
    with pytest.raises(ClaimGateError, match="release-candidate verified or GA"):
        _validate(payload)


def test_product_boundary_drift_is_rejected_by_gate() -> None:
    payload = _load(_PRODUCT_BOUNDARY_PATH)
    payload["invariants"] = ["local_detection_unmetered"]
    with pytest.raises(ClaimGateError, match="invariants"):
        _validate(_manifest(), product_boundary_payload=payload)


def test_source_capability_drift_is_rejected_by_gate() -> None:
    payload = _load(_SOURCE_CAPABILITY_PATH)
    operating_systems = payload["operating_systems"]
    assert isinstance(operating_systems, dict)
    operating_systems["linux"] = "partial"
    with pytest.raises(ClaimGateError, match="statuses"):
        _validate(_manifest(), source_capability_payload=payload)


def test_reason_code_schema_drift_is_rejected_by_gate() -> None:
    payload = _load(_REASON_CODE_PATH)
    payload["schema"] = "guard-secrets-reason-codes.v3"
    with pytest.raises(ClaimGateError, match="unsupported reason-code"):
        _validate(_manifest(), reason_code_payload=payload)


@pytest.mark.parametrize(
    "rule_id",
    (
        "stable",
        "non_sensitive",
        "unknown_codes_fail_closed",
        "raw_exception_text_forbidden",
    ),
)
def test_reason_code_policy_weakening_is_rejected_by_gate(rule_id: str) -> None:
    payload = _load(_REASON_CODE_PATH)
    rules = payload["rules"]
    assert isinstance(rules, dict)
    rules[rule_id] = False
    with pytest.raises(ClaimGateError, match="policy does not match"):
        _validate(_manifest(), reason_code_payload=payload)


def test_main_returns_zero_for_repository_policy(capsys: pytest.CaptureFixture[str]) -> None:
    capability_payload = _load(_CAPABILITY_PATH)
    policy = capability_payload["claim_policy"]
    assert isinstance(policy, dict)
    required = policy["required_capabilities"]
    assert isinstance(required, list)
    argv = [
        "--manifest",
        str(_CAPABILITY_PATH),
        "--product-boundaries",
        str(_PRODUCT_BOUNDARY_PATH),
        "--source-capabilities",
        str(_SOURCE_CAPABILITY_PATH),
        "--reason-codes",
        str(_REASON_CODE_PATH),
        "--release-commit",
        "a" * 40,
    ]
    for capability_id in required:
        argv.extend(("--required-capability", capability_id))
    assert _GATE.main(argv) == 0
    assert capsys.readouterr().err == ""


def test_main_returns_one_for_validation_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write_manifest(tmp_path / "invalid-row.json", _manifest(gap_label=None))
    argv = [
        "--manifest",
        str(path),
        "--product-boundaries",
        str(_PRODUCT_BOUNDARY_PATH),
        "--source-capabilities",
        str(_SOURCE_CAPABILITY_PATH),
        "--reason-codes",
        str(_REASON_CODE_PATH),
        "--release-commit",
        "a" * 40,
        "--required-capability",
        "cli_precommit",
    ]
    assert _GATE.main(argv) == 1
    assert "non-release state requires" in capsys.readouterr().err


def test_main_returns_two_for_input_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "malformed.json"
    path.write_text("{", encoding="utf-8")
    argv = [
        "--manifest",
        str(path),
        "--product-boundaries",
        str(_PRODUCT_BOUNDARY_PATH),
        "--source-capabilities",
        str(_SOURCE_CAPABILITY_PATH),
        "--reason-codes",
        str(_REASON_CODE_PATH),
        "--release-commit",
        "a" * 40,
        "--required-capability",
        "cli_precommit",
    ]
    assert _GATE.main(argv) == 2
    assert "guard-secrets-claim-gate:" in capsys.readouterr().err
