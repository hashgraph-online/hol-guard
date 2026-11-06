"""The public report contract remains valid and explicitly non-authoritative."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from codex_plugin_scanner.models import Finding, ScanResult, Severity, build_severity_counts
from codex_plugin_scanner.reporting import build_json_payload


def _payload(scope: str = "plugin") -> dict:
    """Build the real serializer output with an inert high-severity finding."""
    findings = (Finding("TEST-HIGH", Severity.HIGH, "security", "Example", "Review the source location."),)
    result = ScanResult(
        score=90,
        grade="A",
        categories=(),
        timestamp="2026-10-04T00:00:00Z",
        plugin_dir="untrusted-plugin",
        findings=findings,
        severity_counts=build_severity_counts(findings),
        scope=scope,
    )
    return build_json_payload(result, policy_pass=False)


def _validator() -> Draft202012Validator:
    """Load the committed consumer schema, not a permissive test substitute."""
    path = Path(__file__).resolve().parents[1] / "schemas" / "scan-result.v1.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.mark.parametrize("scope", ["plugin", "repository"])
def test_contributor_payload_matches_the_public_schema(scope: str) -> None:
    """Strict consumers accept the additive contributor review metadata."""
    _validator().validate(_payload(scope))


@pytest.mark.parametrize("flag", ["automaticApproval", "sourceBoundAttestation"])
def test_review_schema_rejects_authoritative_flags(flag: str) -> None:
    """Report-only guidance must not masquerade as an admission decision."""
    payload = _payload()
    payload["contributorReview"][flag] = True
    with pytest.raises(ValidationError):
        _validator().validate(payload)


def test_review_schema_rejects_an_approved_disposition() -> None:
    """There is no implemented approval lane in the contributor report."""
    payload = _payload()
    payload["contributorReview"]["groups"][0]["disposition"] = "approved"
    with pytest.raises(ValidationError):
        _validator().validate(payload)


def test_review_schema_rejects_undeclared_override_fields() -> None:
    """Additional fields cannot silently extend the review contract."""
    payload = _payload()
    payload["contributorReview"]["override"] = True
    with pytest.raises(ValidationError):
        _validator().validate(payload)
