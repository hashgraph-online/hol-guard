"""Describe source representability without asserting a negotiated active route."""

from __future__ import annotations

from dataclasses import replace
from typing import Final, TypedDict

from ..version import __version__
from .policy_capability_inventory import local_row_projection_capabilities
from .policy_document import NETWORK_POLICY_SPEC_FIELD, GuardPolicyDocument
from .policy_document_compile import compile_policy_document
from .policy_document_types import PolicyCompilationError
from .policy_error_guidance import public_policy_document_error

GENERIC_LANE: Final = "generic-local-sqlite"
NATIVE_DEFAULTS_LANE: Final = "native-intrinsic"
NATIVE_SCOPED_LANE: Final = "native-scoped-v4"
RUNTIME_LANES: Final = (GENERIC_LANE, NATIVE_DEFAULTS_LANE, NATIVE_SCOPED_LANE)


class LaneDiagnostic(TypedDict):
    code: str
    rule_id: str | None
    field_path: str
    runtime_lane: str
    remediation: str


class LaneValidation(TypedDict):
    runtime_lane: str
    valid: bool
    compiled_rows: int
    rule_diagnostics: list[LaneDiagnostic]
    validation_scope: str
    activation_evidence: str


def source_runtime_lane_observation() -> dict[str, object]:
    """A source catalog cannot attest which consumer handled a live request."""
    return {
        "contractVersion": "guard.runtime-lane-observation.v1",
        "profileId": "guard.runtime-lanes.v1",
        "runtimeVersion": __version__,
        "selectedLane": None,
        "readiness": "unavailable",
    }


def published_runtime_lane_profiles() -> dict[str, object]:
    """Return fresh descriptive data; no field grants enforcement authority."""
    return {
        "contract_version": "guard.runtime-lane-profile.v1",
        "purpose": "representability_only",
        "activation_evidence": "not_evaluated",
        "command_expression_projection": {
            "evaluator": "policy evaluate-command",
            "authenticated_application": "unsupported",
            "match_fields": ["commands"],
            "lifetimes": ["permanent"],
            "effects": ["allow", "review", "block"],
            "additional_selectors": "unsupported",
            "expiry": "unsupported",
            "local_context": "unsupported",
            "managed_authority": "unsupported",
        },
        "lanes": {
            GENERIC_LANE: {
                "projection": local_row_projection_capabilities(),
                "request_identity": "actual producer context required for every selector",
                "activation": "not_evaluated",
            },
            NATIVE_DEFAULTS_LANE: {
                "snapshot_version": 3,
                "generic_rules": "unsupported",
                "managed_authority": "unsupported",
                "intrinsic_blocks": "never_weakened",
            },
            NATIVE_SCOPED_LANE: {
                "snapshot_version": 4,
                "generic_projection": local_row_projection_capabilities(),
                "request_identities": {
                    "shell": ["pwd", "true", "echo", "printf", "whoami", "uname"],
                    "ssh": "destination only; no flags, remote command, or compound command",
                    "read": "one existing nonsensitive workspace file",
                    "mcp": "bounded tool name and empty arguments",
                },
                "content_context_authority": "unsupported",
                "managed_authority": "unsupported",
                "native_approval_context": "unsupported",
                "unmodeled_request_shapes": "refused",
                "intrinsic_review": "preserved except valid exact signed command approval",
                "artifact_only_approval_context": "unsupported",
                "activation": {
                    "advertised": False,
                    "reason": "negotiated_consumer_not_proven",
                    "required_features": [
                        "policy-snapshot-v4",
                        "policy-scoped-authority-v1",
                        "hook-envelope-v3",
                    ],
                },
            },
        },
    }


def _diagnostic(
    lane: str,
    code: str,
    rule_id: str | None,
    field_path: str,
    remediation: str,
) -> LaneDiagnostic:
    return {
        "code": code,
        "rule_id": rule_id,
        "field_path": field_path,
        "runtime_lane": lane,
        "remediation": remediation,
    }


def _compile_diagnostic(lane: str, error: PolicyCompilationError) -> LaneDiagnostic:
    public = public_policy_document_error(error)
    rule_id = public["rule_id"]
    return _diagnostic(
        lane,
        error.code,
        rule_id if isinstance(rule_id, str) else None,
        str(public["field_path"]),
        str(public["remediation"]),
    )


def validate_policy_runtime_lane(document: GuardPolicyDocument, lane: str) -> LaneValidation:
    """Report every offending active rule, without removing unsupported selectors."""
    if lane not in RUNTIME_LANES:
        raise ValueError("unsupported_runtime_lane")
    diagnostics: list[LaneDiagnostic] = []
    row_count = 0
    if any(key == NETWORK_POLICY_SPEC_FIELD for key, _ in document.spec_extensions):
        diagnostics.append(
            _diagnostic(
                lane,
                "network_policy_requires_separate_runtime",
                None,
                "$.spec.networkPolicy",
                "Use an authenticated consumer for the complete network authority; this lane cannot apply it.",
            )
        )
    for rule in document.rules:
        if not rule.enabled or rule.effect == "ignore":
            continue
        if any(key == "x-hol-extension-targets" for key, _ in rule.extensions):
            diagnostics.append(
                _diagnostic(
                    lane,
                    "managed_rule_requires_separate_runtime",
                    rule.id,
                    "$.spec.rules[*].x-hol-extension-targets",
                    "Validate this rule against an authenticated managed runtime without discarding its targets.",
                )
            )
        try:
            rows = compile_policy_document(replace(document, rules=(rule,)))
        except PolicyCompilationError as error:
            diagnostics.append(_compile_diagnostic(lane, error))
            continue
        row_count += len(rows)
        if lane == NATIVE_DEFAULTS_LANE:
            diagnostics.append(
                _diagnostic(
                    lane,
                    "native_scoped_policy_unsupported",
                    rule.id,
                    "$.spec.rules[*]",
                    "Use a consumer that supports the complete rule; native intrinsic defaults cannot apply it.",
                )
            )
        elif lane == NATIVE_SCOPED_LANE:
            has_context = any(row.decision.artifact_hash is not None for row in rows)
            diagnostics.append(
                _diagnostic(
                    lane,
                    "native_content_context_unsupported" if has_context else "native_lane_unnegotiated",
                    rule.id,
                    "$.spec.rules[*]",
                    "Retain every restriction and obtain an authenticated ready consumer before activation.",
                )
            )
    for key, _ in document.extensions:
        if key in {"x-hol-extension-controls", "x-hol-custom-extension-continuity"}:
            diagnostics.append(
                _diagnostic(
                    lane,
                    "managed_policy_requires_separate_runtime",
                    None,
                    f"$.{key}",
                    "Validate the complete managed authority using its dedicated authenticated runtime.",
                )
            )
    if not diagnostics:
        try:
            # Per-rule checks cannot establish the document-wide fanout limit.
            row_count = len(compile_policy_document(document))
        except PolicyCompilationError as error:
            diagnostics.append(_compile_diagnostic(lane, error))
    if lane == NATIVE_SCOPED_LANE and not diagnostics:
        diagnostics.append(
            _diagnostic(
                lane,
                "native_lane_unnegotiated",
                None,
                "$.spec",
                "A static profile is not evidence of an authenticated ready consumer.",
            )
        )
    return {
        "runtime_lane": lane,
        "valid": not diagnostics,
        "compiled_rows": row_count,
        "rule_diagnostics": diagnostics,
        "validation_scope": "static_representability",
        "activation_evidence": "not_evaluated",
    }


def command_evaluator_document(document: GuardPolicyDocument) -> GuardPolicyDocument:
    """Refuse a projection that would silently discard an active restriction."""
    if any(key == NETWORK_POLICY_SPEC_FIELD for key, _ in document.spec_extensions):
        raise PolicyCompilationError("network_policy_requires_separate_runtime", document.metadata.id)
    if any(key in {"x-hol-extension-controls", "x-hol-custom-extension-continuity"} for key, _ in document.extensions):
        raise PolicyCompilationError("command_evaluator_scope_unsupported", document.metadata.id)
    active = tuple(rule for rule in document.rules if rule.enabled and rule.effect != "ignore")
    for rule in active:
        if (
            rule.match.command_expression is None
            or rule.match.fields
            or rule.match.exact_command_sha256 is not None
            or rule.match.extensions
            or rule.lifetime.mode != "permanent"
            or rule.lifetime.expires_at is not None
            or any(key in {"x-hol-local", "x-hol-extension-targets"} for key, _ in rule.extensions)
        ):
            raise PolicyCompilationError("command_evaluator_scope_unsupported", rule.id)
    return replace(document, rules=active)
