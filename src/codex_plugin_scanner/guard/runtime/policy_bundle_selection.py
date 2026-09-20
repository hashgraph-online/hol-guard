"""Select complete canonical sources without treating row caching as application."""

from __future__ import annotations

from ..models import PolicyDecision
from ..native_mode import native_mode_requires_rust
from ..native_policy_authority_command_source import has_canonical_command_expressions
from ..policy_bundle_decisions import build_policy_bundle_decisions as materialize_legacy_decisions
from ..policy_bundle_staging import prepare_canonical_policy_bundle_staging
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from ..policy_document import GuardPolicyDocument
from ..policy_document_types import PolicyCompilationError
from ..store import GuardStore


def canonical_decisions_for_sync(
    bundle: dict[str, object], *, device_id: str, device_name: str, canonical_enforcement: bool
) -> tuple[list[PolicyDecision], bool]:
    staged = prepare_canonical_policy_bundle_staging(bundle, device_id=device_id, device_name=device_name)
    if staged.require_source_binding and (not canonical_enforcement or not native_mode_requires_rust()):
        payload = bundle.get("payload")
        assert isinstance(payload, dict)  # Complete staging validated this source.
        document = GuardPolicyDocument.from_mapping(payload)
        rule_id = next(
            rule.id
            for rule in document.rules
            if rule.enabled and rule.effect != "ignore" and rule.match.command_expression is not None
        )
        raise PolicyCompilationError(
            "command_expression_native_lane_unavailable",
            rule_id,
            field_path="match.commands",
            remediation="Use a verified native canonical consumer, or remove this command expression.",
        )
    return list(staged.decisions), staged.require_source_binding


def build_policy_bundle_decisions(
    policy_bundle: dict[str, object], *, device_id: str, device_name: str, canonical_enforcement: bool = False
) -> list[PolicyDecision]:
    if policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        if not canonical_enforcement and not has_canonical_command_expressions(policy_bundle):
            return []
        decisions, expressions = canonical_decisions_for_sync(
            policy_bundle, device_id=device_id, device_name=device_name, canonical_enforcement=canonical_enforcement
        )
        return decisions if canonical_enforcement or expressions else []
    return materialize_legacy_decisions(policy_bundle, device_id=device_id, device_name=device_name)


def policy_shadow_mismatch_reason_codes(
    legacy: list[PolicyDecision],
    canonical: list[PolicyDecision],
) -> tuple[str, ...]:
    if not legacy:
        return ("legacy_unavailable",)

    def keyed(
        decisions: list[PolicyDecision],
    ) -> dict[tuple[str, str, str | None, str | None, str | None, str | None], PolicyDecision]:
        return {
            (
                decision.harness,
                decision.scope,
                decision.artifact_id,
                decision.artifact_hash,
                decision.workspace,
                decision.publisher,
            ): decision
            for decision in decisions
        }

    reasons: list[str] = []
    legacy_by_key = keyed(legacy)
    canonical_by_key = keyed(canonical)
    if len(legacy) != len(canonical):
        reasons.append("row_count")
    if legacy_by_key.keys() != canonical_by_key.keys():
        reasons.append("selector_set")
    shared_keys = legacy_by_key.keys() & canonical_by_key.keys()
    if any(legacy_by_key[key].action != canonical_by_key[key].action for key in shared_keys):
        reasons.append("action")
    if any(legacy_by_key[key].expires_at != canonical_by_key[key].expires_at for key in shared_keys):
        reasons.append("expiration")
    return tuple(reasons[:4])


def select_canonical_policy_candidate(
    store: GuardStore,
    bundle: dict[str, object],
    *,
    existing_bundle: dict[str, object] | None,
    device_id: str,
    device_name: str,
    canonical_enforcement: bool,
    now: str,
) -> tuple[list[PolicyDecision], str | None]:
    canonical, expressions = canonical_decisions_for_sync(
        bundle, device_id=device_id, device_name=device_name, canonical_enforcement=canonical_enforcement
    )
    if expressions:
        # The legacy row evaluator has no expression semantics to compare. The
        # complete native projection and later accepted publication are required.
        return canonical, None
    legacy_payload = store.get_sync_payload("policy_bundle_legacy_last_good")
    if not isinstance(legacy_payload, dict):
        legacy_payload = (
            existing_bundle
            if isinstance(existing_bundle, dict) and existing_bundle.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT
            else None
        )
    legacy = (
        build_policy_bundle_decisions(legacy_payload, device_id=device_id, device_name=device_name)
        if isinstance(legacy_payload, dict)
        else []
    )
    reasons = policy_shadow_mismatch_reason_codes(legacy, canonical)
    blocking = tuple(reason for reason in reasons if reason != "legacy_unavailable")
    selected = canonical if canonical_enforcement and not blocking else legacy
    if reasons:
        store.add_event(
            "policy_bundle/shadow_mismatch",
            {
                "canonicalRows": len(canonical),
                "legacyRows": len(legacy),
                "reasonCodes": list(reasons),
                "status": "mismatch",
            },
            now,
        )
    return selected, "canonical_shadow_mismatch" if canonical_enforcement and blocking else None


def compilation_rejection_details(error: PolicyCompilationError) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": error.rule_id,
        "remediation": error.remediation or "Remove the unsupported rule clause or choose a supported target consumer.",
    }
    if error.field_path is not None:
        result["fieldPath"] = error.field_path
    return result
