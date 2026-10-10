"""Valid command-activity fixtures for the parity recorder (original Python types)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityMatchClass,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandActivityMatch,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
)
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    COMMAND_SHADOW_CONTROL_GENERATION,
    COMMAND_SHADOW_SCHEMA_VERSION,
    CommandShadowCohort,
    CommandShadowComparison,
    CommandShadowObservation,
)
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind, UncertaintyKind
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.extension_evidence import EvidenceSeverity, ExtensionRuleIdentity

__all__ = [
    "at",
    "evidence_a",
    "evidence_b",
    "evidence_c",
    "evidence_d",
    "evidence_e",
    "handle",
    "pre_activity",
    "replace",
    "shadow_for",
]


def at(year: int, month: int, day: int, hour: int = 12, minute: int = 0, second: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def handle(kind: CorrelationKind, digest_char: str, harness: str = "codex") -> CorrelationHandle:
    return CorrelationHandle(kind, harness, "key.v1", digest_char * 64)


def pre_activity(
    activity_id: str,
    occurred_at: datetime,
    *,
    request: str | None = "a",
    session: str | None = "b",
    **overrides: object,
) -> CommandActivity:
    base: dict[str, object] = {
        "activity_id": activity_id,
        "occurred_at": occurred_at,
        "harness": "codex",
        "hook_phase": CommandHookPhase.PRE,
        "execution_status": CommandExecutionStatus.ALLOWED_UNCONFIRMED,
        "proof_level": CommandProofLevel.PRE_HOOK,
        "policy_action": "allow",
        "decision_reason_code": ActivityDecisionReason.NO_MATCH,
        "controlling_rule_id": None,
        "parse_confidence": ActivityParseConfidence.EXACT,
        "uncertainty_class": None,
        "match_count": 0,
        "prompted": False,
        "approval_reuse_status": ActivityApprovalReuseStatus.NOT_APPLICABLE,
        "request_correlation": handle(CorrelationKind.REQUEST, request) if request else None,
        "session_correlation": handle(CorrelationKind.SESSION, session) if session else None,
        "receipt_link_status": ReceiptLinkStatus.NOT_APPLICABLE,
        "receipt_id": None,
        "evaluation_latency_bucket": ActivityLatencyBucket.LE_5_MS,
        "persistence_latency_bucket": ActivityLatencyBucket.LE_2_MS,
    }
    base.update(overrides)
    return CommandActivity(**base)  # type: ignore[arg-type]


def _match(
    activity_id: str,
    ordinal: int,
    extension: str,
    rule: str,
    effects: set[EffectKind],
    *,
    severity: EvidenceSeverity = EvidenceSeverity.HIGH,
    floor: str = "review",
    safe_variant_id: str | None = None,
) -> CommandActivityMatch:
    return CommandActivityMatch(
        activity_id=activity_id,
        ordinal=ordinal,
        identity=ExtensionRuleIdentity(extension, "2.2.0", rule, "1.0.0"),
        match_class=ActivityMatchClass.SAFE_VARIANT if safe_variant_id else ActivityMatchClass.UNSAFE,
        severity=severity,
        default_floor=floor,  # type: ignore[arg-type]
        effect_claims=frozenset(effects),
        safe_variant_id=safe_variant_id,
    )


def evidence_a(activity_id: str = "activity:a", occurred_at: datetime | None = None, **overrides: object):
    """Two matches, request and session handles, review floor with receipt."""

    when = occurred_at or at(2026, 7, 18, 20)
    fields: dict[str, object] = {
        "decision_reason_code": ActivityDecisionReason.EXTENSION_MATCH,
        "controlling_rule_id": "command.git.push",
        "match_count": 2,
        "policy_action": "review",
        "prompted": True,
        "receipt_link_status": ReceiptLinkStatus.LINKED,
        "receipt_id": "receipt:one",
    }
    fields.update(overrides)
    activity = pre_activity(activity_id, when, **fields)
    matches = (
        _match(
            activity_id,
            0,
            "command.git",
            "command.git.push",
            {EffectKind.REMOTE_STATE_MUTATION, EffectKind.NETWORK_READ},
        ),
        _match(
            activity_id,
            1,
            "command.package",
            "command.package.install",
            {EffectKind.PACKAGE_OR_SOURCE_INSTALLATION},
            severity=EvidenceSeverity.CRITICAL,
            floor="require-reapproval",
        ),
    )
    return CommandActivityEvidence(activity, matches)


def evidence_b(activity_id: str = "activity:b", occurred_at: datetime | None = None, **overrides: object):
    """No matches, request handle only, allow."""

    fields: dict[str, object] = {"session": None, "request": "c"}
    fields.update(overrides)
    activity = pre_activity(activity_id, occurred_at or at(2026, 7, 18, 20, 5), **fields)
    return CommandActivityEvidence(activity, ())


def evidence_c(activity_id: str = "activity:c", occurred_at: datetime | None = None, **overrides: object):
    """One safe-variant match, no correlation handles, warn."""

    fields: dict[str, object] = {
        "request": None,
        "session": None,
        "decision_reason_code": ActivityDecisionReason.EXTENSION_MATCH,
        "controlling_rule_id": "command.safe.read",
        "match_count": 1,
        "policy_action": "warn",
        "evaluation_latency_bucket": ActivityLatencyBucket.LE_20_MS,
    }
    fields.update(overrides)
    activity = pre_activity(activity_id, occurred_at or at(2026, 7, 19, 8), **fields)
    match = _match(
        activity_id,
        0,
        "command.safe",
        "command.safe.read",
        {EffectKind.WORKSPACE_OR_PUBLIC_READ},
        severity=EvidenceSeverity.LOW,
        floor="warn",
        safe_variant_id="variant.one",
    )
    return CommandActivityEvidence(activity, (match,))


def evidence_d(activity_id: str = "activity:d", occurred_at: datetime | None = None, **overrides: object):
    """Unpaired post: no decision facts, session handle only."""

    fields: dict[str, object] = {
        "request": None,
        "session": "d",
        "hook_phase": CommandHookPhase.POST_SUCCESS,
        "execution_status": CommandExecutionStatus.UNPAIRED_POST,
        "proof_level": CommandProofLevel.UNPAIRED_POST,
        "policy_action": None,
        "decision_reason_code": None,
        "parse_confidence": None,
        "evaluation_latency_bucket": ActivityLatencyBucket.NOT_MEASURED,
    }
    fields.update(overrides)
    activity = pre_activity(activity_id, occurred_at or at(2026, 7, 19, 9), **fields)
    return CommandActivityEvidence(activity, ())


def evidence_e(activity_id: str = "activity:e", occurred_at: datetime | None = None, **overrides: object):
    """Fallback parse with an uncertainty class and one uncertainty match, block."""

    fields: dict[str, object] = {
        "request": "e",
        "session": "f",
        "decision_reason_code": ActivityDecisionReason.UNCERTAINTY,
        "controlling_rule_id": "command.uncertain.parse",
        "parse_confidence": ActivityParseConfidence.FALLBACK,
        "uncertainty_class": UncertaintyKind.PARTIAL_PARSE,
        "match_count": 1,
        "policy_action": "block",
        "execution_status": CommandExecutionStatus.PREVENTED,
        "receipt_link_status": ReceiptLinkStatus.LINKED,
        "receipt_id": "receipt:two",
    }
    fields.update(overrides)
    activity = pre_activity(activity_id, occurred_at or at(2026, 7, 20, 10), **fields)
    match = replace(
        _match(activity_id, 0, "command.uncertain", "command.uncertain.parse", {EffectKind.PROCESS_EXECUTION}),
        match_class=ActivityMatchClass.UNCERTAINTY,
        default_floor="block",
    )
    return CommandActivityEvidence(activity, (match,))


def shadow_for(
    evidence: CommandActivityEvidence,
    *,
    cohorts: tuple[CommandShadowCohort, ...] = (CommandShadowCohort.BASELINE,),
    proposal_version: str = "proposal.multi.v1",
) -> CommandShadowObservation:
    return CommandShadowObservation(
        activity_id=evidence.activity.activity_id,
        occurred_at=evidence.activity.occurred_at,
        cohorts=cohorts,
        authoritative_action="allow",
        current_action="allow",
        current_disposition=FinalDisposition.SILENT_VERIFIED,
        proposed_action="review",
        proposed_disposition=FinalDisposition.REVIEW,
        comparison=CommandShadowComparison.STRENGTHENED,
        proposal_version=proposal_version,
        evaluator_schema_version="1.0.0",
        control_generation=COMMAND_SHADOW_CONTROL_GENERATION,
        sample_basis_points=10_000,
        schema_version=COMMAND_SHADOW_SCHEMA_VERSION,
    )
