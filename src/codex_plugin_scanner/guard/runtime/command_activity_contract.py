"""Versioned, privacy-safe contracts for local command activity evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from enum import Enum
from typing import Final, cast

from codex_plugin_scanner.guard.action_lattice import guard_action_severity, is_guard_action
from codex_plugin_scanner.guard.adapters.contracts import HARNESS_CONTRACTS
from codex_plugin_scanner.guard.models import GuardAction

from .effect_contract import EffectKind, UncertaintyKind
from .extension_evidence import EvidenceSeverity, ExtensionRuleIdentity

COMMAND_ACTIVITY_SCHEMA_VERSION: Final = "1.0.0"
_OPAQUE_ID: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_STABLE_ID: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
COMMAND_ACTIVITY_HARNESSES: Final = frozenset(contract.harness for contract in HARNESS_CONTRACTS)


class CommandHookPhase(str, Enum):
    PRE = "pre"
    POST_SUCCESS = "post_success"
    POST_FAILURE = "post_failure"


class CommandExecutionStatus(str, Enum):
    ATTEMPTED = "attempted"
    PREVENTED = "prevented"
    ALLOWED_UNCONFIRMED = "allowed_unconfirmed"
    CONFIRMED_SUCCESS = "confirmed_success"
    CONFIRMED_FAILURE = "confirmed_failure"
    UNPAIRED_POST = "unpaired_post"


class CommandProofLevel(str, Enum):
    PRE_HOOK = "pre_hook"
    POST_HOOK = "post_hook"
    UNPAIRED_POST = "unpaired_post"


class ActivityParseConfidence(str, Enum):
    EXACT = "exact"
    FALLBACK = "fallback"
    UNCERTAIN = "uncertain"


class ActivityDecisionReason(str, Enum):
    NO_MATCH = "no_match"
    EXTENSION_MATCH = "extension_match"
    UNCERTAINTY = "uncertainty"
    POLICY = "policy"
    APPROVAL_REUSE = "approval_reuse"
    CONTAINMENT = "containment"
    CAPABILITY = "capability"


class ActivityApprovalReuseStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NOT_APPLICABLE = "not-applicable"


class ReceiptLinkStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    LINKED = "linked"


class ActivityMatchClass(str, Enum):
    UNSAFE = "unsafe"
    SAFE_VARIANT = "safe_variant"
    UNCERTAINTY = "uncertainty"


class ActivityLatencyBucket(str, Enum):
    NOT_MEASURED = "not_measured"
    LE_1_MS = "le_1_ms"
    LE_2_MS = "le_2_ms"
    LE_5_MS = "le_5_ms"
    LE_10_MS = "le_10_ms"
    LE_20_MS = "le_20_ms"
    LE_50_MS = "le_50_ms"
    LE_100_MS = "le_100_ms"
    GT_100_MS = "gt_100_ms"


class CorrelationKind(str, Enum):
    REQUEST = "request"
    SESSION = "session"


@dataclass(frozen=True, slots=True)
class CorrelationHandle:
    """A local keyed handle. It is pseudonymous and must never leave the device."""

    kind: CorrelationKind
    harness: str
    key_id: str
    digest: str = field(repr=False)

    def __post_init__(self) -> None:
        _require_enum(self.kind, CorrelationKind, "kind")
        _require_stable_id(self.harness, "harness")
        _require_stable_id(self.key_id, "key_id")
        if not isinstance(cast(object, self.digest), str) or re.fullmatch(r"[0-9a-f]{64}", self.digest) is None:
            raise ValueError("digest must be a 256-bit lowercase hexadecimal HMAC")


@dataclass(frozen=True, slots=True)
class CommandActivity:
    """One logical command row updated through the allowed lifecycle."""

    activity_id: str
    occurred_at: datetime
    harness: str
    hook_phase: CommandHookPhase
    execution_status: CommandExecutionStatus
    proof_level: CommandProofLevel
    policy_action: GuardAction | None
    decision_reason_code: ActivityDecisionReason | None
    controlling_rule_id: str | None
    parse_confidence: ActivityParseConfidence | None
    uncertainty_class: UncertaintyKind | None
    match_count: int
    prompted: bool
    approval_reuse_status: ActivityApprovalReuseStatus
    request_correlation: CorrelationHandle | None
    session_correlation: CorrelationHandle | None
    receipt_link_status: ReceiptLinkStatus
    receipt_id: str | None
    evaluation_latency_bucket: ActivityLatencyBucket
    persistence_latency_bucket: ActivityLatencyBucket
    schema_version: str = COMMAND_ACTIVITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_opaque_id(self.activity_id, "activity_id")
        _require_utc_datetime(self.occurred_at)
        _require_stable_id(self.harness, "harness")
        _require_enum(self.hook_phase, CommandHookPhase, "hook_phase")
        _require_enum(self.execution_status, CommandExecutionStatus, "execution_status")
        _require_enum(self.proof_level, CommandProofLevel, "proof_level")
        _require_optional_guard_action(self.policy_action)
        if self.decision_reason_code is not None:
            _require_enum(self.decision_reason_code, ActivityDecisionReason, "decision_reason_code")
        _require_optional_stable_id(self.controlling_rule_id, "controlling_rule_id")
        if self.parse_confidence is not None:
            _require_enum(self.parse_confidence, ActivityParseConfidence, "parse_confidence")
        if self.uncertainty_class is not None:
            _require_enum(self.uncertainty_class, UncertaintyKind, "uncertainty_class")
        if type(self.match_count) is not int or self.match_count < 0:
            raise ValueError("match_count must be a non-negative integer")
        if type(self.prompted) is not bool:
            raise ValueError("prompted must be a boolean")
        _require_enum(self.approval_reuse_status, ActivityApprovalReuseStatus, "approval_reuse_status")
        if self.prompted and self.approval_reuse_status is ActivityApprovalReuseStatus.ACCEPTED:
            raise ValueError("accepted approval reuse cannot claim a prompt")
        _require_optional_correlation(self.request_correlation, CorrelationKind.REQUEST, self.harness)
        _require_optional_correlation(self.session_correlation, CorrelationKind.SESSION, self.harness)
        _require_enum(self.receipt_link_status, ReceiptLinkStatus, "receipt_link_status")
        if self.receipt_id is not None:
            _require_opaque_id(self.receipt_id, "receipt_id")
        _require_enum(self.evaluation_latency_bucket, ActivityLatencyBucket, "evaluation_latency_bucket")
        _require_enum(self.persistence_latency_bucket, ActivityLatencyBucket, "persistence_latency_bucket")
        _require_schema_version(self.schema_version)
        _validate_activity_state(self)


@dataclass(frozen=True, slots=True)
class CommandActivityMatch:
    activity_id: str
    ordinal: int
    identity: ExtensionRuleIdentity
    match_class: ActivityMatchClass
    severity: EvidenceSeverity
    default_floor: GuardAction
    effect_claims: frozenset[EffectKind]
    safe_variant_id: str | None = None
    schema_version: str = COMMAND_ACTIVITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_opaque_id(self.activity_id, "activity_id")
        if type(self.ordinal) is not int or self.ordinal < 0:
            raise ValueError("ordinal must be a non-negative integer")
        if not isinstance(cast(object, self.identity), ExtensionRuleIdentity):
            raise ValueError("identity must be an ExtensionRuleIdentity")
        _require_enum(self.match_class, ActivityMatchClass, "match_class")
        _require_enum(self.severity, EvidenceSeverity, "severity")
        if not is_guard_action(self.default_floor):
            raise ValueError("default_floor must be a canonical GuardAction")
        if not isinstance(cast(object, self.effect_claims), frozenset) or not self.effect_claims:
            raise ValueError("effect_claims must be a non-empty frozenset")
        if any(not isinstance(cast(object, item), EffectKind) for item in self.effect_claims):
            raise ValueError("effect_claims members must be EffectKind values")
        _require_optional_stable_id(self.safe_variant_id, "safe_variant_id")
        if (self.match_class is ActivityMatchClass.SAFE_VARIANT) != (self.safe_variant_id is not None):
            raise ValueError("safe_variant match class requires exactly one safe_variant_id")
        _require_schema_version(self.schema_version)


@dataclass(frozen=True, slots=True)
class CommandActivityEvidence:
    activity: CommandActivity
    matches: tuple[CommandActivityMatch, ...]

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.activity), CommandActivity):
            raise ValueError("activity must be a CommandActivity")
        if not isinstance(cast(object, self.matches), tuple) or any(
            not isinstance(cast(object, item), CommandActivityMatch) for item in self.matches
        ):
            raise ValueError("matches must be a tuple of CommandActivityMatch values")
        if self.activity.match_count != len(self.matches):
            raise ValueError("match_count must equal the number of match rows")
        if any(item.activity_id != self.activity.activity_id for item in self.matches):
            raise ValueError("every match must reference the parent activity_id")
        if tuple(item.ordinal for item in self.matches) != tuple(range(len(self.matches))):
            raise ValueError("match ordinals must be unique, ordered, and contiguous from zero")
        identities = tuple(item.identity for item in self.matches)
        if len(identities) != len(set(identities)):
            raise ValueError("an activity cannot repeat an extension rule identity")
        rule_id_values = tuple(item.identity.rule_id for item in self.matches)
        if len(rule_id_values) != len(set(rule_id_values)):
            raise ValueError("an activity cannot repeat a logical rule_id across versions")
        rule_ids = set(rule_id_values)
        if self.activity.controlling_rule_id is not None and self.activity.controlling_rule_id not in rule_ids:
            raise ValueError("controlling_rule_id must identify one of the activity matches")


COMMAND_ACTIVITY_FIELDS: Final = tuple(field.name for field in fields(CommandActivity))
COMMAND_ACTIVITY_MATCH_FIELDS: Final = tuple(field.name for field in fields(CommandActivityMatch))


def validate_activity_transition(previous: CommandActivity, current: CommandActivity) -> None:
    """Reject out-of-order, conflicting, or fact-changing lifecycle updates."""

    if not isinstance(cast(object, previous), CommandActivity) or not isinstance(
        cast(object, current), CommandActivity
    ):
        raise ValueError("activity transitions require exact CommandActivity values")
    immutable_fields = (
        "activity_id",
        "occurred_at",
        "harness",
        "policy_action",
        "decision_reason_code",
        "controlling_rule_id",
        "parse_confidence",
        "uncertainty_class",
        "match_count",
        "prompted",
        "approval_reuse_status",
        "request_correlation",
        "session_correlation",
        "receipt_link_status",
        "receipt_id",
        "evaluation_latency_bucket",
        "schema_version",
    )
    if any(getattr(previous, name) != getattr(current, name) for name in immutable_fields):
        raise ValueError("activity transitions cannot change decision, identity, proof, or match facts")
    if previous.execution_status is current.execution_status:
        if previous != current:
            raise ValueError("idempotent activity replay cannot change persisted fields")
        return
    allowed = {
        CommandExecutionStatus.ATTEMPTED: {
            CommandExecutionStatus.PREVENTED,
            CommandExecutionStatus.ALLOWED_UNCONFIRMED,
        },
        CommandExecutionStatus.ALLOWED_UNCONFIRMED: {
            CommandExecutionStatus.CONFIRMED_SUCCESS,
            CommandExecutionStatus.CONFIRMED_FAILURE,
        },
    }
    if current.execution_status not in allowed.get(previous.execution_status, set()):
        raise ValueError("invalid or conflicting command activity lifecycle transition")


def _validate_activity_state(activity: CommandActivity) -> None:
    pre_statuses = {
        CommandExecutionStatus.ATTEMPTED,
        CommandExecutionStatus.PREVENTED,
        CommandExecutionStatus.ALLOWED_UNCONFIRMED,
    }
    confirmed = {
        CommandExecutionStatus.CONFIRMED_SUCCESS: CommandHookPhase.POST_SUCCESS,
        CommandExecutionStatus.CONFIRMED_FAILURE: CommandHookPhase.POST_FAILURE,
    }
    if activity.execution_status in pre_statuses:
        if activity.hook_phase is not CommandHookPhase.PRE or activity.proof_level is not CommandProofLevel.PRE_HOOK:
            raise ValueError("pre-hook statuses require pre phase and pre-hook proof")
    elif activity.execution_status in confirmed:
        if (
            activity.hook_phase is not confirmed[activity.execution_status]
            or activity.proof_level is not CommandProofLevel.POST_HOOK
        ):
            raise ValueError("confirmed status requires its matching post phase and post-hook proof")
        if activity.request_correlation is None:
            raise ValueError("confirmed status requires one strong request correlation")
    elif activity.execution_status is CommandExecutionStatus.UNPAIRED_POST:
        if activity.hook_phase is CommandHookPhase.PRE or activity.proof_level is not CommandProofLevel.UNPAIRED_POST:
            raise ValueError("unpaired post requires a post phase and unpaired-post proof")
        if activity.request_correlation is not None:
            raise ValueError("unpaired post cannot claim request correlation")
        if any(
            (
                activity.policy_action is not None,
                activity.decision_reason_code is not None,
                activity.controlling_rule_id is not None,
                activity.parse_confidence is not None,
                activity.uncertainty_class is not None,
                activity.match_count != 0,
                activity.prompted,
                activity.approval_reuse_status is not ActivityApprovalReuseStatus.NOT_APPLICABLE,
                activity.receipt_link_status is not ReceiptLinkStatus.NOT_APPLICABLE,
                activity.receipt_id is not None,
                activity.evaluation_latency_bucket is not ActivityLatencyBucket.NOT_MEASURED,
            )
        ):
            raise ValueError("unpaired post cannot invent pre-hook decision or match facts")
    if activity.parse_confidence is ActivityParseConfidence.EXACT and activity.uncertainty_class is not None:
        raise ValueError("exact parse confidence cannot carry uncertainty")
    if (
        activity.parse_confidence in {ActivityParseConfidence.FALLBACK, ActivityParseConfidence.UNCERTAIN}
        and activity.uncertainty_class is None
    ):
        raise ValueError("non-exact parse confidence requires a bounded uncertainty class")
    if activity.execution_status is not CommandExecutionStatus.UNPAIRED_POST and (
        activity.policy_action is None or activity.decision_reason_code is None or activity.parse_confidence is None
    ):
        raise ValueError("pre and confirmed activity requires complete bounded decision facts")
    if activity.match_count == 0 and activity.controlling_rule_id is not None:
        raise ValueError("an activity without matches cannot name a controlling rule")
    if activity.execution_status is not CommandExecutionStatus.UNPAIRED_POST:
        if activity.decision_reason_code is ActivityDecisionReason.NO_MATCH and activity.match_count != 0:
            raise ValueError("no-match reason cannot carry activity matches")
        if activity.match_count == 0 and activity.decision_reason_code not in {
            ActivityDecisionReason.NO_MATCH,
            ActivityDecisionReason.CAPABILITY,
        }:
            raise ValueError("an activity without matches requires a no-match or capability reason")
    if activity.receipt_link_status is ReceiptLinkStatus.LINKED and activity.receipt_id is None:
        raise ValueError("linked receipt status requires receipt_id")
    if activity.receipt_link_status is ReceiptLinkStatus.NOT_APPLICABLE and activity.receipt_id is not None:
        raise ValueError("receipt_id requires linked receipt status")
    if (
        activity.policy_action is not None
        and guard_action_severity(activity.policy_action) >= guard_action_severity("review")
        and activity.receipt_link_status is not ReceiptLinkStatus.LINKED
    ):
        raise ValueError("review-or-stronger activity requires a linked receipt")


def _require_schema_version(value: object) -> None:
    if value != COMMAND_ACTIVITY_SCHEMA_VERSION:
        raise ValueError("unsupported command activity schema version")


def _require_utc_datetime(value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise ValueError("occurred_at must be a timezone-aware UTC datetime")


def _require_opaque_id(value: object, label: str) -> None:
    if not isinstance(value, str) or _OPAQUE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a bounded opaque identifier")


def _require_stable_id(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or _STABLE_ID.fullmatch(value) is None
        or (label == "harness" and value not in COMMAND_ACTIVITY_HARNESSES)
    ):
        raise ValueError(f"{label} must be a stable lowercase identifier")


def _require_optional_stable_id(value: object, label: str) -> None:
    if value is not None:
        _require_stable_id(value, label)


def _require_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{label} must be an exact {enum_type.__name__} value")


def _require_optional_guard_action(value: object) -> None:
    if value is not None and not is_guard_action(value):
        raise ValueError("policy_action must be a canonical GuardAction or None")


def _require_optional_correlation(
    value: object,
    kind: CorrelationKind,
    harness: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, CorrelationHandle):
        raise ValueError("correlation values must be exact CorrelationHandle values")
    if value.kind is not kind or value.harness != harness:
        raise ValueError("correlation kind and harness must match the activity")
