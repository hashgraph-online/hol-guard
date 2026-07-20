"""Typed runtime decisions for Guard pause and approval UX."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, TypeGuard

from codex_plugin_scanner.guard.action_lattice import (
    guard_action_severity,
    is_action_bearing_key,
    most_restrictive_guard_action,
)
from codex_plugin_scanner.guard.models import GUARD_ACTION_VALUES, GuardAction
from codex_plugin_scanner.guard.runtime.composition_rules import compose_action_from_signals
from codex_plugin_scanner.guard.runtime.signals import (
    RiskConfidenceLabel,
    RiskSignalV2,
)

GuardDecisionAction = Literal["allow", "warn", "ask", "block"]

AUTHORITATIVE_DECISION_SCHEMA_VERSION = 1
AUTHORITATIVE_DECISION_INCONSISTENT = "authoritative_decision_inconsistent"
_BLOCKING_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
_COMPOSITION_ACTION_FIELDS = (
    "configured_action",
    "current_action",
    "saved_action",
    "scanner_action",
    "runtime_detector_action",
)
_KNOWN_COMPOSITION_ACTION_FIELDS = frozenset((*_COMPOSITION_ACTION_FIELDS, "final_action"))
_TERMINAL_COMPOSITION_ACTIONS = frozenset({"sandbox-required", "block"})
_APPROVAL_REUSE_ACCEPTED_REASON = "approval_reuse_accepted"
_TRUSTED_REQUEST_OVERRIDE_REASON = "trusted_request_override_exact_context"
_SAVED_APPROVAL_CLAIM_DISPOSITIONS = frozenset({"consumed", "retained"})
_DECISION_V2_FIELDS = frozenset(
    {
        "guard_action",
        "action",
        "reason",
        "user_title",
        "user_body",
        "harness_message",
        "dashboard_primary_detail",
        "approval_scopes",
        "retry_instruction",
        "signals",
        "confidence",
    }
)
_DECISION_V2_ACTION_FIELDS = frozenset({"guard_action", "action"})
_ENFORCEMENT_FIELDS = frozenset(
    {
        "blocking",
        "authority_finalized",
        "launch_permitted",
        "prompt_required",
        "sandbox_required",
        "snapshot_permitted",
    }
)
_AUTHORITATIVE_DECISION_FIELDS = frozenset(
    {
        "schema_version",
        "action",
        "source",
        "reason",
        "composition_trace",
        "signals",
        "enforcement",
        "decision_v2",
    }
)
_ARTIFACT_ACTION_FIELDS = frozenset({"policy_action", "verdict_action", "action_envelope_json"})
_ACTION_ENVELOPE_ACTION_FIELDS = frozenset(
    {
        "action_id",
        "action_type",
        "policy_action",
        "pre_execution_result",
        "actionId",
        "actionType",
        "policyAction",
        "preExecutionResult",
    }
)

_ACTION_MESSAGES: dict[GuardAction, tuple[GuardDecisionAction, str, str, str]] = {
    "allow": (
        "allow",
        "Allowed by policy",
        "Policy allows this action.",
        "HOL Guard allowed this action because policy already trusts it.",
    ),
    "warn": (
        "warn",
        "Risk signals found",
        "HOL Guard noticed risk signals, but policy allows the harness to continue.",
        "Review the warning if this action was unexpected.",
    ),
    "review": (
        "ask",
        "Approval required",
        "HOL Guard needs your approval before this action can run.",
        "Choose an approval scope, then retry in the harness.",
    ),
    "sandbox-required": (
        "ask",
        "Sandbox review required",
        "HOL Guard wants this action reviewed and run in a sandboxed path.",
        "Run this action in an approved sandbox, then retry.",
    ),
    "require-reapproval": (
        "ask",
        "Fresh approval required",
        "HOL Guard needs a fresh approval because this action changed.",
        "Choose the smallest approval scope that matches your intent, then retry.",
    ),
    "block": (
        "block",
        "Blocked by policy",
        "HOL Guard blocked this action.",
        "Review the details before changing policy or retrying.",
    ),
}


@dataclass(frozen=True, slots=True)
class GuardDecisionV2:
    """Product-facing Guard decision with harness and dashboard copy."""

    guard_action: GuardAction
    action: GuardDecisionAction
    reason: str
    user_title: str
    user_body: str
    harness_message: str
    dashboard_primary_detail: str
    approval_scopes: tuple[str, ...]
    retry_instruction: str | None
    signals: tuple[RiskSignalV2, ...]
    confidence: RiskConfidenceLabel

    def to_dict(self) -> dict[str, object]:
        return {
            "guard_action": self.guard_action,
            "action": self.action,
            "reason": self.reason,
            "user_title": self.user_title,
            "user_body": self.user_body,
            "harness_message": self.harness_message,
            "dashboard_primary_detail": self.dashboard_primary_detail,
            "approval_scopes": list(self.approval_scopes),
            "retry_instruction": self.retry_instruction,
            "signals": [signal.to_dict() for signal in self.signals],
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardDecisionV2:
        _reject_unknown_action_bearing_fields(
            payload,
            allowed=_DECISION_V2_ACTION_FIELDS,
            context="decision_v2",
        )
        guard_action = _parse_guard_action(payload.get("guard_action"))
        action = _parse_action(payload.get("action"))
        if action != _ACTION_MESSAGES[guard_action][0]:
            raise ValueError("decision_v2.action must match guard_action")
        return cls(
            guard_action=guard_action,
            action=action,
            reason=_required_string(payload, "reason"),
            user_title=_required_string(payload, "user_title"),
            user_body=_required_string(payload, "user_body"),
            harness_message=_required_string(payload, "harness_message"),
            dashboard_primary_detail=_required_string(payload, "dashboard_primary_detail"),
            approval_scopes=_parse_string_tuple(payload.get("approval_scopes"), "approval_scopes"),
            retry_instruction=_optional_string(payload, "retry_instruction"),
            signals=_parse_signals(payload.get("signals")),
            confidence=_parse_confidence(payload.get("confidence")),
        )


@dataclass(frozen=True, slots=True)
class GuardDecisionEnforcementState:
    """Execution and persistence effects derived from one exact Guard action."""

    blocking: bool
    authority_finalized: bool
    launch_permitted: bool
    prompt_required: bool
    sandbox_required: bool
    snapshot_permitted: bool

    def to_dict(self) -> dict[str, bool]:
        return {
            "blocking": self.blocking,
            "authority_finalized": self.authority_finalized,
            "launch_permitted": self.launch_permitted,
            "prompt_required": self.prompt_required,
            "sandbox_required": self.sandbox_required,
            "snapshot_permitted": self.snapshot_permitted,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> GuardDecisionEnforcementState:
        _require_exact_fields(payload, _ENFORCEMENT_FIELDS, "enforcement")
        state = cls(
            blocking=_required_bool(payload, "blocking"),
            authority_finalized=_required_bool(payload, "authority_finalized"),
            launch_permitted=_required_bool(payload, "launch_permitted"),
            prompt_required=_required_bool(payload, "prompt_required"),
            sandbox_required=_required_bool(payload, "sandbox_required"),
            snapshot_permitted=_required_bool(payload, "snapshot_permitted"),
        )
        return state


@dataclass(frozen=True, slots=True)
class AuthoritativeGuardDecision:
    """The single decision from which display, storage, and launch fields derive."""

    schema_version: int
    action: GuardAction
    source: str
    reason: str
    composition_trace: Mapping[str, object]
    signals: tuple[RiskSignalV2, ...]
    enforcement: GuardDecisionEnforcementState
    decision_v2: GuardDecisionV2

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "action": self.action,
            "source": self.source,
            "reason": self.reason,
            "composition_trace": dict(self.composition_trace),
            "signals": [signal.to_dict() for signal in self.signals],
            "enforcement": self.enforcement.to_dict(),
            "decision_v2": self.decision_v2.to_dict(),
        }

    def to_artifact_projection(self) -> dict[str, object]:
        """Return every compatibility field from this decision, never raw scoring."""

        return {
            "authoritative_decision": self.to_dict(),
            "policy_action": self.action,
            "decision_v2_json": self.decision_v2.to_dict(),
            "policy_composition": dict(self.composition_trace),
            # Deprecated compatibility alias. Historically this contained the
            # scanner recommendation and could contradict execution. It now
            # means the exact final action; raw scoring is nested separately.
            "verdict_action": self.action,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> AuthoritativeGuardDecision:
        _require_exact_fields(payload, _AUTHORITATIVE_DECISION_FIELDS, "authoritative_decision")
        schema_version = payload.get("schema_version")
        if schema_version != AUTHORITATIVE_DECISION_SCHEMA_VERSION or isinstance(schema_version, bool):
            raise ValueError(f"schema_version must be {AUTHORITATIVE_DECISION_SCHEMA_VERSION}")
        action = _parse_guard_action(payload.get("action"))
        source = _required_string(payload, "source")
        reason = _required_string(payload, "reason")
        raw_composition = payload.get("composition_trace")
        if not isinstance(raw_composition, Mapping) or not all(isinstance(key, str) for key in raw_composition):
            raise ValueError("composition_trace must be an object with string keys")
        composition_trace = dict(raw_composition)
        if composition_trace.get("final_action") != action:
            raise ValueError("composition_trace.final_action must match action")
        signals = _parse_signals(payload.get("signals"))
        raw_enforcement = payload.get("enforcement")
        if not isinstance(raw_enforcement, Mapping):
            raise ValueError("enforcement must be an object")
        enforcement = GuardDecisionEnforcementState.from_dict(raw_enforcement)
        raw_decision_v2 = payload.get("decision_v2")
        if not isinstance(raw_decision_v2, Mapping):
            raise ValueError("decision_v2 must be an object")
        _require_exact_fields(raw_decision_v2, _DECISION_V2_FIELDS, "decision_v2")
        decision_v2 = GuardDecisionV2.from_dict(raw_decision_v2)
        decision = cls(
            schema_version=AUTHORITATIVE_DECISION_SCHEMA_VERSION,
            action=action,
            source=source,
            reason=reason,
            composition_trace=MappingProxyType(composition_trace),
            signals=signals,
            enforcement=enforcement,
            decision_v2=decision_v2,
        )
        _validate_authoritative_decision(decision)
        return decision


def build_authoritative_decision(
    action: GuardAction,
    *,
    reason: str,
    composition_trace: Mapping[str, object],
    signals: Sequence[RiskSignalV2] = (),
    authority_finalized: bool,
    source: str = "composed-consumer-policy",
) -> AuthoritativeGuardDecision:
    """Build the sole decision after all policy and approval composition."""

    if not reason.strip():
        raise ValueError("reason must be a non-empty string")
    trace = dict(composition_trace)
    trace["final_action"] = action
    signal_tuple = tuple(signals)
    blocking = action in _BLOCKING_ACTIONS
    enforcement = GuardDecisionEnforcementState(
        blocking=blocking,
        authority_finalized=authority_finalized,
        launch_permitted=not blocking and authority_finalized,
        prompt_required=action in {"review", "require-reapproval"},
        sandbox_required=action == "sandbox-required",
        snapshot_permitted=not blocking and authority_finalized,
    )
    decision = AuthoritativeGuardDecision(
        schema_version=AUTHORITATIVE_DECISION_SCHEMA_VERSION,
        action=action,
        source=source,
        reason=reason,
        composition_trace=MappingProxyType(trace),
        signals=signal_tuple,
        enforcement=enforcement,
        decision_v2=decision_from_legacy_policy_action(action, reason=reason, signals=signal_tuple),
    )
    _validate_authoritative_decision(decision)
    return decision


def authoritative_decision_from_artifact(
    payload: Mapping[str, object],
    *,
    require_authoritative: bool = False,
) -> AuthoritativeGuardDecision:
    """Parse and cross-check a serialized artifact decision.

    Older callers without ``authoritative_decision`` are adapted only when
    every action field they do provide agrees. New payloads receive strict
    schema validation.
    """

    raw_authoritative = payload.get("authoritative_decision")
    if isinstance(raw_authoritative, Mapping):
        decision = AuthoritativeGuardDecision.from_dict(raw_authoritative)
    elif raw_authoritative is not None:
        raise ValueError("authoritative_decision must be an object")
    else:
        if require_authoritative:
            raise ValueError("authoritative_decision is required at the launch boundary")
        action = _parse_guard_action(payload.get("policy_action"))
        raw_composition = payload.get("policy_composition")
        composition = dict(raw_composition) if isinstance(raw_composition, Mapping) else {}
        composition["final_action"] = action
        raw_decision_v2 = payload.get("decision_v2_json")
        reason = raw_decision_v2.get("reason") if isinstance(raw_decision_v2, Mapping) else action
        decision = build_authoritative_decision(
            action,
            reason=reason if isinstance(reason, str) and reason.strip() else action,
            composition_trace=composition,
            authority_finalized=True,
            source="legacy-compatible-projection",
        )

    _validate_artifact_projection(payload, decision)
    return decision


def evaluation_authority_error(
    evaluation: Mapping[str, object],
    *,
    require_launch_permitted: bool = False,
) -> str | None:
    """Return a stable fail-closed code when an evaluation contradicts itself."""

    if evaluation.get("decision_contract_error") is not None:
        return AUTHORITATIVE_DECISION_INCONSISTENT
    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list):
        return AUTHORITATIVE_DECISION_INCONSISTENT
    artifact_decisions: list[AuthoritativeGuardDecision] = []
    decisions: list[AuthoritativeGuardDecision] = []
    try:
        for raw_item in raw_artifacts:
            if not isinstance(raw_item, Mapping):
                raise ValueError("artifact decision must be an object")
            if raw_item.get("decision_contract_error") is not None:
                raise ValueError("artifact decision carries a contract error")
            artifact_decision = authoritative_decision_from_artifact(
                raw_item,
                require_authoritative=require_launch_permitted,
            )
            artifact_decisions.append(artifact_decision)
            decisions.append(artifact_decision)
        raw_run_decision = evaluation.get("run_authoritative_decision")
        if raw_run_decision is not None:
            if not isinstance(raw_run_decision, Mapping):
                raise ValueError("run_authoritative_decision must be an object")
            run_decision = AuthoritativeGuardDecision.from_dict(raw_run_decision)
            _validate_run_decision_projection(evaluation, run_decision)
            decisions.append(run_decision)

        raw_runtime_signals = evaluation.get("runtime_detector_signals_v2")
        runtime_composition = evaluation.get("runtime_detector_composition")
        has_runtime_result = raw_runtime_signals is not None or runtime_composition is not None
        if has_runtime_result:
            if raw_runtime_signals is None or not isinstance(runtime_composition, Mapping):
                raise ValueError("runtime detector signals and composition must be projected together")
            runtime_signals = _parse_signals(raw_runtime_signals)
            recomposed = compose_action_from_signals(runtime_signals, "allow")
            if (
                runtime_composition.get("action") != recomposed.action
                or runtime_composition.get("reason") != recomposed.reason
                or runtime_composition.get("downgraded") is not recomposed.downgraded
                or runtime_composition.get("upgraded") is not recomposed.upgraded
            ):
                raise ValueError("runtime detector composition must derive from its signals")
            for artifact_decision in artifact_decisions:
                if any(signal not in artifact_decision.signals for signal in runtime_signals):
                    raise ValueError("artifact authority must include every runtime detector signal")
            if not artifact_decisions and evaluation.get("run_authoritative_decision") is None:
                raise ValueError("zero-artifact detector results require run authority")

        runtime_action = runtime_composition.get("action") if isinstance(runtime_composition, Mapping) else None
        if has_runtime_result:
            for artifact_decision in artifact_decisions:
                if artifact_decision.composition_trace.get("runtime_detector_action") != runtime_action:
                    raise ValueError("artifact trace must include the runtime detector action")
    except (TypeError, ValueError):
        return AUTHORITATIVE_DECISION_INCONSISTENT
    blocked = evaluation.get("blocked")
    if not isinstance(blocked, bool):
        return AUTHORITATIVE_DECISION_INCONSISTENT
    if blocked != any(decision.enforcement.blocking for decision in decisions):
        return AUTHORITATIVE_DECISION_INCONSISTENT
    if require_launch_permitted and any(not decision.enforcement.launch_permitted for decision in decisions):
        return AUTHORITATIVE_DECISION_INCONSISTENT
    return None


def rebuild_artifact_authority(
    payload: Mapping[str, object],
    *,
    reason: str | None = None,
    composition_updates: Mapping[str, object] | None = None,
    additional_signals: Sequence[RiskSignalV2] = (),
) -> dict[str, object]:
    """Synchronize runner-added trace/reason fields across every projection."""

    # Runner-added evidence may update an existing authority, but it must
    # never mint launch authority from a legacy compatibility projection.
    decision = authoritative_decision_from_artifact(payload, require_authoritative=True)
    composition = dict(decision.composition_trace)
    composition.update(composition_updates or {})
    merged_signals = _merge_signals(decision.signals, additional_signals)
    rebuilt = build_authoritative_decision(
        decision.action,
        reason=reason or decision.reason,
        composition_trace=composition,
        signals=merged_signals,
        authority_finalized=decision.enforcement.authority_finalized,
        source=decision.source,
    )
    return {**dict(payload), **rebuilt.to_artifact_projection()}


def decision_from_legacy_policy_action(
    policy_action: GuardAction,
    *,
    reason: str,
    signals: Sequence[RiskSignalV2] = (),
) -> GuardDecisionV2:
    action, user_title, harness_message, retry_instruction = _ACTION_MESSAGES[policy_action]
    signal_tuple = tuple(signals)
    confidence = _highest_confidence(signal_tuple)
    dashboard_detail = _dashboard_detail_from_signals(signal_tuple, harness_message)
    harness_detail = _harness_message_from_signals(
        signal_tuple,
        harness_message,
        policy_action=policy_action,
    )
    return GuardDecisionV2(
        guard_action=policy_action,
        action=action,
        reason=reason,
        user_title=user_title,
        user_body=dashboard_detail,
        harness_message=harness_detail,
        dashboard_primary_detail=dashboard_detail,
        approval_scopes=_approval_scopes_for_action(policy_action),
        retry_instruction=None if action in {"allow", "warn"} else retry_instruction,
        signals=signal_tuple,
        confidence=confidence,
    )


def _approval_scopes_for_action(action: GuardAction) -> tuple[str, ...]:
    if action not in {"review", "require-reapproval"}:
        return ()
    return ("artifact", "workspace", "publisher", "harness")


def _dashboard_detail_from_signals(signals: tuple[RiskSignalV2, ...], fallback: str) -> str:
    if not signals:
        return fallback
    if _has_data_flow_exfiltration_signal(signals):
        sink_type = _data_flow_sink_type(signals)
        return (
            f"Source-to-sink route: local secret -> {sink_type}. "
            f"This command sends local secret to {sink_type} without exposing the raw secret in Guard evidence."
        )
    strongest = max(signals, key=lambda item: _confidence_rank(item.confidence))
    return strongest.plain_reason


def _harness_message_from_signals(
    signals: tuple[RiskSignalV2, ...],
    fallback: str,
    *,
    policy_action: GuardAction,
) -> str:
    if _has_data_flow_exfiltration_signal(signals):
        sink_type = _data_flow_sink_type(signals)
        match policy_action:
            case "allow":
                return f"HOL Guard allowed this action after noting that it sends local secret to {sink_type}."
            case "warn":
                return f"HOL Guard allowed this action with a warning because it sends local secret to {sink_type}."
            case "sandbox-required":
                return f"HOL Guard requires a sandbox because this action sends local secret to {sink_type}."
            case "block":
                return f"HOL Guard blocked this action because it sends local secret to {sink_type}."
            case "review" | "require-reapproval":
                return f"HOL Guard paused this action because it sends local secret to {sink_type}."
    return fallback


def _data_flow_sink_type(signals: tuple[RiskSignalV2, ...]) -> str:
    signal_ids = {signal.signal_id for signal in signals}
    if any(signal.category == "network" for signal in signals):
        return "network host"
    if "data-flow:clipboard-secret" in signal_ids:
        return "clipboard"
    if "data-flow:world-readable-temp-secret" in signal_ids:
        return "world-readable temp file"
    if "data-flow:git-remote-token" in signal_ids:
        return "git remote configuration"
    return "external sink"


def _has_data_flow_exfiltration_signal(signals: tuple[RiskSignalV2, ...]) -> bool:
    return any(
        signal.detector == "data_flow.exfiltration" or signal.signal_id.startswith("data-flow:") for signal in signals
    )


def _highest_confidence(signals: tuple[RiskSignalV2, ...]) -> RiskConfidenceLabel:
    if not signals:
        return "likely"
    return max((signal.confidence for signal in signals), key=_confidence_rank)


def _confidence_rank(confidence: RiskConfidenceLabel) -> int:
    match confidence:
        case "strong":
            return 3
        case "likely":
            return 2
        case "weak":
            return 1


def _parse_action(value: object) -> GuardDecisionAction:
    match value:
        case "allow":
            return "allow"
        case "warn":
            return "warn"
        case "ask":
            return "ask"
        case "block":
            return "block"
        case _:
            raise ValueError("action must be a known Guard decision action")


def _parse_confidence(value: object) -> RiskConfidenceLabel:
    match value:
        case "weak":
            return "weak"
        case "likely":
            return "likely"
        case "strong":
            return "strong"
        case _:
            raise ValueError("confidence must be a known confidence label")


def _parse_signals(value: object) -> tuple[RiskSignalV2, ...]:
    if not isinstance(value, list):
        raise ValueError("signals must be a list")
    signals: list[RiskSignalV2] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError(f"signal item must be an object, got {type(item).__name__}")
        signals.append(RiskSignalV2.from_dict(item))
    return tuple(signals)


def _parse_string_tuple(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{key} must be a list of non-empty strings")
    return tuple(value)


def _required_string(payload: Mapping[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _optional_string(payload: Mapping[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null")
    return value


def _is_guard_action(value: object) -> TypeGuard[GuardAction]:
    return isinstance(value, str) and value in GUARD_ACTION_VALUES


def _parse_guard_action(value: object) -> GuardAction:
    if not _is_guard_action(value):
        raise ValueError("action must be a known Guard action")
    return value


def _required_bool(payload: Mapping[str, object], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _validate_authoritative_decision(decision: AuthoritativeGuardDecision) -> None:
    _validate_composition_trace(decision.action, decision.composition_trace)
    expected_blocking = decision.action in _BLOCKING_ACTIONS
    expected_launch = not expected_blocking and decision.enforcement.authority_finalized
    expected_prompt = decision.action in {"review", "require-reapproval"}
    expected_sandbox = decision.action == "sandbox-required"
    if decision.enforcement.blocking != expected_blocking:
        raise ValueError("enforcement.blocking must derive from action")
    if decision.enforcement.launch_permitted != expected_launch:
        raise ValueError("enforcement.launch_permitted must derive from action and authority state")
    if decision.enforcement.prompt_required != expected_prompt:
        raise ValueError("enforcement.prompt_required must derive from action")
    if decision.enforcement.sandbox_required != expected_sandbox:
        raise ValueError("enforcement.sandbox_required must derive from action")
    if decision.enforcement.snapshot_permitted != expected_launch:
        raise ValueError("enforcement.snapshot_permitted must derive from action and authority state")
    expected_decision_v2 = decision_from_legacy_policy_action(
        decision.action,
        reason=decision.reason,
        signals=decision.signals,
    )
    if decision.decision_v2 != expected_decision_v2:
        raise ValueError("decision_v2 must derive entirely from action, reason, and signals")


def _validate_composition_trace(action: GuardAction, trace: Mapping[str, object]) -> None:
    """Reject action-bearing trace data that could conceal stronger authority."""

    if trace.get("final_action") != action:
        raise ValueError("composition_trace.final_action must match action")
    _reject_unknown_composition_action_fields(trace)
    parsed: dict[str, GuardAction | None] = {}
    for key in _COMPOSITION_ACTION_FIELDS:
        if key not in trace:
            parsed[key] = None
            continue
        value = trace.get(key)
        if value is None and key in {"configured_action", "saved_action", "scanner_action"}:
            parsed[key] = None
            continue
        if not _is_guard_action(value):
            raise ValueError(f"composition_trace.{key} must be a known Guard action or null")
        parsed[key] = value

    trusted_override = trace.get("trusted_request_override", False)
    if not isinstance(trusted_override, bool):
        raise ValueError("composition_trace.trusted_request_override must be a boolean")
    saved_state_present = trace.get("saved_state_present", False)
    if not isinstance(saved_state_present, bool):
        raise ValueError("composition_trace.saved_state_present must be a boolean")

    runtime_action = parsed["runtime_detector_action"]
    if runtime_action == "block" and action != "block":
        raise ValueError("runtime detector block cannot be overridden")
    current_action = parsed["current_action"]

    for key, candidate in parsed.items():
        if candidate not in _TERMINAL_COMPOSITION_ACTIONS:
            continue
        if guard_action_severity(action) < guard_action_severity(candidate):
            raise ValueError(f"composition_trace.{key} cannot be weakened by the final action")

    for key in ("configured_action", "scanner_action"):
        candidate = parsed[key]
        if (
            current_action is not None
            and candidate is not None
            and guard_action_severity(current_action) < guard_action_severity(candidate)
        ):
            raise ValueError(f"composition_trace.current_action cannot be weaker than {key}")

    saved_allow_override = bool(
        current_action == "review"
        and parsed["saved_action"] == "allow"
        and saved_state_present
        and action in {"allow", "warn"}
    )
    explicit_approval_override = (trusted_override and action in {"allow", "warn"}) or saved_allow_override
    if runtime_action == "warn" and guard_action_severity(action) < guard_action_severity("warn"):
        raise ValueError("runtime detector warning cannot be erased by the final action")
    if (
        runtime_action == "review"
        and guard_action_severity(action) < guard_action_severity("review")
        and not explicit_approval_override
    ):
        raise ValueError("runtime detector review requires an explicit allowed override")

    authority_inputs = tuple(
        candidate for key, candidate in parsed.items() if key != "runtime_detector_action" and candidate is not None
    )
    strongest_input = max(authority_inputs, key=guard_action_severity, default=None)
    if strongest_input is None or guard_action_severity(action) >= guard_action_severity(strongest_input):
        return
    if explicit_approval_override:
        return
    raise ValueError("composition_trace final action weakens authority without an explicit allowed override")


def _reject_unknown_composition_action_fields(trace: Mapping[str, object]) -> None:
    """Reject hidden action aliases at any nesting depth in a composition trace."""

    def visit(value: object, *, path: str, top_level: bool) -> None:
        if isinstance(value, Mapping):
            for raw_key, nested in value.items():
                if not isinstance(raw_key, str):
                    raise ValueError(f"{path} must contain only string keys")
                key_path = f"{path}.{raw_key}"
                known_top_level_action = top_level and raw_key in _KNOWN_COMPOSITION_ACTION_FIELDS
                if is_action_bearing_key(raw_key) and not known_top_level_action:
                    raise ValueError(f"composition_trace contains unknown action-bearing field: {key_path}")
                visit(nested, path=key_path, top_level=False)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for index, nested in enumerate(value):
                visit(nested, path=f"{path}[{index}]", top_level=False)

    visit(trace, path="composition_trace", top_level=True)


def _validate_run_decision_projection(
    evaluation: Mapping[str, object],
    decision: AuthoritativeGuardDecision,
) -> None:
    composition = evaluation.get("runtime_detector_composition")
    if not isinstance(composition, Mapping):
        raise ValueError("run authority requires runtime_detector_composition")
    if composition.get("action") != decision.action or composition.get("reason") != decision.reason:
        raise ValueError("runtime detector composition must match run authority")
    if decision.composition_trace.get("runtime_detector_action") != decision.action:
        raise ValueError("run authority trace must match the runtime detector action")
    raw_signals = evaluation.get("runtime_detector_signals_v2")
    if not isinstance(raw_signals, list):
        raise ValueError("run authority requires runtime detector signals")
    if [signal.to_dict() for signal in decision.signals] != raw_signals:
        raise ValueError("runtime detector signals must match run authority")
    blocked_reason = evaluation.get("blocked_by_detector")
    if decision.enforcement.blocking and blocked_reason != decision.reason:
        raise ValueError("blocked_by_detector must match run authority reason")


def _merge_signals(
    existing: Sequence[RiskSignalV2],
    additional: Sequence[RiskSignalV2],
) -> tuple[RiskSignalV2, ...]:
    merged: list[RiskSignalV2] = []
    seen: set[str] = set()
    for signal in (*existing, *additional):
        if signal.signal_id in seen:
            continue
        seen.add(signal.signal_id)
        merged.append(signal)
    return tuple(merged)


def _validate_artifact_projection(
    payload: Mapping[str, object],
    decision: AuthoritativeGuardDecision,
) -> None:
    _reject_unknown_action_bearing_fields(
        payload,
        allowed=_ARTIFACT_ACTION_FIELDS,
        context="artifact projection",
    )
    policy_action = payload.get("policy_action")
    if policy_action != decision.action:
        raise ValueError("policy_action must match authoritative action")
    verdict_action = payload.get("verdict_action")
    if verdict_action is not None and verdict_action != decision.action:
        raise ValueError("verdict_action must match authoritative action")
    raw_composition = payload.get("policy_composition")
    if raw_composition is not None:
        if not isinstance(raw_composition, Mapping):
            raise ValueError("policy_composition must be an object")
        if raw_composition.get("final_action") != decision.action:
            raise ValueError("policy_composition.final_action must match authoritative action")
        if "authoritative_decision" in payload and dict(raw_composition) != dict(decision.composition_trace):
            raise ValueError("policy_composition must match authoritative composition_trace")
    raw_decision_v2 = payload.get("decision_v2_json")
    if raw_decision_v2 is not None:
        if not isinstance(raw_decision_v2, Mapping):
            raise ValueError("decision_v2_json must be an object")
        if raw_decision_v2.get("action") != decision.decision_v2.action:
            raise ValueError("decision_v2_json.action must match authoritative action")
        if "guard_action" in raw_decision_v2:
            exact_guard_action = _parse_guard_action(raw_decision_v2.get("guard_action"))
            if exact_guard_action != decision.action:
                raise ValueError("decision_v2_json.guard_action must match authoritative action")
        if "authoritative_decision" in payload and dict(raw_decision_v2) != decision.decision_v2.to_dict():
            raise ValueError("decision_v2_json must match authoritative decision_v2")
    raw_action_envelope = payload.get("action_envelope_json")
    if raw_action_envelope is not None:
        if not isinstance(raw_action_envelope, Mapping):
            raise ValueError("action_envelope_json must be an object or null")
        _reject_unknown_action_bearing_fields(
            raw_action_envelope,
            allowed=_ACTION_ENVELOPE_ACTION_FIELDS,
            context="action_envelope_json",
        )
        _require_matching_alias(raw_action_envelope, "action_id", "actionId", "action_envelope_json")
        _require_matching_alias(raw_action_envelope, "action_type", "actionType", "action_envelope_json")
        _require_matching_alias(raw_action_envelope, "policy_action", "policyAction", "action_envelope_json")
        _require_matching_alias(
            raw_action_envelope,
            "pre_execution_result",
            "preExecutionResult",
            "action_envelope_json",
        )
        for key, alias in (("policy_action", "policyAction"), ("pre_execution_result", "preExecutionResult")):
            envelope_action = raw_action_envelope.get(key, raw_action_envelope.get(alias))
            if envelope_action is None:
                continue
            if not _is_guard_action(envelope_action):
                raise ValueError(f"action_envelope_json.{key} must be a known Guard action")
            if envelope_action != decision.action:
                raise ValueError(f"action_envelope_json.{key} must match authoritative action")
    _validate_artifact_approval_projection(payload, decision)


def _reject_unknown_action_bearing_fields(
    payload: Mapping[str, object],
    *,
    allowed: frozenset[str],
    context: str,
) -> None:
    for key in payload:
        if not isinstance(key, str):
            raise ValueError(f"{context} keys must be strings")
        if is_action_bearing_key(key) and key not in allowed:
            raise ValueError(f"{context} contains unknown action-bearing field: {key}")


def _require_matching_alias(
    payload: Mapping[str, object],
    snake_key: str,
    camel_key: str,
    context: str,
) -> None:
    if snake_key in payload and camel_key in payload and payload[snake_key] != payload[camel_key]:
        raise ValueError(f"{context}.{camel_key} must match {snake_key}")


def _require_exact_fields(
    payload: Mapping[str, object],
    expected: frozenset[str],
    context: str,
) -> None:
    actual = frozenset(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(key for key in actual - expected if isinstance(key, str))
        raise ValueError(f"{context} fields must match schema; missing={missing!r}, extra={extra!r}")


def _validate_artifact_approval_projection(
    payload: Mapping[str, object],
    decision: AuthoritativeGuardDecision,
) -> None:
    """Cross-check approval evidence before it can finalize launch authority."""

    trace = decision.composition_trace
    approval_fields_present = bool(
        {"approval_reuse", "approval_reuse_status", "approval_reuse_reason_code", "trusted_request_override"}
        & payload.keys()
    )
    if not approval_fields_present and not {
        "saved_state_present",
        "trusted_request_override",
        "saved_approval_claim",
    }.intersection(trace):
        return

    raw_reuse = payload.get("approval_reuse")
    if not isinstance(raw_reuse, Mapping):
        raise ValueError("approval_reuse must be an object")
    reuse_action = _parse_guard_action(raw_reuse.get("action"))
    current_action = _parse_guard_action(raw_reuse.get("current_action"))
    raw_saved_action = raw_reuse.get("saved_action")
    saved_action = None if raw_saved_action is None else _parse_guard_action(raw_saved_action)
    reuse_status = raw_reuse.get("status")
    if reuse_status not in {"accepted", "rejected", "not-applicable"}:
        raise ValueError("approval_reuse.status must be a known status")
    reuse_reason = _required_string(raw_reuse, "reason_code")
    reuse_should_claim = raw_reuse.get("should_claim")
    if not isinstance(reuse_should_claim, bool):
        raise ValueError("approval_reuse.should_claim must be a boolean")
    if payload.get("approval_reuse_status") != reuse_status:
        raise ValueError("approval_reuse_status must match approval_reuse.status")
    if payload.get("approval_reuse_reason_code") != reuse_reason:
        raise ValueError("approval_reuse_reason_code must match approval_reuse.reason_code")
    if trace.get("current_action") != current_action:
        raise ValueError("composition_trace.current_action must match approval_reuse.current_action")
    if trace.get("saved_action") != saved_action:
        raise ValueError("composition_trace.saved_action must match approval_reuse.saved_action")
    saved_state_present = trace.get("saved_state_present")
    if not isinstance(saved_state_present, bool):
        raise ValueError("composition_trace.saved_state_present must be a boolean")
    if saved_state_present != (saved_action is not None):
        raise ValueError("composition_trace.saved_state_present must match saved approval evidence")

    raw_trusted = payload.get("trusted_request_override")
    if not isinstance(raw_trusted, Mapping):
        raise ValueError("trusted_request_override must be an object")
    trusted_applied = raw_trusted.get("applied")
    if not isinstance(trusted_applied, bool):
        raise ValueError("trusted_request_override.applied must be a boolean")
    trusted_reason = raw_trusted.get("reason_code")
    expected_trusted_reason = _TRUSTED_REQUEST_OVERRIDE_REASON if trusted_applied else None
    if trusted_reason != expected_trusted_reason:
        raise ValueError("trusted_request_override.reason_code must match applied state")
    if trace.get("trusted_request_override") is not trusted_applied:
        raise ValueError("composition_trace.trusted_request_override must match outer evidence")

    saved_allow_reuse = bool(
        current_action == "review"
        and saved_action == "allow"
        and reuse_action == "allow"
        and reuse_status == "accepted"
        and reuse_reason == _APPROVAL_REUSE_ACCEPTED_REASON
        and reuse_should_claim
    )
    saved_block_reuse = bool(
        saved_action == "block"
        and reuse_action == "block"
        and reuse_status == "accepted"
        and reuse_reason == "approval_reuse_saved_block"
        and not reuse_should_claim
    )
    if reuse_status == "accepted" and not (saved_allow_reuse or saved_block_reuse):
        raise ValueError("accepted approval reuse must be an exact saved allow or block")
    if reuse_should_claim and not saved_allow_reuse:
        raise ValueError("approval_reuse.should_claim requires accepted exact saved allow reuse")

    expected_action: GuardAction = "allow" if trusted_applied else reuse_action
    runtime_action = trace.get("runtime_detector_action")
    if runtime_action is not None:
        parsed_runtime_action = _parse_guard_action(runtime_action)
        detector_review_was_approved = parsed_runtime_action == "review" and (trusted_applied or saved_allow_reuse)
        if not detector_review_was_approved:
            expected_action = most_restrictive_guard_action(expected_action, parsed_runtime_action)
    if decision.action != expected_action:
        raise ValueError("authoritative action must derive from approval reuse and runtime authority")

    raw_trace_claim = trace.get("saved_approval_claim")
    raw_outer_claim = payload.get("approval_claim")
    if (raw_trace_claim is None) != (raw_outer_claim is None):
        raise ValueError("saved approval claim must match its authoritative trace")
    claim: Mapping[str, object] | None = None
    if raw_trace_claim is not None:
        if not isinstance(raw_trace_claim, Mapping) or not isinstance(raw_outer_claim, Mapping):
            raise ValueError("saved approval claim must be an object")
        if dict(raw_trace_claim) != dict(raw_outer_claim):
            raise ValueError("saved approval claim must match its authoritative trace")
        claim = raw_trace_claim
        _validate_saved_approval_claim(payload, claim)

    if trusted_applied:
        if claim is not None:
            raise ValueError("trusted request and saved approval claim cannot both finalize authority")
        if reuse_action not in {"review", "require-reapproval"}:
            raise ValueError("trusted request override must satisfy a review action")
        if not decision.enforcement.authority_finalized:
            raise ValueError("trusted request override must finalize authority")
        if decision.action == "allow" and decision.reason != _TRUSTED_REQUEST_OVERRIDE_REASON:
            raise ValueError("trusted request allow reason must match its evidence")
        _require_scanner_evidence(
            payload,
            source="trusted_request_override",
            status="accepted",
            reason_code=_TRUSTED_REQUEST_OVERRIDE_REASON,
            artifact_hash=payload.get("approval_context_hash"),
        )

    if claim is not None:
        if not decision.enforcement.authority_finalized:
            raise ValueError("saved approval claim must finalize authority")
        if not saved_allow_reuse:
            raise ValueError("saved approval claim must match accepted exact allow reuse")
        _require_scanner_evidence(
            payload,
            source="approval_reuse",
            status="accepted",
            reason_code=_APPROVAL_REUSE_ACCEPTED_REASON,
        )
    elif reuse_should_claim and decision.enforcement.authority_finalized and not trusted_applied:
        raise ValueError("finalized saved approval reuse requires an atomic claim proof")


def _validate_saved_approval_claim(
    payload: Mapping[str, object],
    claim: Mapping[str, object],
) -> None:
    expected_keys = {"status", "approval_context_hash", "reason_code"}
    if set(claim) != expected_keys:
        raise ValueError("saved approval claim has an invalid schema")
    if claim.get("status") not in _SAVED_APPROVAL_CLAIM_DISPOSITIONS:
        raise ValueError("saved approval claim status must be consumed or retained")
    context_hash = payload.get("approval_context_hash")
    if not isinstance(context_hash, str) or not context_hash or claim.get("approval_context_hash") != context_hash:
        raise ValueError("saved approval claim must match approval_context_hash")
    if claim.get("reason_code") != _APPROVAL_REUSE_ACCEPTED_REASON:
        raise ValueError("saved approval claim must carry the accepted reuse reason")


def _require_scanner_evidence(
    payload: Mapping[str, object],
    *,
    source: str,
    status: str,
    reason_code: str,
    artifact_hash: object | None = None,
) -> None:
    raw_evidence = payload.get("scanner_evidence")
    if not isinstance(raw_evidence, list):
        raise ValueError("scanner_evidence must be a list")
    for entry in raw_evidence:
        if not isinstance(entry, Mapping):
            continue
        if (
            entry.get("source") == source
            and entry.get("status") == status
            and entry.get("reason_code") == reason_code
            and (artifact_hash is None or entry.get("artifact_hash") == artifact_hash)
        ):
            return
    raise ValueError(f"scanner_evidence must contain matching {source} evidence")
