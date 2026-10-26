"""The retired Python final-action settle, frozen as a parity oracle.

``_recorded_settle`` and ``recorded_browser_outcome`` below are the Python code
the artifact hook ran at 3b8ac2e848 (``set_native_artifact_hook_final_action``
in ``commands_hook_native_state.py`` and the browser-outcome section of
``finalize_native_artifact_hook`` in ``commands_hook_native_finish.py``), kept
here so the oracle never calls the code it checks. The two collaborators that
only render (``build_decision_v2`` and ``build_incident_context``) are stubs
that echo their arguments, so a vector records which arguments the settle
chose. ``record_artifact_finalize_vectors.py`` enumerates the cases and writes
the vectors.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any

from codex_plugin_scanner.guard.action_lattice import normalize_guard_action

RISK0 = "RISK0"
TERMINAL0 = "TERMINAL0"
CLOUD_CODE_SET = {"cloud_auth_error", "cloud_http_error", "cloud_timeout", "cloud_validation_error"}


@dataclass(frozen=True)
class Receipt:
    """The receipt fields the settle reads and writes."""

    policy_decision: str
    approval_source: str | None
    approval_request_id: str | None
    user_override: str | None
    scanner_evidence: tuple[dict[str, object], ...]
    harness: str = "codex"


@dataclass(frozen=True)
class Envelope:
    """Stands in for the action envelope: remembers the result it was given."""

    result: str | None = None

    def with_pre_execution_result(self, action: str) -> Envelope:
        return Envelope(action)


def stub_decision_v2(action: str, *, reason: str, signals: object) -> SimpleNamespace:
    """Echo the arguments the settle chose; the real builder only renders them."""

    assert signals == ("signal",)
    payload = {
        "action": action,
        "reason": reason,
        "dashboard_primary_detail": f"detail:{action}:{reason}",
        "user_title": f"title:{action}:{reason}",
        "user_body": f"body:{action}:{reason}",
        "retry_instruction": "" if action == "block" else f"retry:{action}:{reason}",
        "harness_message": f"message:{action}:{reason}",
    }
    return SimpleNamespace(to_dict=lambda: payload)


def stub_incident_context(**kwargs: Any) -> dict[str, str]:
    """Echo the arguments the settle passed to the incident builder."""

    action, risk = kwargs["policy_action"], kwargs["risk_summary"]
    assert kwargs["harness"] == "codex" and kwargs["launch_target"] is None
    return {
        "trigger_summary": f"trigger:{action}:{risk}",
        "why_now": f"why:{action}:{risk}",
        "risk_headline": f"headline:{action}:{risk}",
    }


@dataclass(frozen=True)
class SettleCase:
    """One enumerated fact combination for the final-action settle."""

    previous_action: str
    policy_action: str
    observed_policy_action: str | None = None
    approval_source: str | None = None
    approval_request_id: str | None = None
    queued_request_id: str | None = None
    initial_policy_action: str = "review"
    receipt_approval_source: str | None = None
    receipt_approval_request_id: str | None = None
    receipt_user_override: str | None = None
    package_review_cloud_reason_code: str | None = None
    supply_chain_present: bool = False
    supply_chain_action: str | None = None

    def facts(self) -> dict[str, object]:
        return {
            "previous_action": self.previous_action,
            "policy_action": self.policy_action,
            "observed_policy_action": self.observed_policy_action,
            "approval_source": self.approval_source,
            "approval_request_id": self.approval_request_id,
            "queued_request_id": self.queued_request_id,
            "initial_policy_action": self.initial_policy_action,
            "receipt_approval_source": self.receipt_approval_source,
            "receipt_approval_request_id": self.receipt_approval_request_id,
            "receipt_user_override": self.receipt_user_override,
            "package_review_cloud_reason_code": self.package_review_cloud_reason_code,
            "supply_chain_present": self.supply_chain_present,
            "supply_chain_action": self.supply_chain_action,
        }

    def state(self) -> SimpleNamespace:
        """The hook state the facts describe, before the settle."""

        response: dict[str, object] = {
            "policy_action": self.previous_action,
            "resolved_policy_action": "stale",
            "terminal_action": TERMINAL0,
            "risk_summary": RISK0,
            "policy_composition": {"current_composed_action": "review", "authoritative_action": "stale"},
            "decision_v2_json": {"stale": True},
        }
        if self.supply_chain_present:
            response["supply_chain_evaluation"] = {
                "policy_action": self.supply_chain_action,
                "decision": "allow",
                "risk_summary": "package risk",
                "user_copy": {"title": "t0", "kept": "kept"},
            }
        evidence = _evidence()
        decision_v2: dict[str, object] = {"action": self.previous_action}
        if self.package_review_cloud_reason_code is not None:
            decision_v2["package_review_cloud_reason_code"] = self.package_review_cloud_reason_code
        return SimpleNamespace(
            action_envelope=Envelope(),
            artifact_id="artifact",
            artifact_name="name",
            changed_capabilities=["cap"],
            decision_signals=("signal",),
            decision_v2_payload=decision_v2,
            guard_home=None,
            initial_policy_action=self.initial_policy_action,
            policy_action=self.previous_action,
            receipt=Receipt(
                policy_decision="stale",
                approval_source=self.receipt_approval_source,
                approval_request_id=self.receipt_approval_request_id,
                user_override=self.receipt_user_override,
                scanner_evidence=tuple(copy.deepcopy(evidence)),
            ),
            response_payload=response,
            risk_summary=RISK0,
            runtime_artifact=SimpleNamespace(artifact_type="tool_action_request", source_scope="s", config_path="c"),
            scanner_evidence_payload=evidence,
        )


def _evidence() -> list[dict[str, object]]:
    """Evidence entries: one that already carries the key, a bare probe, others."""

    return [
        {"source": "policy_composition", "authoritative_action": "stale", "note": "kept"},
        {"source": "policy_composition"},
        {"source": "scanner", "authoritative_action": "untouched"},
    ]


def _recorded_settle(
    state: SimpleNamespace,
    policy_action: str,
    *,
    approval_request_id: str | None = None,
    approval_source: str | None = None,
    observed_policy_action: str | None = None,
) -> None:
    """``set_native_artifact_hook_final_action`` as it stood at 3b8ac2e848."""

    previous_action = normalize_guard_action(state.policy_action, unknown_action="block")
    normalized_action = normalize_guard_action(policy_action, unknown_action="block")
    state.policy_action = normalized_action
    state.response_payload["policy_action"] = normalized_action
    state.response_payload["resolved_policy_action"] = normalized_action
    normalized_observed_action = (
        normalize_guard_action(observed_policy_action, unknown_action="block")
        if observed_policy_action is not None
        else None
    )
    if normalized_observed_action is not None:
        state.response_payload["observed_policy_action"] = normalized_observed_action
        state.response_payload.pop("terminal_action", None)
    if state.action_envelope is not None:
        state.action_envelope = state.action_envelope.with_pre_execution_result(normalized_action)

    decision_v2_payload = stub_decision_v2(
        normalized_action,
        reason=("browser-approval" if approval_source == "browser" else normalized_action),
        signals=state.decision_signals,
    ).to_dict()
    package_review_cloud_reason_code = state.decision_v2_payload.get("package_review_cloud_reason_code")
    if package_review_cloud_reason_code in {
        "cloud_auth_error",
        "cloud_http_error",
        "cloud_timeout",
        "cloud_validation_error",
    }:
        decision_v2_payload["package_review_cloud_reason_code"] = package_review_cloud_reason_code
    state.decision_v2_payload = decision_v2_payload
    state.response_payload["decision_v2_json"] = decision_v2_payload

    if previous_action != normalized_action:
        final_risk_summary = str(decision_v2_payload["dashboard_primary_detail"])
        state.risk_summary = final_risk_summary
        state.response_payload["risk_summary"] = final_risk_summary
        raw_supply_chain = state.response_payload.get("supply_chain_evaluation")
        if isinstance(raw_supply_chain, dict):
            observed_supply_chain = dict(raw_supply_chain)
            raw_user_copy = raw_supply_chain.get("user_copy")
            user_copy = dict(raw_user_copy) if isinstance(raw_user_copy, dict) else {}
            if normalized_observed_action is not None:
                raw_package_action = observed_supply_chain.get(
                    "policy_action",
                    observed_supply_chain.get("decision"),
                )
                observed_package_action = (
                    normalize_guard_action(raw_package_action, unknown_action="block")
                    if isinstance(raw_package_action, str)
                    else normalized_observed_action
                )
                raw_supply_chain["observed_policy_action"] = observed_package_action
                raw_supply_chain["observed_risk_summary"] = observed_supply_chain.get("risk_summary")
                raw_supply_chain["observed_user_copy"] = observed_supply_chain.get("user_copy")
            user_copy.update(
                {
                    "title": decision_v2_payload["user_title"],
                    "summary": decision_v2_payload["user_body"],
                    "next_step": decision_v2_payload["retry_instruction"] or decision_v2_payload["user_body"],
                    "harness_message": decision_v2_payload["harness_message"],
                }
            )
            raw_supply_chain.update(
                {
                    "decision": decision_v2_payload["action"],
                    "policy_action": normalized_action,
                    "risk_summary": final_risk_summary,
                    "user_copy": user_copy,
                }
            )

    incident = stub_incident_context(
        harness=state.receipt.harness,
        artifact=state.runtime_artifact,
        artifact_id=state.artifact_id,
        artifact_name=state.artifact_name,
        artifact_type=state.runtime_artifact.artifact_type,
        source_scope=state.runtime_artifact.source_scope,
        config_path=state.runtime_artifact.config_path,
        changed_fields=state.changed_capabilities,
        policy_action=normalized_action,
        launch_target=None,
        risk_summary=state.risk_summary,
        guard_home=state.guard_home,
    )
    for key in ("trigger_summary", "why_now", "risk_headline"):
        state.response_payload[key] = incident[key]

    policy_composition = state.response_payload.get("policy_composition")
    if isinstance(policy_composition, dict):
        policy_composition["authoritative_action"] = normalized_action
        if normalized_observed_action is not None:
            policy_composition["observed_policy_action"] = normalized_observed_action
    for evidence in state.scanner_evidence_payload:
        if evidence.get("source") == "policy_composition":
            evidence["authoritative_action"] = normalized_action
            if normalized_observed_action is not None:
                evidence["observed_policy_action"] = normalized_observed_action

    receipt_evidence = tuple(
        {
            **evidence,
            "authoritative_action": normalized_action,
            **(
                {"observed_policy_action": normalized_observed_action} if normalized_observed_action is not None else {}
            ),
        }
        if evidence.get("source") == "policy_composition"
        else evidence
        for evidence in state.receipt.scanner_evidence
    )
    if approval_source == "browser":
        receipt_evidence = (
            *receipt_evidence,
            {
                "source": "browser_approval_resolution",
                "initial_action": state.initial_policy_action,
                "authoritative_action": normalized_action,
                "approval_request_id": approval_request_id,
            },
        )
    state.receipt = replace(
        state.receipt,
        policy_decision=normalized_action,
        approval_source=approval_source or state.receipt.approval_source,
        approval_request_id=approval_request_id or state.receipt.approval_request_id,
        user_override=("browser-approval" if approval_source == "browser" else state.receipt.user_override),
        scanner_evidence=receipt_evidence,
    )


def recorded_settle_call(case: SettleCase) -> SimpleNamespace:
    """The call each path made.

    The browser paths resolved the request id first, in
    ``finalize_native_artifact_hook``: the allow path passed the resolution's
    request id only, a terminal outcome fell back to the first queued request
    when the resolution named none, and an id that is not text became ``None``.
    The other paths passed no source and no request id.
    """

    state = case.state()
    request_id = case.approval_request_id
    if case.approval_source == "browser":
        assert case.policy_action in {"allow", "block", "sandbox-required"}, "the browser decides one of three"
        if case.policy_action != "allow" and request_id is None:
            request_id = case.queued_request_id
    _recorded_settle(
        state,
        case.policy_action,
        approval_request_id=request_id,
        approval_source=case.approval_source,
        observed_policy_action=case.observed_policy_action,
    )
    return state


def _evidence_text(entries: object) -> str:
    """The exact persisted text: key order is observable, so nothing is sorted."""

    return json.dumps(list(entries), separators=(",", ":"))  # type: ignore[call-overload]


def outcome_of(state: SimpleNamespace) -> dict[str, Any]:
    """Everything the settle leaves observable on the state."""

    return {
        "policy_action": state.policy_action,
        "envelope": state.action_envelope.result,
        "response_payload": state.response_payload,
        "decision_v2_payload": state.decision_v2_payload,
        "risk_summary": state.risk_summary,
        "scanner_evidence_text": _evidence_text(state.scanner_evidence_payload),
        "receipt": receipt_pins(state.receipt),
    }


def receipt_pins(receipt: Receipt) -> dict[str, Any]:
    """The persisted receipt fields, with the evidence as exact text."""

    return {
        "policy_decision": receipt.policy_decision,
        "approval_source": receipt.approval_source,
        "approval_request_id": receipt.approval_request_id,
        "user_override": receipt.user_override,
        "scanner_evidence": _evidence_text(receipt.scanner_evidence),
    }


def recorded_browser_outcome(decision: str, event_name: str) -> list[list[object]]:
    """The browser-outcome section of ``finalize_native_artifact_hook`` at 3b8ac2e848.

    Every effect is a trace entry; ``render`` is where the section handed the
    settled verdict to the directive.
    """

    trace: list[list[object]] = []
    if decision == "allow":
        trace.append(["adopt"])
        trace.append(["settle", "allow", "browser"])
        if event_name != "PreToolUse":
            trace.append(["native_allow", event_name, ""])
        trace.append(["receipt"])
        trace.append(["usage", "allow"])
        trace.append(["return", 0])
        return trace
    if decision in {"block", "sandbox-required"}:
        trace.append(["adopt"])
        trace.append(["settle", decision, "browser"])
    trace.append(["render"])
    return trace
