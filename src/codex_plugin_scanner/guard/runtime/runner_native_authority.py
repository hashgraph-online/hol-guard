"""Typed projections between ``guard run`` and the native runner-authority owner.

Every function here ships a minimal typed projection of runner state to
``native_runner_authority`` and returns the owner's answer unchanged. Nothing
here composes an action, reason, signature or override: the Rust resident owns
that, and any transport or shape failure raises ``NativeRunnerAuthorityError``
so ``guard run`` refuses to launch.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, cast

from ..config import GuardConfig
from ..models import GuardAction, HarnessDetection, PolicyDecision
from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

_DETECTOR_KEYS = (
    "runtime_detector_composition",
    "runtime_detector_signals_v2",
    "runtime_detector_telemetry",
)
_DETECTOR_RESULT_KEYS = (*_DETECTOR_KEYS, "runtime_detector_trace_error", "blocked_by_detector")
_SAVED_DECISION_KEYS = (
    "approval_id",
    "artifact_id",
    "decision_id",
    "source",
    "fresh_local_approval",
    "durable_exact_approval",
)
_SHADOW_KEYS = ("harness", "scope", "artifact_id", "artifact_hash", "workspace", "publisher", "action", "expires_at")


@dataclass(frozen=True, slots=True)
class DetectorAuthority:
    """The owner's reading of one runtime-detector evaluation."""

    action: GuardAction | None
    reason: str | None
    context: dict[str, Any] | None
    nonterminal_evidence: dict[str, Any] | None
    blocked_by_detector: str | None


def _malformed() -> NativeRunnerAuthorityError:
    return NativeRunnerAuthorityError("native_runner_authority_result_invalid")


def _typed(payload: Mapping[str, Any], key: str, kind: type | tuple[type, ...], *, nullable: bool = False) -> Any:
    value = payload.get(key)
    if value is None and nullable and key in payload:
        return None
    if not isinstance(value, kind):
        raise _malformed()
    return value


def _subset(source: Mapping[str, object], keys: Iterable[str]) -> dict[str, object]:
    return {key: source[key] for key in keys if key in source}


def _artifact_list(evaluation: Mapping[str, object]) -> list[object] | None:
    raw = evaluation.get("artifacts")
    return list(raw) if isinstance(raw, list) else None


def detector_authority(evaluation: Mapping[str, object]) -> DetectorAuthority:
    payload = native_runner_authority(
        "detector_authority",
        {"evaluation": _subset(evaluation, (*_DETECTOR_KEYS, "blocked_by_detector"))},
    )
    return DetectorAuthority(
        action=cast("GuardAction | None", _typed(payload, "action", str, nullable=True)),
        reason=_typed(payload, "reason", str, nullable=True),
        context=_typed(payload, "context", dict, nullable=True),
        nonterminal_evidence=_typed(payload, "nonterminal_evidence", dict, nullable=True),
        blocked_by_detector=_typed(payload, "blocked_by_detector", str, nullable=True),
    )


def detector_composition(signals: Sequence[Mapping[str, object]]) -> tuple[dict[str, Any], bool]:
    """Compose detector signals; returns ``(composition, blocks)``."""

    payload = native_runner_authority("detector_composition", {"signals": [dict(signal) for signal in signals]})
    return _typed(payload, "composition", dict), _typed(payload, "blocks", bool)


def config_with_current_authority(
    config: GuardConfig,
    evaluation: Mapping[str, object],
    authority_action: GuardAction,
    *,
    artifact_ids: set[str] | None = None,
) -> GuardConfig:
    """Bind runner-only authority into each artifact's current policy context."""

    artifacts = [
        {
            "artifact_id": item.get("artifact_id"),
            "policy_action": item.get("policy_action"),
            "policy_composition": {"current_action": composition.get("current_action")}
            if isinstance(composition := item.get("policy_composition"), Mapping)
            else None,
        }
        for item in _artifact_list(evaluation) or []
        if isinstance(item, Mapping)
    ]
    payload = native_runner_authority(
        "current_authority_actions",
        {
            "artifacts": artifacts,
            "artifact_actions": dict(config.artifact_actions or {}),
            "authority_action": authority_action,
            "artifact_ids": sorted(artifact_ids) if artifact_ids is not None else None,
        },
    )
    actions = _typed(payload, "artifact_actions", dict, nullable=True)
    return config if actions is None else replace(config, artifact_actions=actions)


def exact_request_overrides(evaluation: Mapping[str, object]) -> dict[str, str]:
    """Trusted allow results bound to the exact queued context token."""

    payload = native_runner_authority(
        "request_overrides",
        {"mode": "exact", "approval_wait": evaluation.get("approval_wait"), "artifacts": None},
    )
    return _typed(payload, "overrides", dict)


def interactive_request_overrides(evaluation: Mapping[str, object]) -> tuple[dict[str, str], dict[str, str]]:
    """Exact allow intents returned by the trusted terminal resolver."""

    payload = native_runner_authority(
        "request_overrides",
        {"mode": "interactive", "approval_wait": None, "artifacts": _artifact_list(evaluation)},
    )
    return _typed(payload, "overrides", dict), _typed(payload, "labels", dict)


def claim_partition(
    pending: Sequence[tuple[Mapping[str, object], str, str]],
) -> tuple[dict[str, str], dict[str, str], dict[str, dict[str, bool]]]:
    """Split saved claims into consumed/retained overrides plus qualifications."""

    if not pending:
        return {}, {}, {}
    payload = native_runner_authority(
        "claim_partition",
        {
            "pending": [
                {
                    "decision": {
                        **_subset(decision, _SAVED_DECISION_KEYS),
                        "expires_at": None if decision.get("expires_at") is None else True,
                    },
                    "artifact_id": artifact_id,
                    "artifact_hash": artifact_hash,
                }
                for decision, artifact_id, artifact_hash in pending
            ]
        },
    )
    return _typed(payload, "consumed", dict), _typed(payload, "retained", dict), _typed(payload, "qualifications", dict)


def with_recorded_detector_result(
    evaluation: Mapping[str, Any],
    detector_evaluation: Mapping[str, object],
) -> dict[str, Any]:
    """Carry one pre-launch detector result across persistence without rerunning it."""

    payload = native_runner_authority(
        "apply_detector_result",
        {
            "artifacts": evaluation.get("artifacts"),
            "blocked": evaluation.get("blocked"),
            "detector": _subset(detector_evaluation, _DETECTOR_RESULT_KEYS),
        },
    )
    return {**evaluation, **_typed(payload, "set", dict)}


def with_preclaim_failure(
    evaluation: Mapping[str, Any],
    *,
    affected_artifact_ids: set[str],
    reason_code: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Terminal failure before claiming; returns ``(evaluation, receipt_evidence)``."""

    payload = native_runner_authority(
        "preclaim_failure",
        {
            "artifacts": evaluation.get("artifacts", []),
            "affected_artifact_ids": sorted(affected_artifact_ids),
            "reason_code": reason_code,
        },
    )
    return {**evaluation, **_typed(payload, "set", dict)}, _typed(payload, "receipt_evidence", dict)


def with_claim_context_failure(
    evaluation: Mapping[str, Any],
    *,
    claimed_artifact_ids: set[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Changed post-claim authority; returns ``(evaluation, receipt_evidence)``."""

    payload = native_runner_authority(
        "claim_context_failure",
        {"artifacts": evaluation.get("artifacts", []), "claimed_artifact_ids": sorted(claimed_artifact_ids)},
    )
    return {**evaluation, **_typed(payload, "set", dict)}, _typed(payload, "receipt_evidence", dict)


def _jsonable(value: object) -> Any:
    return json.loads(json.dumps(value, default=str))


def authority_signature(
    detection: HarnessDetection,
    evaluation: Mapping[str, object],
    launch_previews: Sequence[Any],
) -> dict[str, Any] | None:
    """Exact launch authority checked on both sides of a claim; ``None`` if unbound."""

    artifacts = _artifact_list(evaluation)
    payload = native_runner_authority(
        "authority_signature",
        {
            "harness": detection.harness,
            "installed": detection.installed,
            "command_available": detection.command_available,
            "config_paths": list(detection.config_paths),
            "artifacts": None
            if artifacts is None
            else [
                _subset(item, ("artifact_id", "approval_context_hash", "policy_action"))
                if isinstance(item, Mapping)
                else item
                for item in artifacts
            ],
            "detector": _subset(evaluation, _DETECTOR_KEYS),
            "launch_previews": [
                {
                    "adapter_command": list(plan.adapter_command),
                    "environment_sha256": plan.environment_sha256,
                    "identity": _jsonable(dict(plan.identity)),
                    "reusable": plan.reusable,
                }
                for plan in launch_previews
            ],
        },
    )
    return _typed(payload, "signature", dict, nullable=True)


def authority_error(evaluation: Mapping[str, object], *, require_launch_permitted: bool) -> str | None:
    """The final fail-closed contradiction check run before any launch."""

    gate_keys = (
        "decision_contract_error",
        "artifacts",
        "run_authoritative_decision",
        "runtime_detector_signals_v2",
        "runtime_detector_composition",
        "blocked_by_detector",
        "blocked",
    )
    payload = native_runner_authority(
        "authority_gate",
        {"evaluation": _subset(evaluation, gate_keys), "require_launch_permitted": require_launch_permitted},
    )
    return _typed(payload, "authority_error", str, nullable=True)


def policy_shadow_mismatch(legacy: Sequence[PolicyDecision], canonical: Sequence[PolicyDecision]) -> tuple[str, ...]:
    """Reason codes where the legacy and canonical policy rows disagree."""

    def rows(decisions: Sequence[PolicyDecision]) -> list[dict[str, object]]:
        return [{key: getattr(decision, key) for key in _SHADOW_KEYS} for decision in decisions]

    payload = native_runner_authority("policy_shadow_mismatch", {"legacy": rows(legacy), "canonical": rows(canonical)})
    return tuple(_typed(payload, "reason_codes", list))


def receipt_evidence_updates(
    rows: Sequence[Mapping[str, object]],
    *,
    artifact_ids: Iterable[str],
    evidence: Mapping[str, object],
    approval_source: str,
    source_actions: Iterable[str],
    replace_existing_source: bool,
) -> list[dict[str, Any]]:
    """Per-row ``scanner_evidence``/``approval_source`` updates for receipts."""

    payload = native_runner_authority(
        "receipt_evidence_merge",
        {
            "rows": [
                {
                    "rowid": row["rowid"],
                    "artifact_id": str(row["artifact_id"]),
                    "policy_decision": str(row["policy_decision"]),
                    "scanner_evidence_json": str(row["scanner_evidence_json"]),
                    "approval_source": row["approval_source"],
                }
                for row in rows
            ],
            "artifact_ids": sorted(artifact_ids),
            "evidence": dict(evidence),
            "approval_source": approval_source,
            "source_actions": sorted(source_actions),
            "replace_existing_source": replace_existing_source,
        },
    )
    return _typed(payload, "updates", list)
