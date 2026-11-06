"""Bound resident transport for decision construction and validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class NativeDecisionAuthorityError(ValueError):
    """The native owner returned an incomplete decision projection."""


class NativeDecisionUnavailableError(RuntimeError):
    """Decision transport failed independently of stored-data validity."""


_ARTIFACT_FIELDS = frozenset(
    {
        "artifact_id",
        "artifact_type",
        "inventory_only",
        "approval_context_hash",
        "policy_action",
        "verdict_action",
        "policy_composition",
        "decision_v2_json",
        "action_envelope_json",
        "authoritative_decision",
        "approval_reuse",
        "approval_reuse_status",
        "approval_reuse_reason_code",
        "trusted_request_override",
        "approval_claim",
        "scanner_evidence",
        "decision_contract_error",
        "user_override",
    }
)


def _invalid() -> NativeDecisionAuthorityError:
    return NativeDecisionAuthorityError("native_decision_authority_result_invalid")


def _request(kind: str, args: Mapping[str, object]) -> dict[str, Any]:
    from .native_runner_authority import (
        NativeRunnerAuthorityError,
        NativeRunnerAuthorityRefusalError,
        native_runner_authority,
    )

    try:
        return native_runner_authority(kind, args)
    except NativeRunnerAuthorityRefusalError as error:
        raise NativeDecisionAuthorityError(str(error)) from error
    except NativeRunnerAuthorityError as error:
        raise NativeDecisionUnavailableError(str(error)) from error


def _fields(payload: object, fields: Mapping[str, type], nullable: tuple[str, ...] = ()) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != set(fields):
        raise _invalid()
    for key, kind in fields.items():
        value = payload[key]
        if value is None and key in nullable:
            continue
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            raise _invalid()
    return payload


def _shape(payload: dict[str, Any], kind: str) -> None:
    if kind == "enforcement":
        _fields(
            payload,
            dict.fromkeys(
                (
                    "blocking",
                    "authority_finalized",
                    "launch_permitted",
                    "prompt_required",
                    "sandbox_required",
                    "snapshot_permitted",
                ),
                bool,
            ),
        )
        return
    if kind == "authoritative":
        _fields(
            payload,
            {
                "schema_version": int,
                "action": str,
                "source": str,
                "reason": str,
                "composition_trace": dict,
                "signals": list,
                "enforcement": dict,
                "decision_v2": dict,
            },
        )
        _shape(payload["enforcement"], "enforcement")
        _shape(payload["decision_v2"], "v2")
    else:
        fields: dict[str, type] = dict.fromkeys(
            (
                "guard_action",
                "action",
                "reason",
                "user_title",
                "user_body",
                "harness_message",
                "dashboard_primary_detail",
                "retry_instruction",
                "confidence",
            ),
            str,
        )
        fields.update({"approval_scopes": list, "signals": list})
        if "package_review_cloud_reason_code" in payload:
            fields["package_review_cloud_reason_code"] = str
        _fields(payload, fields, ("retry_instruction", "package_review_cloud_reason_code"))
        if any(not isinstance(scope, str) for scope in payload["approval_scopes"]):
            raise _invalid()
    signal_fields: dict[str, type] = dict.fromkeys(
        (
            "signal_id",
            "category",
            "severity",
            "confidence",
            "detector",
            "title",
            "plain_reason",
            "technical_detail",
            "evidence_ref",
            "redaction_level",
            "false_positive_hint",
            "advisory_id",
        ),
        str,
    )
    for signal in payload["signals"]:
        _fields(signal, signal_fields, ("technical_detail", "evidence_ref", "false_positive_hint", "advisory_id"))


def artifact_transport_fields(payload: Mapping[str, object]) -> dict[str, object]:
    """Retain action-bearing keys and the native owner's readable values."""
    return {key: value if key in _ARTIFACT_FIELDS else None for key, value in payload.items()}


def decision_authority(kind: str, args: Mapping[str, object]) -> dict[str, Any]:
    payload = args.get("payload")
    if kind == "decision_artifact_decode" and isinstance(payload, Mapping):
        # Preserve every key for native hidden-action detection, while removing
        # values the owner never reads (including raw scanner content).
        args = {**args, "payload": artifact_transport_fields(payload)}
    result = _request(kind, args)
    if result.get("status") == "error":
        message = result.get("message")
        error_type = result.get("error_type")
        if not isinstance(message, str) or error_type != "ValueError":
            raise _invalid()
        raise ValueError(message)
    value = result.get("value")
    if result.get("status") != "ok" or not isinstance(value, dict):
        raise _invalid()
    if kind == "decision_enforcement_decode":
        shape = "enforcement"
    elif kind in {"decision_v2_decode", "decision_legacy"}:
        shape = "v2"
    else:
        shape = "authoritative"
    _shape(value, shape)
    return value
