"""Prove and redact the native Cloud Review origin for a queued pause."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path

from ..native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from ..runtime.actions import normalize_harness_payload
from ..runtime.native_cloud_review_origin import (
    eligible_native_origin_receipt,
    validated_native_approval_origin,
)
from ..runtime.native_cloud_review_v4 import NativeCloudReviewV4Error, get_native_approval_origin

_NATIVE_DIGEST = re.compile(r"[0-9a-f]{64}")


def _native_cloud_review_origin(
    *,
    guard_home: Path,
    harness: str,
    native_result: Mapping[str, object],
    native_receipt: object,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    receipt = eligible_native_origin_receipt(native_receipt, harness=harness)
    if (
        receipt is None
        or native_result.get("agent_visible_immutable_block") is True
        or not receipt_matches_edge(
            {
                "harness": harness,
                "event_name": "PreToolUse",
                "payload_kind": receipt["payload_kind"],
                "result": native_result,
            },
            receipt,
        )
    ):
        return None, _native_origin_unavailable(native_receipt, reason_code="native_cloud_review_origin_ineligible")
    try:
        origin = get_native_approval_origin(guard_home, str(receipt["request_id"]))
    except NativeCloudReviewV4Error as error:
        if error.code == "native_cloud_review_v4_capability_unavailable":
            # A genuinely older native core may still prove its legacy Root
            # origin. No copied receipt or SDK snapshot establishes that proof.
            return None, None
        return None, _native_origin_unavailable(receipt, reason_code=error.code)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None, _native_origin_unavailable(receipt, reason_code="native_cloud_review_origin_unavailable")
    validated = validated_native_approval_origin(origin, native_receipt=receipt, harness=harness)
    if validated is None:
        return None, _native_origin_unavailable(receipt, reason_code="native_cloud_review_v4_origin_invalid")
    return validated, None


def _native_origin_unavailable(native_receipt: object, *, reason_code: str) -> dict[str, object]:
    receipt = validate_native_decision_receipt(native_receipt)
    code = (
        reason_code
        if re.fullmatch(r"[a-z0-9_]{1,128}", reason_code) is not None
        else "native_cloud_review_origin_unavailable"
    )
    return {
        "schema": "guard-native-cloud-review-origin-unavailable.v4",
        "version": 4,
        "request_id": receipt["request_id"] if receipt is not None else None,
        "reason_code": code,
        "executable": False,
    }


def _native_review_action_envelope(
    *,
    harness: str,
    payload: Mapping[str, object],
    native_receipt: Mapping[str, object] | None = None,
    workspace: Path | None,
    guard_home: Path | None = None,
    home_dir: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Store the canonical redacted envelope used by live revalidation."""

    try:
        envelope = (
            normalize_harness_payload(
                harness,
                "PreToolUse",
                dict(payload),
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
                deadline=deadline,
            )
            .with_pre_execution_result("review")
            .to_dict()
        )
    except ValueError:
        return None
    validated = validate_native_decision_receipt(native_receipt)
    if validated is not None:
        intent = validated.get("execution_intent_digest")
        if isinstance(intent, str) and _NATIVE_DIGEST.fullmatch(intent) is not None:
            envelope["execution_intent_digest"] = intent
    if validated is None or "origin_authentication" not in validated:
        return envelope
    # Keep only the validated aggregate receipt. Never carry raw hook input
    # through the presentation envelope, and do not alias nested mappings.
    envelope["native_origin_receipt"] = deepcopy(validated)
    return envelope
