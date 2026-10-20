"""Canonical redacted action presentation shared by native review queues."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path

from ..native_decision_receipt import validate_native_decision_receipt
from ..runtime.actions import normalize_harness_payload


def native_review_tool_name(payload: Mapping[str, object]) -> str:
    for key in ("tool_name", "toolName", "tool"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "tool"


def native_review_action_envelope(
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
    if validated is None or "origin_authentication" not in validated:
        return envelope
    # Keep only the validated aggregate receipt, without aliasing nested maps.
    envelope["native_origin_receipt"] = deepcopy(validated)
    return envelope
