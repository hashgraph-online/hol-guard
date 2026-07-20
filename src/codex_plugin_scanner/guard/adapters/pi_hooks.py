"""Pi hook response helpers for HOL Guard."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import TextIO


def pi_hook_response_from_guard(
    *,
    policy_action: str,
    reason: str,
    approval_payload: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Translate a Guard policy action into the Pi extension bridge response."""

    if policy_action in {"review", "require-reapproval", "sandbox-required", "block"}:
        cleaned_reason = reason.strip() if isinstance(reason, str) else ""
        response: dict[str, object] = {
            "decision": "deny",
            "reason": cleaned_reason or "Blocked by HOL Guard.",
        }
        response.update(pi_resume_metadata_from_guard_payload(approval_payload))
        return response
    return {"decision": "allow"}


def pi_resume_metadata_from_guard_payload(approval_payload: Mapping[str, object] | None) -> dict[str, object]:
    if approval_payload is None:
        return {}
    request_id = _optional_string(approval_payload.get("primary_approval_request_id"))
    approval_url = _optional_string(approval_payload.get("primary_approval_url"))
    approval_center_url = _optional_string(approval_payload.get("approval_center_url"))
    metadata: dict[str, object] = {}
    if request_id is not None:
        metadata["approval_request_id"] = request_id
        metadata["resume_poll_path"] = f"/v1/requests/{request_id}"
    if approval_url is not None:
        metadata["approval_url"] = approval_url
    if approval_center_url is not None:
        metadata["approval_center_url"] = approval_center_url
    return metadata


def emit_pi_hook_response(
    *,
    policy_action: str,
    reason: str,
    approval_payload: Mapping[str, object] | None = None,
    output_stream: TextIO | None = None,
) -> None:
    payload = pi_hook_response_from_guard(
        policy_action=policy_action,
        reason=reason,
        approval_payload=approval_payload,
    )
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(payload, separators=(",", ":")) + "\n")
    stream.flush()


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


__all__ = ["emit_pi_hook_response", "pi_hook_response_from_guard", "pi_resume_metadata_from_guard_payload"]
