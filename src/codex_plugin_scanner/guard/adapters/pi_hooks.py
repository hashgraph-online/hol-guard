"""Pi hook response helpers for HOL Guard."""

from __future__ import annotations

import json
import sys
from typing import TextIO


def pi_hook_response_from_guard(*, policy_action: str, reason: str) -> dict[str, object]:
    """Translate a Guard policy action into the Pi extension bridge response."""

    if policy_action in {"block", "sandbox-required", "require-reapproval"}:
        cleaned_reason = reason.strip() if isinstance(reason, str) else ""
        return {
            "decision": "deny",
            "reason": cleaned_reason or "Blocked by HOL Guard.",
        }
    return {"decision": "allow"}


def emit_pi_hook_response(
    *,
    policy_action: str,
    reason: str,
    output_stream: TextIO | None = None,
) -> None:
    payload = pi_hook_response_from_guard(policy_action=policy_action, reason=reason)
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(payload, separators=(",", ":")) + "\n")
    stream.flush()


__all__ = ["emit_pi_hook_response", "pi_hook_response_from_guard"]
