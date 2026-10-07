"""Privacy-safe correlation for observing a real installed hook invocation.

A probe ID requests diagnostics only. It never grants approval, changes a
decision, or enables a fallback. Commands remain classification inputs.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping

from .native_decision_receipt import validate_native_decision_receipt

PROBE_FIELD = "guard_transition_probe"
OBSERVATION_FIELD = "guard_transition_observation"
PROBE_SCHEMA = "hol-guard.transition-hook-probe.v1"
OBSERVATION_SCHEMA = "hol-guard.transition-hook-observation.v1"


def transition_hook_probe(payload: Mapping[str, object]) -> tuple[str, str] | None:
    probe = payload.get(PROBE_FIELD)
    if not isinstance(probe, dict) or set(probe) != {"schema", "operation_id", "request_id"}:
        return None
    operation, request = probe.get("operation_id"), probe.get("request_id")
    if (
        probe.get("schema") != PROBE_SCHEMA
        or not isinstance(operation, str)
        or not isinstance(request, str)
        or re.fullmatch(r"transition-hook-[0-9a-f]{32}", request) is None
    ):
        return None
    try:
        if str(uuid.UUID(operation)) != operation:
            return None
    except ValueError:
        return None
    return operation, request


def transition_hook_observation(payload: Mapping[str, object], receipt: object) -> dict[str, object] | None:
    probe = transition_hook_probe(payload)
    if probe is None:
        return None
    native = validate_native_decision_receipt(receipt)
    if (
        native is None
        or native["request_id"] != probe[1]
        or native["event_name"] != "PreToolUse"
        or native["harness"] not in {"codex", "omp"}
        or native["payload_kind"] != "inline"
        or native["observe_mode"] is not False
    ):
        return None
    return {"schema": OBSERVATION_SCHEMA, "operation_id": probe[0], "request_id": probe[1], "native_receipt": native}
