"""Thin authenticated transport to the resident-owned Swarm service."""

from __future__ import annotations

import os
from functools import partial
from pathlib import Path
from typing import Any

from .native_context import _resolve_digest_home
from .native_execution import _resident_request
from .native_resident_decision import ResidentOperation, resident_decide, shape_fields


class SwarmError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION = ResidentOperation(
    operation="swarm",
    feature="swarm-v1",
    prefix="swarm",
    request_schema="guard-swarm-request.v1",
    result_schema="guard-swarm-result.v1",
    request_id_prefix="swarm",
    timeout_seconds=5.0,
    error=SwarmError,
    shared_resident_health=False,
)


def execute(action: str, payload: dict[str, Any], *, guard_home: Path) -> dict[str, Any]:
    home = _resolve_digest_home(guard_home)

    inputs = {
        "snapshot": {"action": "snapshot"},
        "launch": {"action": "launch", "launch": payload},
        "direct": {"action": "direct", "request": payload},
        "events": {"run_id": payload.get("run_id"), "action": "events"},
    }
    fields = {
        "snapshot": {"snapshot": dict},
        "launch": {"agent": dict},
        "direct": {"agent": dict},
        "events": {"events": list},
    }

    def validate(answer: dict[str, Any]) -> None:
        shape_fields(answer, fields[action], lambda: SwarmError(_OPERATION.invalid))

    answer = resident_decide(
        _OPERATION,
        partial(_resident_request, max_request_bytes=32768),
        {"guard_home": str(home), "cli_path": os.environ.get("PATH", ""), "input": inputs[action]},
        home,
        validate,
    )
    return answer["snapshot"] if action == "snapshot" else answer
