"""Resident bridge for the ``command_job_plan`` op.

The Rust runtime decides how a leased Guard Cloud command job runs: its
operation family, the manager, harness and surface arguments it may carry,
which jobs wait for a local confirmation command, and that command. This
module frames one request, binds the answer and checks its shape. It never
plans a job itself; a runtime that cannot answer raises
``CommandJobPlanError`` and the job posts ``failed`` without running.
"""

from __future__ import annotations

import functools
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .native_context import _resolve_digest_home
from .native_execution import _resident_request
from .native_resident_decision import ResidentOperation, resident_decide

_MAX_REQUEST_BYTES = 64 * 1024
_FAMILIES = frozenset({"package_shims", "app", "exact_cloud_review", "policy_memory"})


class CommandJobPlanError(RuntimeError):
    """The resident gave no usable plan for a command job."""

    @property
    def code(self) -> str:
        return str(self.args[0]) if self.args else "native_command_job_plan_unavailable"


_OPERATION = ResidentOperation(
    operation="command_job_plan",
    feature="command-job-plan-v1",
    prefix="native_command_job_plan",
    request_schema="guard-command-job-plan-request.v1",
    result_schema="guard-command-job-plan-result.v1",
    request_id_prefix="command-job-plan",
    timeout_seconds=2.0,
    error=CommandJobPlanError,
)


def plan_command_job(
    operation: object,
    payload: Mapping[str, object],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """The resident's plan for one job: ``fail``, ``confirm`` or ``run``."""

    def validate(answer: dict[str, Any]) -> None:
        if set(answer) != {"kind", "plan"} or not _valid_plan(answer["plan"]):
            raise CommandJobPlanError(_OPERATION.invalid)
        plan = answer["plan"]
        if plan["action"] == "run" and plan["operation"] != operation:
            raise CommandJobPlanError(_OPERATION.invalid)

    query: dict[str, object] = {
        "kind": "plan",
        "operation": operation,
        "harness": payload.get("harness"),
        "surface": payload.get("surface"),
        "managers": payload.get("managers"),
    }
    answer = resident_decide(
        _OPERATION,
        functools.partial(_resident_request, max_request_bytes=_MAX_REQUEST_BYTES),
        query,
        Path(_resolve_digest_home(guard_home)),
        validate,
    )
    return dict(answer["plan"])


def _valid_plan(plan: object) -> bool:
    if not isinstance(plan, dict):
        return False
    action = plan.get("action")
    if action == "fail":
        return set(plan) == {"action", "failure_code", "failure_message"} and all(
            isinstance(plan[key], str) and plan[key] for key in ("failure_code", "failure_message")
        )
    if action == "confirm":
        return set(plan) == {"action", "data"} and isinstance(plan["data"], dict)
    if action != "run" or set(plan) != {"action", "operation", "family", "managers", "harness", "surface"}:
        return False
    managers = plan["managers"]
    return (
        isinstance(plan["operation"], str)
        and isinstance(plan["family"], str)
        and plan["family"] in _FAMILIES
        and (managers is None or (isinstance(managers, list) and all(isinstance(item, str) for item in managers)))
        and all(plan[key] is None or isinstance(plan[key], str) for key in ("harness", "surface"))
    )


__all__ = ["CommandJobPlanError", "plan_command_job"]
