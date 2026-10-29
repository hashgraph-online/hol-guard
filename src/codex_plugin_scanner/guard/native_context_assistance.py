"""Thin presentation/transport for the native optional CIGAR control service.

This module never imports CIGAR, discovers Python or decides availability.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from threading import BoundedSemaphore
from typing import Any

from .native_context import _resolve_digest_home
from .native_daemon_route import _decide
from .native_resident_decision import ResidentOperation, shape_fields


class ContextAssistanceError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION = ResidentOperation(
    operation="context_assistance",
    feature="context-assistance-control-v2",
    prefix="native_context_assistance",
    request_schema="guard-context-assistance-request.v1",
    result_schema="guard-context-assistance-result.v1",
    request_id_prefix="context-assistance",
    timeout_seconds=2.0,
    error=ContextAssistanceError,
    # Rust owns the optional service lifecycle. Its transport cannot alter
    # the shared resident health circuit used by native Guard authority.
    shared_resident_health=False,
)

_NULL = type(None)
_FIELDS = {
    "schema": str,
    "availability": str,
    "requested_enabled": bool,
    "effective_enabled": bool,
    "preferences": dict,
    "effective_preferences": dict,
    "restriction": (str, _NULL),
    "verification_permitted": bool,
    "generation": str,
    "diagnostic": (str, _NULL),
    "runtime": (dict, _NULL),
    "last_check": (dict, _NULL),
    "qualification": (str, _NULL),
    "capabilities": dict,
    "installation_options": (list, _NULL),
    "job": (dict, _NULL),
}
_WORKSPACE_OPERATION = replace(_OPERATION, feature="context-assistance-workspaces-v1", timeout_seconds=8.0)
_WORKSPACE_SLOTS = BoundedSemaphore(2)
_VERSIONS_OPERATION = replace(_OPERATION, feature="context-assistance-versions-v1", timeout_seconds=8.0)


def _validate_state(answer: dict[str, Any]) -> None:
    if not isinstance(answer["state"], dict):
        raise ContextAssistanceError(_OPERATION.invalid)
    fields = dict(_FIELDS)
    for field, kind in {
        "execution_ready": bool,
        "execution_observations": (list, _NULL),
        "upgrade": (dict, _NULL),
    }.items():
        if field in answer["state"]:
            fields[field] = kind
    state = shape_fields(answer["state"], fields, lambda: ContextAssistanceError(_OPERATION.invalid))
    if state["schema"] != "guard-context-assistance-status.v2":
        raise ContextAssistanceError(_OPERATION.invalid)
    capabilities = {"shared_agents": bool, "private_persistence": bool}
    if "execution_context" in state["capabilities"]:
        capabilities["execution_context"] = bool
    shape_fields(
        state["capabilities"],
        capabilities,
        lambda: ContextAssistanceError(_OPERATION.invalid),
    )
    for runtime in (state["runtime"], state["last_check"]):
        for flag in ("persistence_compile_verified", "execution_handoff_verified"):
            if runtime is not None and flag in runtime and type(runtime[flag]) is not bool:
                raise ContextAssistanceError(_OPERATION.invalid)


def control(
    kind: str,
    *,
    guard_home: Path | None = None,
    payload: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise ContextAssistanceError("native_context_assistance_home_unbound") from None

    answer = _decide(
        {"kind": kind, "guard_home": str(home), "input": dict(payload or {})},
        home,
        {"state": dict},
        _validate_state,
        operation=_OPERATION,
        max_request_bytes=64 * 1024,
        request_budget_after_preflight=True,
    )
    return answer["state"]


def versions(*, guard_home: Path, payload: Mapping[str, object]) -> dict[str, Any]:
    """Transport native operator metadata and jobs without computing readiness."""
    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise ContextAssistanceError("native_context_assistance_home_unbound") from None

    def validate(answer: dict[str, Any]) -> None:
        _validate_state(answer)
        data = shape_fields(
            answer["data"], {"schema": str, "result": dict}, lambda: ContextAssistanceError(_VERSIONS_OPERATION.invalid)
        )
        if data["schema"] != "guard-cigar-versions-result.v1":
            raise ContextAssistanceError(_VERSIONS_OPERATION.invalid)

    answer = _decide(
        {"kind": "versions", "guard_home": str(home), "input": dict(payload)},
        home,
        {"state": dict, "data": dict},
        validate,
        operation=_VERSIONS_OPERATION,
        max_request_bytes=4 * 1024 * 1024 if payload.get("action") == "import_catalog" else 64 * 1024,
        slots=_WORKSPACE_SLOTS,
    )
    return {**answer["data"], "state": answer["state"]}


def workspace(kind: str, *, guard_home: Path, payload: Mapping[str, object]) -> dict[str, Any]:
    """Frame the route-bound operation; native code validates every action and scope."""
    try:
        home = _resolve_digest_home(guard_home)
    except (OSError, RuntimeError, ValueError):
        raise ContextAssistanceError("native_context_assistance_home_unbound") from None

    def validate(answer: dict[str, Any]) -> None:
        _validate_state(answer)
        data = shape_fields(
            answer["data"],
            {"schema": str, "data_role": bool, "result": dict},
            lambda: ContextAssistanceError(_WORKSPACE_OPERATION.invalid),
        )
        if data["schema"] != "guard-cigar-workspace-result.v1" or data["data_role"] is not True:
            raise ContextAssistanceError(_WORKSPACE_OPERATION.invalid)

    answer = _decide(
        {"kind": kind, "guard_home": str(home), "input": dict(payload)},
        home,
        {"state": dict, "data": dict},
        validate,
        operation=_WORKSPACE_OPERATION,
        max_request_bytes=64 * 1024,
        slots=_WORKSPACE_SLOTS,
    )
    return answer["data"]
