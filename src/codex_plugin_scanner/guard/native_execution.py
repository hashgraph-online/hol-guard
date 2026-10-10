"""Resident bridge for contained-execution + shim-admin + MCP-probe ops (RTM-020).

Each helper sends a native request and decodes its response. A missing or
malformed response returns ``None``; enforcement callers must treat that as
unavailable authority, not permission to substitute Python decisions.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, get_args

from .models import GuardAction
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, native_runtime_status
from .native_runtime_resilience import (
    native_record_resident_failure,
    native_record_resident_success,
)

if TYPE_CHECKING:
    from .contained_node_execution import ContainedNodeResult
    from .contained_package_script_execution import ContainedPackageScriptResult
    from .contained_typescript_execution import ContainedTypeScriptResult
    from .contained_workspace_write_execution import ContainedWorkspaceWriteResult
    from .runtime.effect_decision import DecisionReason, EffectDecision, PositiveProof

_MAX_REQUEST_BYTES = 256 * 1024
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_CONTAINED_EXECUTION_FEATURE = "contained-execution-v1"
_SHIM_ADMIN_FEATURE = "shim-admin-v1"
_MCP_STDIO_PROBE_FEATURE = "mcp-stdio-probe-v1"
_MCP_STDIO_SESSION_FEATURE = "mcp-stdio-session-v1"
_MCP_STDIO_SESSION_OPEN_SCHEMA = "guard-mcp-stdio-session-open-request.v1"
_MCP_STDIO_SESSION_IO_SCHEMA = "guard-mcp-stdio-session-io-request.v1"
_MCP_STDIO_SESSION_RESULT_SCHEMA = "guard-mcp-stdio-session-result.v1"


def _native_session_feature_available() -> bool:
    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None or status.capabilities is None:
        return False
    features = set(status.capabilities.features)
    return _RESIDENT_PROTOCOL_FEATURE in features and _MCP_STDIO_SESSION_FEATURE in features


# Terminal/vocab statuses each session op may legitimately return. A reported
# "error"/"exited"/"eof" is a terminal native answer — the caller must see it
# rather than get None and silently fall back to a Python subprocess.
_MCP_SESSION_ACCEPTED_STATUS = {
    "mcp_stdio_session_open": frozenset({"opened", "exited", "error"}),
    "mcp_stdio_session_send": frozenset({"sent", "error"}),
    "mcp_stdio_session_recv": frozenset({"event", "running", "timeout", "eof", "exited", "error"}),
    "mcp_stdio_session_close": frozenset({"closed", "error"}),
    "mcp_stdio_session_cancel": frozenset({"cancelled", "error"}),
}
_PROMPT_ANALYZE_FEATURE = "prompt-analyze-v1"


def _request_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _resident_request(
    *,
    operation: str,
    request: dict[str, object],
    guard_home: Path,
    timeout_seconds: float,
    required_feature: str,
    response_schema: str | None = None,
    max_request_bytes: int = _MAX_REQUEST_BYTES,
    record_success: bool = True,
) -> dict[str, object] | None:
    """Envelope + transport shared by all contained-execution ops.

    Pass ``record_success=False`` when the caller validates the reply further
    and records success itself; otherwise a resident that keeps sending
    unusable replies would reset the failure streak on every call.
    """
    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None or status.capabilities is None:
        return None
    features = set(status.capabilities.features)
    if _RESIDENT_PROTOCOL_FEATURE not in features or required_feature not in features:
        return None

    envelope = {
        "operation": operation,
        "request": request,
        "deadline_budget_ms": max(1, int(timeout_seconds * 1000)),
    }
    try:
        payload = json.dumps(envelope).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(payload) > max_request_bytes:
        return None
    environment = _isolated_environment()
    response = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=environment,
        payload=payload,
        timeout_seconds=timeout_seconds,
    )
    if response is None:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_transport")
        return None
    try:
        decoded = json.loads(response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_malformed")
        return None
    if not isinstance(decoded, dict):
        return None
    if response_schema is not None and decoded.get("schema") != response_schema:
        native_record_resident_failure(status.identity.sha256, guard_home, reason=f"native_{operation}_schema")
        return None
    result_schema = {
        "prompt_analyze": "guard-prompt-analyze-result.v1",
        "mcp_stdio_probe": "guard-mcp-stdio-probe-result.v1",
    }.get(operation)
    if result_schema is not None:
        # These versioned Rust replies have no status field. Do not discard
        # valid native results or reinterpret them through a Python fallback.
        if decoded.get("schema") != result_schema or set(decoded) != {"schema", "result"}:
            return None
    else:
        # Session/terminal ops report success under their own status, not
        # "ok". Requiring "ok" dropped every successful mcp_stdio_session_open
        # ("opened") / recv ("event") / close ("closed") and forced a silent
        # Python fallback the resident should own.
        accepted = _MCP_SESSION_ACCEPTED_STATUS.get(operation)
        if operation in {
            "policy_decision_lookup",
            "local_cli_grant_decide",
            "local_mcp_grant_decide",
            "approval_proof_decide",
            "request_context_build",
        }:
            accepted = frozenset({"ok", "error"})
        elif operation == "mcp_tool_policy_decide":
            accepted = frozenset({"ok", "need", "error"})
        if accepted is not None:
            if decoded.get("status") not in accepted:
                return None
        elif decoded.get("status") != "ok":
            return None
    if record_success:
        native_record_resident_success(status.identity.sha256, guard_home)
    return decoded


# ---------------------------------------------------------------------------
# Contained execution ops
# ---------------------------------------------------------------------------


def _contained_request(
    *,
    op_prefix: str,
    request_schema: str,
    workspace: Path,
    manager: str,
    argv: Sequence[str],
    guard_home: Path,
    evidence: dict[str, object] | None = None,
    extra_fields: dict[str, object] | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": request_schema,
        "request_id": _request_id(op_prefix),
        "workspace": str(workspace),
        "manager": manager,
        "argv": list(argv),
        "guard_home": str(guard_home),
        "evidence": evidence,
    }
    if extra_fields:
        request.update(extra_fields)
    decoded = _resident_request(
        operation=op_prefix,
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_CONTAINED_EXECUTION_FEATURE,
    )
    if decoded is None:
        return None
    result = decoded.get("result")
    return result if isinstance(result, dict) else None


def contained_node_execute_native(
    workspace: Path,
    manager: str,
    argv: Sequence[str],
    *,
    guard_home: Path,
    evidence: dict[str, object] | None = None,
    timeout_seconds: float = 30.0,
) -> ContainedNodeResult | None:
    result = _contained_request(
        op_prefix="contained_node_execute",
        request_schema="guard-contained-node-execute-request.v1",
        workspace=workspace,
        manager=manager,
        argv=argv,
        guard_home=guard_home,
        evidence=evidence,
        timeout_seconds=timeout_seconds,
    )
    if result is None:
        return None
    try:
        return _contained_node_result(result)
    except (KeyError, TypeError, ValueError):
        return None


def contained_typescript_execute_native(
    workspace: Path,
    manager: str,
    argv: Sequence[str],
    *,
    guard_home: Path,
    evidence: dict[str, object] | None = None,
    timeout_seconds: float = 30.0,
) -> ContainedTypeScriptResult | None:
    result = _contained_request(
        op_prefix="contained_typescript_execute",
        request_schema="guard-contained-typescript-execute-request.v1",
        workspace=workspace,
        manager=manager,
        argv=argv,
        guard_home=guard_home,
        evidence=evidence,
        timeout_seconds=timeout_seconds,
    )
    if result is None:
        return None
    try:
        return _contained_typescript_result(result)
    except (KeyError, TypeError, ValueError):
        return None


def contained_package_script_execute_native(
    workspace: Path,
    manager: str,
    argv: Sequence[str],
    *,
    guard_home: Path,
    shim_directory: Path | None = None,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = 30.0,
) -> ContainedPackageScriptResult | None:
    result = _contained_request(
        op_prefix="contained_package_script_execute",
        request_schema="guard-contained-package-script-execute-request.v1",
        workspace=workspace,
        manager=manager,
        argv=argv,
        guard_home=guard_home,
        extra_fields={
            "shim_directory": str(shim_directory) if shim_directory else None,
            "environment": dict(environment) if environment else None,
            "timeout_seconds": timeout_seconds,
        },
        timeout_seconds=timeout_seconds,
    )
    if result is None:
        return None
    try:
        return _contained_package_script_result(result)
    except (KeyError, TypeError, ValueError):
        return None


def contained_workspace_write_execute_native(
    workspace: Path,
    command_text: str = "",
    *,
    guard_home: Path,
    timeout_seconds: float = 10.0,
    operation: str | None = None,
    source: str | None = None,
    target: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> ContainedWorkspaceWriteResult | None:
    request: dict[str, object] = {
        "schema": "guard-contained-workspace-write-execute-request.v1",
        "request_id": _request_id("contained_workspace_write_execute"),
        "workspace": str(workspace),
        "command_text": command_text,
        "operation": operation,
        "source": source,
        "target": target,
        "environment": dict(environment) if environment else None,
        "timeout_seconds": int(timeout_seconds),
        "guard_home": str(guard_home),
    }
    decoded = _resident_request(
        operation="contained_workspace_write_execute",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_CONTAINED_EXECUTION_FEATURE,
    )
    if decoded is None:
        return None
    result = decoded.get("result")
    if not isinstance(result, dict):
        return None
    try:
        return _contained_workspace_write_result(result)
    except (KeyError, TypeError, ValueError):
        return None


def contained_execute_native(
    request_payload: dict[str, object],
    policy_payload: dict[str, object],
    *,
    guard_home: Path,
    run_id: str,
    timeout_seconds: float = 60.0,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": "guard-contained-execute-request.v1",
        "request_id": _request_id("contained_execute"),
        "request": request_payload,
        "policy": policy_payload,
        "guard_home": str(guard_home),
        "run_id": run_id,
    }
    decoded = _resident_request(
        operation="contained_execute",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_CONTAINED_EXECUTION_FEATURE,
    )
    if decoded is None:
        return None
    result = decoded.get("result")
    return result if isinstance(result, dict) else None


def contained_test_hook_native(
    workspace: Path,
    command_text: str,
    *,
    guard_home: Path,
    timeout_seconds: float = 10.0,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": "guard-contained-test-hook-request.v1",
        "request_id": _request_id("contained_test_hook"),
        "workspace": str(workspace),
        "command_text": command_text,
        "guard_home": str(guard_home),
    }
    decoded = _resident_request(
        operation="contained_test_hook",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_CONTAINED_EXECUTION_FEATURE,
    )
    if decoded is None:
        return None
    result = decoded.get("result")
    return result if isinstance(result, dict) else None


# ---------------------------------------------------------------------------
# Shim admin op
# ---------------------------------------------------------------------------


def shim_admin_native(
    subop: str,
    *,
    guard_home: Path,
    managers: Sequence[str] | None = None,
    workspace_dir: Path | None = None,
    allow_inactive_path: bool = False,
    timeout_seconds: int = 30,
    path_env: str | None = None,
    install_managers: Sequence[str] | None = None,
    repair: bool = False,
) -> dict[str, object] | list[object] | None:
    request: dict[str, object] = {
        "schema": "guard-shim-admin-request.v1",
        "subop": subop,
        "guard_home": str(guard_home),
        "managers": list(managers) if managers else None,
        "workspace_dir": str(workspace_dir) if workspace_dir else None,
        "allow_inactive_path": allow_inactive_path,
        "timeout_seconds": timeout_seconds,
        "path_env": path_env,
        "install_managers": list(install_managers) if install_managers else None,
        "repair": repair,
    }
    decoded = _resident_request(
        operation="shim_admin",
        request=request,
        guard_home=guard_home,
        timeout_seconds=float(timeout_seconds) + 5.0,
        required_feature=_SHIM_ADMIN_FEATURE,
    )
    if decoded is None:
        return None
    result = decoded.get("result")
    return result if isinstance(result, (dict, list)) else None


# ---------------------------------------------------------------------------
# MCP stdio probe op
# ---------------------------------------------------------------------------


def mcp_stdio_probe_native(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path | None = None,
    extra_env: Mapping[str, str] | None = None,
    timeout_seconds: float = 6.0,
    connection_identity_hash: str | None = None,
    guard_home: Path,
    cancel: threading.Event | None = None,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": "guard-mcp-stdio-probe-request.v1",
        "request_id": _request_id("mcp_stdio_probe"),
        "command_text": command_text,
        "cwd": str(cwd),
        "home_dir": str(home_dir) if home_dir else None,
        "extra_env": dict(extra_env) if extra_env else None,
        "timeout_seconds": timeout_seconds,
        "connection_identity_hash": connection_identity_hash,
        "guard_home": str(guard_home),
    }
    done = threading.Event()
    watcher: threading.Thread | None = None
    if cancel is not None:

        def deliver_cancellation() -> None:
            while not done.is_set():
                if not cancel.wait(0.05):
                    continue
                response = _resident_request(
                    operation="mcp_stdio_cancel",
                    request={"request_id": request["request_id"]},
                    guard_home=guard_home,
                    timeout_seconds=1.0,
                    required_feature=_MCP_STDIO_PROBE_FEATURE,
                )
                if response is None or response.get("cancelled") is True:
                    return
                if done.wait(0.05):
                    return

        watcher = threading.Thread(target=deliver_cancellation, daemon=True)
        watcher.start()
    try:
        decoded = _resident_request(
            operation="mcp_stdio_probe",
            request=request,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds + 2.0,
            required_feature=_MCP_STDIO_PROBE_FEATURE,
            response_schema="guard-mcp-stdio-probe-result.v1",
        )
    finally:
        done.set()
        if watcher is not None:
            watcher.join(1.1)
    if decoded is None:
        return None
    result = decoded.get("result")
    return result if isinstance(result, dict) else None


# ---------------------------------------------------------------------------
# Result translators — reconstruct Python dataclasses from Rust to_dict
# payloads. Every translator raises on a missing/mismatched field so the
# caller falls back to the Python body rather than fabricating a result.
# ---------------------------------------------------------------------------


def _require_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"missing or non-string field: {key}")
    return value


def _require_guard_action(payload: dict[str, Any], key: str) -> GuardAction:
    value = _require_str(payload, key)
    if value not in get_args(GuardAction):
        raise ValueError(f"invalid guard action: {key}")
    return cast(GuardAction, value)


def _require_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"missing or non-int field: {key}")
    return value


def _require_list(payload: dict[str, Any], key: str) -> list[Any]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ValueError(f"missing or non-list field: {key}")
    return value


def _require_dict(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"missing or non-dict field: {key}")
    return value


def _positive_proof(payload: dict[str, Any]) -> PositiveProof:
    from .runtime.effect_contract import ProofRequirement, ProofRoute
    from .runtime.effect_decision import PositiveProof

    route_str = _require_str(payload, "route")
    binding_digest = _require_str(payload, "binding_digest")
    raw_reqs = _require_list(payload, "satisfied_requirements")
    enforced = payload.get("enforced")
    if not isinstance(enforced, bool):
        raise ValueError("missing or non-bool field: enforced")
    return PositiveProof(
        route=ProofRoute(route_str),
        binding_digest=binding_digest,
        satisfied_requirements=frozenset(ProofRequirement(r) for r in raw_reqs),
        enforced=enforced,
    )


def _decision_reason(item: dict[str, Any]) -> DecisionReason:
    from .runtime.effect_decision import DecisionFactorSource, DecisionReason

    source = _require_str(item, "source")
    reason_code = _require_str(item, "reason_code")
    action_floor = _require_guard_action(item, "action_floor")
    segment_ref = item.get("segment_ref")
    operation_ref = item.get("operation_ref")
    return DecisionReason(
        source=DecisionFactorSource(source),
        reason_code=reason_code,
        action_floor=action_floor,
        segment_ref=segment_ref if isinstance(segment_ref, str) else None,
        operation_ref=operation_ref if isinstance(operation_ref, str) else None,
    )


def _effect_decision(payload: dict[str, Any]) -> EffectDecision:
    from .runtime.effect_contract import ProofRoute
    from .runtime.effect_decision import EffectDecision, FinalDisposition

    action = _require_guard_action(payload, "action")
    disposition = _require_str(payload, "disposition")
    raw_routes = _require_list(payload, "proof_routes")
    raw_controlling = _require_list(payload, "controlling_reasons")
    raw_reasons = _require_list(payload, "reasons")
    return EffectDecision(
        action=action,
        disposition=FinalDisposition(disposition),
        controlling_reasons=tuple(_decision_reason(r) for r in raw_controlling),
        reasons=tuple(_decision_reason(r) for r in raw_reasons),
        proof_routes=frozenset(ProofRoute(r) for r in raw_routes),
    )


def _contained_node_result(payload: dict[str, Any]) -> ContainedNodeResult:
    from .contained_node_execution import ContainedNodeResult

    attestation = _require_dict(payload, "attestation")
    decision_raw = _require_dict(payload, "decision")
    exit_code = _require_int(attestation, "exit_code")
    stdout = _require_str(payload, "stdout")
    stderr = _require_str(payload, "stderr")
    proof = _positive_proof(_require_dict(payload, "proof"))
    decision = _effect_decision(decision_raw)
    operation_id = _require_str(payload, "operation_id")
    return ContainedNodeResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        proof=proof,
        decision=decision,
        operation_id=operation_id,
    )


def _contained_typescript_result(payload: dict[str, Any]) -> ContainedTypeScriptResult:
    from .contained_typescript_execution import ContainedTypeScriptResult

    attestation = _require_dict(payload, "attestation")
    decision_raw = _require_dict(payload, "decision")
    exit_code = _require_int(attestation, "exit_code")
    stdout = _require_str(payload, "stdout")
    stderr = _require_str(payload, "stderr")
    proof = _positive_proof(_require_dict(payload, "proof"))
    decision = _effect_decision(decision_raw)
    operation_id = _require_str(payload, "operation_id")
    return ContainedTypeScriptResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        proof=proof,
        decision=decision,
        operation_id=operation_id,
    )


def _contained_package_script_result(payload: dict[str, Any]) -> ContainedPackageScriptResult:
    from .contained_package_script_execution import ContainedPackageScriptResult

    attestation = _require_dict(payload, "attestation")
    decision_raw = _require_dict(payload, "decision")
    exit_code = _require_int(attestation, "exit_code")
    stdout = _require_str(payload, "stdout")
    stderr = _require_str(payload, "stderr")
    proof = _positive_proof(_require_dict(payload, "proof"))
    decision = _effect_decision(decision_raw)
    operation_id = _require_str(payload, "operation_id")
    return ContainedPackageScriptResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        proof=proof,
        decision=decision,
        operation_id=operation_id,
    )


def _contained_workspace_write_result(payload: dict[str, Any]) -> ContainedWorkspaceWriteResult:
    from .contained_workspace_write_execution import (
        ContainedWorkspaceWriteResult,
        ContainedWriteOperation,
    )

    attestation = _require_dict(payload, "attestation")
    decision_raw = _require_dict(payload, "decision")
    exit_code = _require_int(attestation, "exit_code")
    stdout = _require_str(payload, "stdout")
    stderr = _require_str(payload, "stderr")
    proof = _positive_proof(_require_dict(payload, "proof"))
    decision = _effect_decision(decision_raw)
    op_raw = _require_str(payload, "operation_id")
    if op_raw not in get_args(ContainedWriteOperation):
        raise ValueError("invalid contained write operation")
    output_digest = payload.get("output_digest")
    return ContainedWorkspaceWriteResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        proof=proof,
        decision=decision,
        operation_id=cast(ContainedWriteOperation, op_raw),
        output_digest=output_digest if isinstance(output_digest, str) else None,
    )


# ---------------------------------------------------------------------------
# Prompt-analysis op (RTM-019)
# ---------------------------------------------------------------------------


def prompt_analyze_native(
    subop: str,
    *,
    guard_home: Path,
    prompt_text: str | None = None,
    request_class: str | None = None,
    matched_text: str | None = None,
    harness: str | None = None,
    config_path: str | None = None,
    requests: Sequence[Mapping[str, object]] | None = None,
    prior_policy_present: bool | None = None,
    approved_classes: Sequence[str] | None = None,
    timeout_seconds: float = 10.0,
) -> object:
    """Subop-multiplexed `prompt_analyze` resident op (RTM-019).

    Returns the decoded ``result`` payload (request dicts, artifact dicts,
    bool, or string per subop), or ``None`` on transport failure / missing
    feature. The prompt client must stop the operation on missing authority.
    """
    if requests is not None and (
        not isinstance(requests, Sequence)
        or isinstance(requests, (str, bytes, bytearray))
        or not all(isinstance(item, Mapping) for item in requests)
    ):
        return None
    if approved_classes is not None and (
        not isinstance(approved_classes, Sequence)
        or isinstance(approved_classes, (str, bytes, bytearray))
        or not all(isinstance(item, str) for item in approved_classes)
    ):
        return None
    request: dict[str, object] = {
        "schema": "guard-prompt-analyze-request.v1",
        "request_id": _request_id("prompt_analyze"),
        "subop": subop,
        "prompt_text": prompt_text,
        "request_class": request_class,
        "matched_text": matched_text,
        "harness": harness,
        "config_path": config_path,
        "requests": [dict(r) for r in requests] if requests is not None else None,
        "prior_policy_present": prior_policy_present,
        "approved_classes": list(approved_classes) if approved_classes is not None else None,
        "guard_home": str(guard_home),
    }
    decoded = _resident_request(
        operation="prompt_analyze",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_PROMPT_ANALYZE_FEATURE,
    )
    if decoded is None:
        return None
    return decoded.get("result")


def mcp_stdio_session_open_native(
    argv: Sequence[str],
    *,
    session_id: str,
    home_dir: Path | None = None,
    cwd: Path | None = None,
    extra_env: Mapping[str, str] | None = None,
    guard_home: Path,
    timeout_seconds: float = 10.0,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": _MCP_STDIO_SESSION_OPEN_SCHEMA,
        "session_id": session_id,
        "owner_pid": os.getpid(),
        "argv": list(argv),
        "extra_env": dict(extra_env) if extra_env else None,
        "home_dir": str(home_dir) if home_dir else None,
        "cwd": str(cwd) if cwd else None,
    }
    decoded = _resident_request(
        operation="mcp_stdio_session_open",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_MCP_STDIO_SESSION_FEATURE,
        response_schema=_MCP_STDIO_SESSION_RESULT_SCHEMA,
    )
    if decoded is None:
        return None
    return decoded


def mcp_stdio_session_send_native(
    session_id: str,
    message: Mapping[str, object],
    *,
    guard_home: Path,
    timeout_seconds: float = 10.0,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": _MCP_STDIO_SESSION_IO_SCHEMA,
        "session_id": session_id,
        "message": dict(message),
    }
    return _resident_request(
        operation="mcp_stdio_session_send",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_MCP_STDIO_SESSION_FEATURE,
        response_schema=_MCP_STDIO_SESSION_RESULT_SCHEMA,
    )


def mcp_stdio_session_recv_native(
    session_id: str,
    *,
    guard_home: Path,
    timeout_seconds: float = 30.0,
    await_request_id: object = None,
    poll_only: bool = False,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": _MCP_STDIO_SESSION_IO_SCHEMA,
        "session_id": session_id,
        "timeout_ms": int(timeout_seconds * 1000),
        "await_request_id": await_request_id,
        "poll_only": poll_only,
    }
    return _resident_request(
        operation="mcp_stdio_session_recv",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds if poll_only else timeout_seconds + 2.0,
        required_feature=_MCP_STDIO_SESSION_FEATURE,
        response_schema=_MCP_STDIO_SESSION_RESULT_SCHEMA,
    )


def mcp_stdio_session_close_native(
    session_id: str,
    *,
    guard_home: Path,
    timeout_seconds: float = 5.0,
) -> dict[str, object] | None:
    request: dict[str, object] = {
        "schema": _MCP_STDIO_SESSION_IO_SCHEMA,
        "session_id": session_id,
    }
    return _resident_request(
        operation="mcp_stdio_session_close",
        request=request,
        guard_home=guard_home,
        timeout_seconds=timeout_seconds,
        required_feature=_MCP_STDIO_SESSION_FEATURE,
        response_schema=_MCP_STDIO_SESSION_RESULT_SCHEMA,
    )
