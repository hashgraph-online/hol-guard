"""Exact-action identity and review binding answered by the native runtime.

A persistent "Always" decision needs an identity that survives new sessions
while changing whenever the code that would run, the files it reads, the git
configuration it would consult or the Rust rules that judged it change. The
short-lived retry binding of one native review needs the Rust request digest.
The resident (``native_exact_action``) owns every one of those proofs.

Python transports the facts only it holds: the verified policy binding, the
ambient environment and the extension-control digest. There is no Python
fallback: when the resident cannot answer, no persistent token is available.
The separate delivery contract decides whether a once retry is executable.
Launch evidence reports observations only and never grants execution.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from ..native_daemon_route import EXACT_ACTION_ASK_SLOTS, _decide
from ..native_resident_decision import ResidentOperation
from ..runtime.extension_control_runtime import current_extension_control_binding_digest
from .hook_native_review_binding import native_review_policy_binding
from .hook_request_parsing import pre_tool_command, pre_tool_input

NATIVE_EXACT_ACTION_FEATURE = "native-exact-action-v4"
UNPROVEN_LAUNCH = "unproven_launch"
_LOGGER = logging.getLogger(__name__)
_TIMEOUT_SECONDS = 6.0
_BUDGET_MS = 4000
_MAX_REQUEST_BYTES = 256 * 1024
# Native action types for changes to Guard itself; the resident judges them, and
# the saved-decision path still skips them without asking.
GUARD_CONTROL_ACTION_TYPES = frozenset(
    {"guard_control", "guard-control", "guard_control_operation", "guard-control-operation"}
)
_ONCE_ONLY_REASONS = frozenset(
    {
        "no_command_identity",
        "mutable_launcher",
        "compound_command",
        "guard_control",
        "package_action",
        "non_overridable",
        "unproven_launch",
        "sensitive_path",
        "broad_scope",
        "destructive_command",
        "git_helper_config",
        "node_package_manifest_unproven",
        "node_package_entrypoint_unproven",
        "node_package_exports_unproven",
        "node_package_native_addon_unproven",
        "node_runtime_package_mutation_unproven",
        "runner_code_closure_unproven",
        "python_runtime_module_unproven",
        "python_runtime_bootstrap_unproven",
        "script_execution_binding_unavailable",
    }
)


class NativeExactActionError(RuntimeError):
    """No authoritative answer; ``code`` says why, for diagnostics only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPERATION = ResidentOperation(
    operation="native_exact_action",
    feature=NATIVE_EXACT_ACTION_FEATURE,
    prefix="native_exact_action",
    request_schema="guard-native-exact-action-request.v1",
    request_id_prefix="native-exact-action",
    result_schema="guard-native-exact-action-result.v1",
    timeout_seconds=_TIMEOUT_SECONDS,
    error=NativeExactActionError,
)


def launch_cwd(payload: Mapping[str, object], workspace: Path | None) -> Path | None:
    """The absolute, existing directory a hook action would launch in."""

    raw = payload.get("cwd")
    candidate = Path(raw) if isinstance(raw, str) and raw.strip() else workspace
    if candidate is None or not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if os.path.isdir(resolved) else None


def launch_path(payload: Mapping[str, object]) -> str | None:
    """The ``PATH`` the hook stamped from the agent's own environment, if any."""

    stamped = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    path = stamped.get("path") if isinstance(stamped, Mapping) else None
    return path if isinstance(path, str) and path and "\0" not in path else None


def _facts(native_result: Mapping[str, object]) -> dict[str, str | None]:
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    return {
        "decision": str(native_result.get("decision") or ""),
        "minimum_action": str(native_result.get("minimum_action") or ""),
        "policy_action": str(native_result.get("policy_action") or ""),
        "reason_code": str(native_result.get("reason_code") or ""),
        "action_type": action_type if isinstance(action_type, str) else None,
    }


def _policy_binding(
    harness: str, native_result: Mapping[str, object], receipt: Mapping[str, object] | None
) -> dict[str, object]:
    try:
        binding = native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=receipt)
    except ValueError:
        return {"state": "invalid"}
    if binding is None:
        return {"state": "unbound"}
    return {"state": "bound", "value": dict(binding)}


def _tool_input_pairs(payload: Mapping[str, object]) -> list[list[object]] | None:
    tool_input = pre_tool_input(payload)
    if tool_input is None:
        arguments = payload.get("arguments")
        tool_input = arguments if isinstance(arguments, Mapping) else None
    if tool_input is None:
        return None
    return [[key, value] for key, value in tool_input.items() if isinstance(key, str)]


def _raw_tool_input(payload: Mapping[str, object]) -> object | None:
    """The first tool input sent that is not an object, when none is one."""

    if pre_tool_input(payload) is not None or isinstance(payload.get("arguments"), Mapping):
        return None
    for key in ("tool_input", "toolInput", "arguments"):
        value = payload.get(key)
        if value is not None:
            return value
    return None


def _text(value: object) -> str | None:
    return str(value) if value is not None else None


def _exact_query(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object]:
    raw_cwd = payload.get("cwd")
    query: dict[str, object] = {
        "kind": "exact_action",
        "harness": harness,
        "tool_name": tool_name,
        "command": pre_tool_command(payload),
        "tool_input": _tool_input_pairs(payload),
        "payload_cwd": raw_cwd if isinstance(raw_cwd, str) and raw_cwd.strip() else None,
        "workspace": _text(workspace),
        "home_dir": _text(home_dir),
        "environment": {key: value for key, value in os.environ.items() if isinstance(value, str)},
        "facts": _facts(native_result),
        "policy_binding": _policy_binding(harness, native_result, native_receipt),
        "extension_control_digest": current_extension_control_binding_digest(),
        "budget_ms": _BUDGET_MS,
    }
    raw_tool_input = _raw_tool_input(payload)
    if raw_tool_input is not None:
        query["raw_tool_input"] = raw_tool_input
    return query


def native_exact_action(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
    guard_home: Path | None = None,
) -> tuple[str | None, str | None]:
    """Return a usable context token or a specific refusal; neither authorizes execution alone."""
    try:
        query = _exact_query(
            harness=harness,
            tool_name=tool_name,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
        )
        reply = _answer(query, guard_home)
    except (NativeExactActionError, OSError, RuntimeError, TypeError, ValueError) as error:
        # Only the error class is logged: the query holds environment and command text.
        _LOGGER.warning("native exact-action ask failed closed: %s", type(error).__name__)
        return None, UNPROVEN_LAUNCH
    token, reason = reply["token"], reply["once_only_reason"]
    if (token is None) == (reason is None):
        return None, UNPROVEN_LAUNCH
    return token, reason


def native_launch_evidence(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
    guard_home: Path | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Observe code/configuration without minting any execution or persistence capability."""
    try:
        action = _exact_query(
            harness=harness,
            tool_name=tool_name,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
        )
        reply = _answer({"kind": "launch_evidence", "action": action}, guard_home)
        return reply["evidence"], reply["unavailable_reason"]
    except (NativeExactActionError, OSError, RuntimeError, TypeError, ValueError) as error:
        _LOGGER.warning("native launch-evidence ask failed closed: %s", type(error).__name__)
        return None, UNPROVEN_LAUNCH


def _execution_environment(payload: Mapping[str, object]) -> dict[str, object] | None:
    stamped = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    return dict(stamped) if isinstance(stamped, Mapping) else None


def native_review_binding(
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path | None = None,
) -> str | None:
    """Bind a short-lived retry to Rust-owned request and decision evidence."""

    raw_cwd = payload.get("cwd")
    try:
        query: dict[str, object] = {
            "kind": "review_binding",
            "harness": harness,
            "command": pre_tool_command(payload),
            "cwd": raw_cwd if isinstance(raw_cwd, str) and raw_cwd.strip() else None,
            "workspace_bound": workspace is not None,
            "facts": _facts(native_result),
            "receipt": dict(native_receipt) if isinstance(native_receipt, Mapping) else None,
            "policy_binding": _policy_binding(harness, native_result, native_receipt),
            # A plain `git push origin <branch>` binds to the native push proof,
            # which runs in the agent's own stamped environment, never this
            # process's.
            "workspace": _text(workspace),
            "execution_environment": _execution_environment(payload),
        }
        return _answer(query, guard_home)["binding"]
    except (NativeExactActionError, OSError, RuntimeError, TypeError, ValueError) as error:
        _LOGGER.warning("native review-binding ask failed closed: %s", type(error).__name__)
        return None


def _validate_exact_action(payload: dict[str, Any]) -> None:
    reason = payload["once_only_reason"]
    if reason is not None and reason not in _ONCE_ONLY_REASONS:
        raise NativeExactActionError(_OPERATION.invalid)


def _answer(query: Mapping[str, object], guard_home: Path | None) -> dict[str, Any]:
    if query["kind"] == "launch_evidence":
        return _decide(
            query,
            guard_home,
            {"evidence": (dict, type(None)), "unavailable_reason": (str, type(None))},
            _validate_launch_evidence,
            operation=_OPERATION,
            max_request_bytes=_MAX_REQUEST_BYTES,
            slots=EXACT_ACTION_ASK_SLOTS,
        )
    is_exact = query["kind"] == "exact_action"
    fields: dict[str, Any] = (
        {"token": (str, type(None)), "once_only_reason": (str, type(None))}
        if is_exact
        else {"binding": (str, type(None))}
    )
    return _decide(
        query,
        guard_home,
        fields,
        _validate_exact_action if is_exact else None,
        operation=_OPERATION,
        max_request_bytes=_MAX_REQUEST_BYTES,
        slots=EXACT_ACTION_ASK_SLOTS,
    )


def _validate_launch_evidence(payload: dict[str, Any]) -> None:
    evidence, reason = payload["evidence"], payload["unavailable_reason"]
    if evidence is None:
        if reason not in _ONCE_ONLY_REASONS:
            raise NativeExactActionError(_OPERATION.invalid)
        return
    expected = {
        "schema": "guard-native-launch-evidence.v1",
        "code_identity_complete": False,
        "unknown_edges": ["unverified_code_closure"],
        "risk_verdict": "not_evaluated",
        "execution_binding": "unavailable",
        "duration": "none",
        "scope": "observed_invocation",
        "can_run_once": False,
        "can_persist": False,
    }
    if reason is not None or set(evidence) != {*expected, "inventory_sha256"}:
        raise NativeExactActionError(_OPERATION.invalid)
    if any(evidence[key] != value or type(evidence[key]) is not type(value) for key, value in expected.items()):
        raise NativeExactActionError(_OPERATION.invalid)
    digest = evidence["inventory_sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise NativeExactActionError(_OPERATION.invalid)


__all__ = [
    "GUARD_CONTROL_ACTION_TYPES",
    "NATIVE_EXACT_ACTION_FEATURE",
    "UNPROVEN_LAUNCH",
    "NativeExactActionError",
    "launch_cwd",
    "native_exact_action",
    "native_launch_evidence",
    "native_review_binding",
]
