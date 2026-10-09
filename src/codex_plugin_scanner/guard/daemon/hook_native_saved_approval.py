"""Bind daemon native reviews to a stable exact-action identity.

The native once-retry binding embeds the Rust request digest, which changes on
every hook delivery. An "Always" decision needs an identity that survives new
sessions and tool-use ids while still changing whenever the code that would run,
the reviewed command, or the Rust rules that judged it change.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
from collections.abc import Mapping
from pathlib import Path

from ..runtime.approval_context import (
    build_approval_context_token,
    build_runtime_launch_identity,
    parse_approval_context_token,
    runtime_launch_identity_is_reusable,
)
from ..runtime.local_cli_runner import LOCAL_BIN_RUNNERS, runner_local_bin
from ..store_policy_decision import policy_decision_hash_exists
from .hook_native_review_binding import native_review_policy_binding
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import harness_json_from_native_pre_tool

_LOGGER = logging.getLogger(__name__)

EXACT_ACTION_CONTEXT_TOKEN_KEY = "exact_context_token"
_NATIVE_EXACT_ACTION_POLICY_VERSION = "native-exact-action-v1"
# Runners whose target is accepted only when it resolves to a content-hashed
# project-local binary. Registry and cache fetches stay once-only.
_LOCAL_BIN_RUNNERS = LOCAL_BIN_RUNNERS
# Interpreters, task runners and wrappers beyond the once-retry list whose
# launch identity does not bind the code they load or run.
_EXTRA_MUTABLE_LAUNCHERS = frozenset(
    {
        "nodejs",
        "php",
        "go",
        "tsx",
        "ts-node",
        "vite-node",
        "jiti",
        "esno",
        "babel-node",
        "nodemon",
        "zx",
        "docker",
        "podman",
        # git runs aliases, hooks and config-defined helpers from mutable files.
        "git",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "xargs",
        "parallel",
        "env",
        "sudo",
        "doas",
        "nohup",
        "timeout",
        "watch",
        "osascript",
        "pwsh",
        "powershell",
        "java",
        "dotnet",
        "lua",
        "rscript",
        "julia",
        "swift",
        "r",
        # Tools that load project code or config the token cannot bind.
        *("terraform", "tofu", "terragrunt", "pulumi", "ansible", "ansible-playbook"),
        *("pytest", "py.test", "tox", "nox", "jest", "vitest", "mocha", "rake", "gradle", "mvn"),
        # GNU sed can run shell commands from its script (``e``).
        "sed",
    }
)
_FIND_EXEC_OPTIONS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
# Existing file operands are content-bound so an edited script, program or
# input re-prompts. Larger or more numerous operands stay once-only.
_MAX_BOUND_OPERANDS = 16
_MAX_BOUND_OPERAND_BYTES = 4_194_304


def native_exact_action_token(
    *,
    harness: str,
    tool_name: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> str | None:
    """Return a persistent exact-action token, or ``None`` when only once is safe."""

    if not _native_review_is_overridable(native_result):
        return None
    command = pre_tool_command(payload)
    if command is None or not command.strip():
        return None
    try:
        policy_binding = native_review_policy_binding(
            harness=harness, native_result=native_result, verified_receipt=native_receipt
        )
    except ValueError:
        return None
    if policy_binding is None:
        return None
    cwd = _launch_cwd(payload, workspace)
    if cwd is None:
        return None
    try:
        launch = _launch_identity(command, cwd=cwd, home_dir=home_dir)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if launch is None:
        return None
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    try:
        token = build_approval_context_token(
            identity={
                "harness": harness,
                "tool_name": tool_name,
                "workspace": str(workspace.resolve()) if workspace is not None else None,
                "cwd": str(cwd),
                "launch": launch,
            },
            content={"command": command},
            capabilities={
                "action_type": action_type if isinstance(action_type, str) else None,
                "minimum_action": str(native_result.get("minimum_action") or ""),
                "policy_action": str(native_result.get("policy_action") or ""),
                "reason_code": str(native_result.get("reason_code") or ""),
            },
            policy={
                "version": _NATIVE_EXACT_ACTION_POLICY_VERSION,
                "rule_digest": policy_binding["rule_digest"],
                "command_extensions": policy_binding["command_extensions"],
            },
            sandbox={"required": native_result.get("minimum_action") == "sandbox-required"},
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return token if parse_approval_context_token(token) is not None else None


def native_saved_decision_response(
    store: object,
    *,
    harness: str,
    token: str | None,
    artifact_id: str,
    native_result: Mapping[str, object],
    workspace: Path | None,
) -> dict[str, object] | None:
    """Apply a saved exact-action allow or block; ``None`` keeps the review flow."""

    if token is None:
        return None
    lookup = getattr(store, "resolve_policy_decision_lookup", None)
    if not callable(lookup):
        return None
    try:
        # The full lookup refreshes integrity state under a write lock. Skip it
        # on the hot hook path unless an exact decision for this token exists.
        if not policy_decision_hash_exists(store, harness=harness, artifact_id=artifact_id, artifact_hash=token):
            return None
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # Without a probe result the action still goes to a human review.
        _LOGGER.warning("Native saved approval probe failed (%s)", type(error).__name__)
        return None
    try:
        result = lookup(
            harness,
            artifact_id,
            artifact_hash=token,
            workspace=str(workspace) if workspace is not None else None,
            consume_one_shot=False,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # A saved decision exists but could not be read; it may be a block.
        _LOGGER.warning("Native saved approval lookup failed (%s)", type(error).__name__)
        return _saved_block_response(
            harness,
            native_result,
            reason_code="saved_exact_action_unreadable",
            reason="HOL Guard could not read your saved decision for this exact action.",
        )
    if not isinstance(result, Mapping) or result.get("ignored_local_integrity"):
        return None
    decision = result.get("decision")
    if not isinstance(decision, Mapping):
        return None
    if (
        decision.get("scope") != "artifact"
        or decision.get("artifact_id") != artifact_id
        or decision.get("artifact_hash") != token
    ):
        return None
    action = decision.get("action")
    if action == "block":
        return _saved_block_response(
            harness,
            native_result,
            reason_code="saved_exact_action_block",
            reason="You chose to always block this exact action in HOL Guard.",
        )
    if action != "allow" or decision.get("source") != "approval-gate" or decision.get("expires_at"):
        return None
    if not _native_review_is_overridable(native_result):
        return None
    allowed = dict(native_result)
    allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
    response = harness_json_from_native_pre_tool(harness, allowed)
    response["approval_reuse_status"] = "accepted"
    return response


def native_saved_review_response(
    store: object,
    *,
    harness: str,
    tool_name: str,
    artifact_id: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """Return the saved exact-action outcome for a paused native review."""

    token = native_exact_action_token(
        harness=harness,
        tool_name=tool_name,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        home_dir=home_dir,
    )
    return native_saved_decision_response(
        store,
        harness=harness,
        token=token,
        artifact_id=artifact_id,
        native_result=native_result,
        workspace=workspace,
    )


def _saved_block_response(
    harness: str, native_result: Mapping[str, object], *, reason_code: str, reason: str
) -> dict[str, object]:
    blocked = dict(native_result)
    blocked.update(
        decision="deny",
        minimum_action="block",
        policy_action="block",
        reason_code=reason_code,
        reason=reason,
    )
    response = harness_json_from_native_pre_tool(harness, blocked)
    response["approval_reuse_status"] = "blocked"
    return response


def _native_review_is_overridable(native_result: Mapping[str, object]) -> bool:
    if native_result.get("policy_action") not in {"review", "require-reapproval"}:
        return False
    if native_result.get("minimum_action") not in {"review", "require-reapproval"}:
        return False
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    return action_type not in {"guard_control", "guard-control", "guard_control_operation", "package"}


def _launch_identity(command: str, *, cwd: Path, home_dir: Path | None) -> dict[str, object] | None:
    from ..runtime.command_model import parse_shell_command
    from ..runtime.command_tokens import executable_name
    from ..runtime.local_cli_identity import unlisted_cli_invocation_is_safe

    try:
        model = parse_shell_command(command, cwd=cwd, home_dir=home_dir)
    except ValueError:
        return None
    if not unlisted_cli_invocation_is_safe(model):
        return None
    segment = model.segments[0]
    name = (executable_name(segment.executable) or "").lower()
    for suffix in (".exe", ".cmd"):
        name = name.removesuffix(suffix)
    arguments = list(segment.arguments)
    operands = _file_operand_hashes(arguments, cwd=cwd)
    if operands is None:
        return None
    if name in _LOCAL_BIN_RUNNERS:
        local_bin = _runner_local_bin(command, name, arguments, cwd=cwd, home_dir=home_dir)
        if local_bin is None:
            return None
        return {"kind": "runner-local-bin", "runner": name, "local_bin": local_bin, "operands": operands}
    if _loads_unbound_code(name, arguments):
        return None
    launch = build_runtime_launch_identity(
        segment.executable,
        args=segment.arguments,
        structured_command=True,
        cwd=cwd,
        home_dir=home_dir,
    )
    if not runtime_launch_identity_is_reusable(launch):
        return None
    return {"kind": "direct", "identity": launch, "operands": operands}


def _loads_unbound_code(name: str, arguments: list[str]) -> bool:
    from .hook_native_review_approval import (
        _FILE_BACKED_PROGRAM_COMMANDS,
        _rg_executes_unreviewed_preprocessor,
        _uses_file_backed_program,
    )

    if _is_mutable_launcher(name):
        return True
    if name == "find" and any(argument in _FIND_EXEC_OPTIONS for argument in arguments):
        return True
    if name in _FILE_BACKED_PROGRAM_COMMANDS and _uses_file_backed_program(arguments):
        return True
    return name == "rg" and _rg_executes_unreviewed_preprocessor(arguments)


def _is_mutable_launcher(name: str) -> bool:
    from .hook_native_review_approval import _MUTABLE_CODE_LAUNCHERS, _PYTHON_LAUNCHER

    return name in _MUTABLE_CODE_LAUNCHERS or name in _EXTRA_MUTABLE_LAUNCHERS or bool(_PYTHON_LAUNCHER.fullmatch(name))


def _runner_local_bin(
    command: str, runner: str, arguments: list[str], *, cwd: Path, home_dir: Path | None
) -> dict[str, object] | None:
    # A local interpreter or task runner loads code its identity does not bind.
    return runner_local_bin(command, runner, arguments, cwd=cwd, home_dir=home_dir, reject_target=_is_mutable_launcher)


def _file_operand_hashes(arguments: list[str], *, cwd: Path) -> list[dict[str, str]] | None:
    """Hash existing regular-file operands, or ``None`` when they cannot be bound."""

    bound: list[dict[str, str]] = []
    for argument in arguments:
        value = argument.partition("=")[2] if argument.startswith("-") else argument
        if not value or value.startswith("-"):
            continue
        candidate = Path(value) if os.path.isabs(value) else cwd / value
        try:
            if not candidate.is_file():
                continue
            if candidate.stat().st_size > _MAX_BOUND_OPERAND_BYTES or len(bound) >= _MAX_BOUND_OPERANDS:
                return None
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        except (OSError, ValueError):
            return None
        bound.append({"argument": argument, "sha256": digest})
    return bound


def _launch_cwd(payload: Mapping[str, object], workspace: Path | None) -> Path | None:
    raw = payload.get("cwd")
    candidate = Path(raw) if isinstance(raw, str) and raw.strip() else workspace
    if candidate is None or not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    return resolved if os.path.isdir(resolved) else None


__all__ = [
    "EXACT_ACTION_CONTEXT_TOKEN_KEY",
    "native_exact_action_token",
    "native_saved_decision_response",
    "native_saved_review_response",
]
