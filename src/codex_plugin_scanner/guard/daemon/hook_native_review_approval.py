"""Queue native PreToolUse pauses while Rust remains the semantic authority."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shlex
import sqlite3
import uuid
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import GuardApprovalRequest, format_local_http_origin
from ..native_decision_receipt import validate_native_decision_receipt
from ..runtime.actions import normalize_harness_payload
from .hook_native_review_binding import (
    native_review_claimed_allow,
    native_review_matching_allow,
    native_review_policy_binding,
)
from .hook_request_parsing import pre_tool_command
from .hook_worker_responses import (
    harness_json_from_native_pre_tool,
    harness_json_from_native_pre_tool_review,
)

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

_DEFAULT_APPROVAL_CENTER_PORT = 4781
_MUTABLE_CODE_LAUNCHERS = {
    ".",
    "source",
    "sh",
    "bash",
    "dash",
    "ash",
    "zsh",
    "ksh",
    "fish",
    "node",
    "bun",
    "deno",
    "ruby",
    "perl",
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "bunx",
    "make",
    "just",
    "task",
    "cargo",
    "uv",
    "uvx",
    "pipx",
}
_PYTHON_LAUNCHER = re.compile(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?$", re.IGNORECASE)
_FILE_BACKED_PROGRAM_COMMANDS = {"sed", "grep", "egrep", "fgrep", "rg"}
_DIRECT_REUSABLE_COMMANDS = {
    "cat",
    "head",
    "tail",
    "sed",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "stat",
    "wc",
    "base64",
    "xxd",
    "od",
    "hexdump",
    "strings",
}
_NATIVE_DIGEST = re.compile(r"[0-9a-f]{64}")
_NATIVE_IDENTITY_TOKEN = re.compile(r"[a-z0-9_-]{1,128}")
_SHELL_PUNCTUATION = frozenset(";&|<>")


def pause_native_pre_tool_for_approval(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path | None = None,
    deadline: float | None = None,
    claim_saved_approval: bool = True,
    claimed_saved_allow_hash: str | None = None,
    claimed_approval_request_id: str | None = None,
) -> dict[str, object]:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        failed = dict(native_result)
        failed.update(
            decision="deny",
            minimum_action="block",
            policy_action="block",
            reason_code="native_review_policy_binding_invalid",
            reason="HOL Guard could not bind this review to its native policy.",
        )
        return harness_json_from_native_pre_tool(harness, failed)
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    identity = _native_review_binding(
        harness,
        payload,
        native_result,
        native_receipt,
        workspace,
    )
    if claimed_saved_allow_hash is not None and native_review_claimed_allow(
        store,
        harness=harness,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        workspace=workspace,
        identity=identity,
        claimed_saved_allow_hash=claimed_saved_allow_hash,
        claimed_approval_request_id=claimed_approval_request_id,
        claim_saved_approval=claim_saved_approval,
    ):
        allowed = dict(native_result)
        allowed["decision"] = "allow"
        allowed["minimum_action"] = "allow"
        allowed["policy_action"] = "allow"
        response = harness_json_from_native_pre_tool(harness, allowed)
        response["approval_reuse_status"] = "accepted"
        return response
    if claim_saved_approval and native_review_matching_allow(
        store,
        harness=harness,
        tool_name=tool_name,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        launch_target=launch_target,
        workspace=workspace,
        identity=identity,
    ):
        allowed = dict(native_result)
        allowed["decision"] = "allow"
        allowed["minimum_action"] = "allow"
        allowed["policy_action"] = "allow"
        response = harness_json_from_native_pre_tool(harness, allowed)
        response["approval_reuse_status"] = "accepted"
        return response
    from ..blocked_request_mode import asks_for_approval, safe_alternative_reason
    from ..config import load_guard_config

    try:
        ask = asks_for_approval(load_guard_config(guard_home, workspace=workspace))
    except (OSError, RuntimeError, TypeError, ValueError):
        ask = False
    if not ask:
        # The agent stays on the silent block. The inbox row is a separate record.
        queued = queue_native_pre_tool_review(
            store,
            harness=harness,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            guard_home=guard_home,
            home_dir=home_dir,
            deadline=deadline,
        )
        if queued is None:
            _LOGGER.warning("Silent review blocked without an inbox row for %s", harness)
        else:
            _record_silent_native_review_event(store, queued)
        blocked = dict(native_result)
        blocked.update(
            decision="deny",
            minimum_action="block",
            policy_action="block",
            reason=safe_alternative_reason(str(native_result.get("reason") or "HOL Guard blocked this action.")),
        )
        response = harness_json_from_native_pre_tool(harness, blocked)
        response["prompted"] = False
        response["blocked_request_mode"] = "safe-alternative"
        return response

    queued = queue_native_pre_tool_review(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        guard_home=guard_home,
        home_dir=home_dir,
        deadline=deadline,
    )
    if queued is None:
        failed = dict(native_result)
        failed["decision"] = "deny"
        failed["minimum_action"] = "block"
        failed["policy_action"] = "block"
        failed["reason_code"] = "native_review_queue_failed"
        failed["reason"] = "HOL Guard could not record this review for approval."
        return harness_json_from_native_pre_tool(harness, failed)
    response = harness_json_from_native_pre_tool_review(
        harness,
        native_result,
        approval=queued,
        guard_home=guard_home,
    )
    response["prompted"] = True
    response["approval_center_url"] = _native_review_approval_center_url(store)
    return response


def _record_silent_native_review_event(store: object, queued: Mapping[str, object]) -> None:
    """Write the local creation event for a silent inbox row. Do not mark a prompt as shown."""

    add_event = getattr(store, "add_event", None)
    if not callable(add_event):
        return
    created_at = queued.get("created_at")
    timestamp = created_at if isinstance(created_at, str) and created_at else datetime.now(tz=timezone.utc).isoformat()
    try:
        add_event(
            "approval.created",
            {
                "request_id": queued.get("request_id"),
                "harness": queued.get("harness"),
                "artifact_id": queued.get("artifact_id"),
                "artifact_name": queued.get("artifact_name"),
                "artifact_type": queued.get("artifact_type"),
                "policy_action": queued.get("policy_action"),
                "recommended_scope": queued.get("recommended_scope"),
                "source_scope": queued.get("source_scope"),
                "workspace": queued.get("workspace"),
                "publisher": queued.get("publisher"),
            },
            timestamp,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Silent review inbox row saved without approval.created (%s)", type(error).__name__)


def queue_native_pre_tool_review(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        return None
    persist = getattr(store, "add_approval_request", None)
    lookup = getattr(store, "get_approval_request", None)
    if not callable(persist) or not callable(lookup):
        return None
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    request_id = uuid.uuid4().hex
    artifact_id = _native_review_artifact_id(harness, tool_name)
    approval_center_url = _native_review_approval_center_url(store)
    approval_url = f"{approval_center_url}/requests/{request_id}"
    reason = str(native_result.get("reason") or "HOL Guard requires review before this action can execute.")
    binding = _native_review_binding(harness, payload, native_result, native_receipt, workspace)
    try:
        action_envelope = _native_review_action_envelope(
            harness=harness,
            payload=payload,
            native_receipt=native_receipt,
            workspace=workspace,
            guard_home=guard_home,
            home_dir=home_dir,
            deadline=deadline,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        # Never make an action approvable when its details could not be safely presented.
        # Exception messages can contain private tool input; log only the error class.
        _LOGGER.warning("Native review presentation failed for %s (%s)", request_id, type(error).__name__)
        return None
    if action_envelope is None:
        _LOGGER.warning("Native review presentation failed for %s (ValueError)", request_id)
        return None
    request = GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=artifact_id,
        artifact_name=tool_name,
        artifact_hash=binding or request_id,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace if workspace is not None else guard_home),
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=approval_url,
        workspace=str(workspace) if workspace is not None else None,
        artifact_type="tool_call",
        launch_target=launch_target,
        risk_summary=reason,
        action_envelope_json=action_envelope,
    )
    try:
        persisted_id = persist(request, datetime.now(tz=timezone.utc).isoformat())
        stored = lookup(persisted_id)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    return stored if isinstance(stored, dict) else None


def _native_review_artifact_id(harness: str, tool_name: str) -> str:
    return f"{harness}:native-pretool:{tool_name}"


def record_claude_permission_notice_for_native_review(
    store: GuardStore,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
) -> None:
    """Persist the Claude permission-prompt notice for a queued native review."""
    from ..cli.commands_support_hook_state import _record_claude_permission_notice
    from ..models import GuardArtifact

    tool_name = _native_review_tool_name(payload)
    command = pre_tool_command(payload)
    artifact_id = _native_review_artifact_id(harness, tool_name)
    binding = _native_review_binding(harness, payload, native_result, native_receipt, workspace)
    metadata: dict[str, object] = {"raw_command_text": command} if command else {}
    artifact = GuardArtifact(
        artifact_id=artifact_id,
        name=tool_name,
        harness=harness,
        artifact_type="tool_call",
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace if workspace is not None else guard_home),
        command=command,
        metadata=metadata,
    )
    _record_claude_permission_notice(
        store=store,
        payload=dict(payload),
        reason=str(native_result.get("reason") or "HOL Guard requires review before this action can execute."),
        artifact=artifact,
        artifact_hash=binding or artifact_id,
    )


def _command_reuse_is_payload_bound(command: str) -> bool:
    """Allow retry reuse only when mutable local code cannot hide behind argv."""

    if any(marker in command for marker in ("`", "$(", "${", "\n", "\r")):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens:
        return False
    # shlex groups adjacent punctuation, so reject every punctuation-only token
    # rather than a fixed operator list. This covers |&, <<<, <>, >| and future
    # combinations without accidentally treating them as part of argv.
    if any(token and all(char in _SHELL_PUNCTUATION for char in token) for token in tokens):
        return False
    # Leading environment assignments can change executable lookup or loader
    # behavior without changing the apparent command. They are never reusable.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        return False
    executable = tokens[0]
    if "/" in executable or "\\" in executable or executable.startswith("."):
        return False
    basename = Path(executable).name.lower()
    if basename in _MUTABLE_CODE_LAUNCHERS or _PYTHON_LAUNCHER.fullmatch(basename):
        return False
    if basename in _FILE_BACKED_PROGRAM_COMMANDS and _uses_file_backed_program(tokens[1:]):
        return False
    if basename == "rg" and _rg_executes_unreviewed_preprocessor(tokens[1:]):
        return False
    return basename in _DIRECT_REUSABLE_COMMANDS


def _rg_executes_unreviewed_preprocessor(tokens: list[str]) -> bool:
    """Reject ripgrep launches that run a mutable preprocessor."""

    return any(token == "--pre" or token.startswith("--pre=") for token in tokens)


def _uses_file_backed_program(tokens: list[str]) -> bool:
    """Reject programs or patterns loaded from a mutable file instead of argv."""

    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in {"-f", "--file", "--fi", "--fil"}:
            return True
        if token.startswith(("--file=", "--fi=", "--fil=")):
            return True
        if token in {"-e", "--expression", "--regexp"}:
            skip_next = True
            continue
        if token.startswith("-") and not token.startswith("--") and token != "-":
            cluster = token[1:]
            for index, flag in enumerate(cluster):
                if flag == "e":
                    skip_next = index == len(cluster) - 1
                    break
                if flag == "f":
                    return True
    return False


def _native_review_binding(
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
) -> str | None:
    """Bind a short-lived retry to Rust-owned request and decision evidence."""

    command = pre_tool_command(payload)
    action = native_result.get("action")
    action_type = action.get("action_type") if isinstance(action, Mapping) else None
    if action_type == "package":
        return None
    if command is not None and not _command_reuse_is_payload_bound(command):
        return None
    if not isinstance(native_receipt, Mapping):
        return None
    if (
        native_receipt.get("schema") != "guard-native-hook-decision-receipt.v1"
        or native_receipt.get("version") != 1
        or native_receipt.get("authority") != "rust"
        or native_receipt.get("harness") != harness
        or native_receipt.get("event_name") != "PreToolUse"
        or native_receipt.get("workspace_bound") is not (workspace is not None)
    ):
        return None
    request_digest = native_receipt.get("request_digest")
    if not isinstance(request_digest, str) or _NATIVE_DIGEST.fullmatch(request_digest) is None:
        return None
    decision = str(native_result.get("decision") or "")
    minimum_action = str(native_result.get("minimum_action") or "")
    policy_action = str(native_result.get("policy_action") or "")
    reason_code = str(native_result.get("reason_code") or "")
    if (
        native_receipt.get("decision") != decision
        or native_receipt.get("policy_action") != policy_action
        or native_receipt.get("reason_code") != reason_code
    ):
        return None
    identity_tokens = (decision, minimum_action, policy_action, reason_code)
    if any(_NATIVE_IDENTITY_TOKEN.fullmatch(value) is None for value in identity_tokens):
        return None
    identity = ":".join(("native-review-v4", request_digest, *identity_tokens))
    try:
        policy_binding = native_review_policy_binding(
            harness=harness, native_result=native_result, verified_receipt=native_receipt
        )
    except ValueError:
        return None
    if policy_binding is None:
        return identity
    encoded = json.dumps(policy_binding, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    domain = hashlib.sha256(b"hol-guard.native-review-extension-binding.v1\0" + encoded).hexdigest()
    return f"{identity}:{domain}"


def _native_review_action_envelope(
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
    # Keep only the validated aggregate receipt. Never carry raw hook input
    # through the presentation envelope, and do not alias nested mappings.
    envelope["native_origin_receipt"] = deepcopy(validated)
    return envelope


def _native_review_approval_center_url(store: object) -> str:
    getter = getattr(store, "get_runtime_state", None)
    if callable(getter):
        try:
            state = getter()
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            state = None
        if isinstance(state, dict):
            center = state.get("approval_center_url")
            if isinstance(center, str) and center.strip():
                return center.rstrip("/")
            host = state.get("daemon_host")
            port = state.get("daemon_port")
            if isinstance(host, str) and isinstance(port, int) and port > 0:
                return format_local_http_origin(host, port)
    return format_local_http_origin("127.0.0.1", _DEFAULT_APPROVAL_CENTER_PORT)


def _native_review_tool_name(payload: Mapping[str, object]) -> str:
    for key in ("tool_name", "toolName", "tool"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "tool"


def _native_review_launch_target(payload: Mapping[str, object]) -> str:
    command = pre_tool_command(payload)
    if command is not None:
        return command
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping):
        for key in ("url", "path", "file_path", "target"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return f"tool:{_native_review_tool_name(payload)}"


__all__ = [
    "pause_native_pre_tool_for_approval",
    "queue_native_pre_tool_review",
    "record_claude_permission_notice_for_native_review",
]
