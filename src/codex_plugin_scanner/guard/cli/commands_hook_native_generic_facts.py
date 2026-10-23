"""Facts the generic hook transport hands the resident decision op.

The resident owns every decision (see ``native_hook_decision``). This module
only gathers inputs: payload fields as given, and the classifier verdicts the
resident asks for by name. A classifier runs only when the resident needs its
verdict, and its boolean is a fact, not a decision.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path

_EVENT_KEYS = ("event", "hook_event_name", "hookEventName", "hook_name")
# The resident refuses a tool input above 64 KiB, and the hook-decision envelope
# is capped at 256 KiB; an oversized request is omitted rather than sent.
_MAX_TOOL_INPUT_BYTES = 64 * 1024
_MAX_NATIVE_REQUEST_BYTES = 128 * 1024


def hook_classifiers(
    *,
    guard_home: Path | None,
    home_dir: Path | None,
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
) -> dict[str, Callable[[str | None], bool]]:
    """Classifier verdicts keyed by the fact name the resident requests."""

    def _prompt_text() -> str | None:
        prompt_text = payload.get("prompt")
        return prompt_text if isinstance(prompt_text, str) else None

    def prompt_request_free(_event: str | None) -> bool:
        from ..native_prompt import extract_prompt_requests

        prompt_text = _prompt_text()
        if prompt_text is None:
            return False
        return not extract_prompt_requests(prompt_text, guard_home=guard_home)

    # The scans below run in the caller's own resident, and a resident that
    # cannot answer leaves the prompt unclassified rather than ending the hook:
    # an unanswered observation is not a clear one.
    def prompt_credential_free(_event: str | None) -> bool:
        from ..native_context import bound_context_digest_home
        from ..native_sensitive_request import NativeSensitiveRequestError
        from .commands_support_codex_paths import _codex_prompt_credential_file_artifact

        prompt_text = _prompt_text()
        if prompt_text is None:
            return False
        try:
            with bound_context_digest_home(guard_home):
                return (
                    _codex_prompt_credential_file_artifact(
                        prompt_text=prompt_text,
                        cwd=runtime_workspace,
                        config_path="<runtime>",
                    )
                    is None
                )
        except NativeSensitiveRequestError:
            return False

    def prompt_attachment_free(_event: str | None) -> bool:
        from ..native_context import bound_context_digest_home
        from ..native_sensitive_request import NativeSensitiveRequestError
        from .commands_support_codex_prompt_attachments import _codex_prompt_attachment_artifact

        prompt_text = _prompt_text()
        if prompt_text is None:
            return False
        if home_dir is None:
            return True
        try:
            with bound_context_digest_home(guard_home):
                return (
                    _codex_prompt_attachment_artifact(
                        prompt_text=prompt_text,
                        home_dir=home_dir,
                        config_path="<runtime>",
                    )
                    is None
                )
        except NativeSensitiveRequestError:
            return False

    def post_tool_read_only_inspection(_event: str | None) -> bool:
        from .commands_support_codex_commands import _codex_post_tool_command_is_read_only_source_inspection

        return _codex_post_tool_command_is_read_only_source_inspection(
            payload=dict(payload),
            cwd=runtime_workspace,
            home_dir=home_dir,
        )

    def apply_patch_targets_non_sensitive(_event: str | None) -> bool:
        from .commands_support_apply_patch_policy import apply_patch_targets_are_non_sensitive

        return apply_patch_targets_are_non_sensitive(
            home_dir=home_dir,
            payload=payload,
            runtime_workspace=runtime_workspace,
        )

    return {
        "prompt_request_free": prompt_request_free,
        "prompt_credential_free": prompt_credential_free,
        "prompt_attachment_free": prompt_attachment_free,
        "post_tool_read_only_inspection": post_tool_read_only_inspection,
        "apply_patch_targets_non_sensitive": apply_patch_targets_non_sensitive,
    }


def _native_request(
    payload: Mapping[str, object],
    runtime_workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """The raw tool call and host facts the resident classifies itself.

    Nothing here is a verdict. When the host cannot be observed the request is
    omitted and the resident treats every dependent verdict as not benign.
    """

    from .. import native_git_execution_safety as git_safety
    from ..native_codex_tool_output import _environment_snapshot

    try:
        host: dict[str, object] = {
            "process_cwd": os.getcwd(),
            "home": str(Path.home()),
            "account_home": git_safety._account_home_directory(),
            "groups": git_safety._process_groups(),
            "environment": _environment_snapshot(),
            "git_executable": shutil.which("git"),
        }
    except (OSError, RuntimeError):
        return None
    tool_input = payload.get("tool_input", payload.get("arguments"))
    if _encoded_size(tool_input) > _MAX_TOOL_INPUT_BYTES:
        return None
    request: dict[str, object] = {
        "tool_name": payload.get("tool_name"),
        "tool_input": tool_input,
        "cwd": None if runtime_workspace is None else str(runtime_workspace),
        "home_dir": None if home_dir is None else str(home_dir),
        "host": host,
    }
    control_snapshot = _control_snapshot()
    if control_snapshot is not None:
        request["control_snapshot"] = control_snapshot
    return request if _encoded_size(request) <= _MAX_NATIVE_REQUEST_BYTES else None


def _encoded_size(value: object) -> int:
    try:
        return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return _MAX_NATIVE_REQUEST_BYTES + 1


def _control_snapshot() -> dict[str, object] | None:
    """The active extension-control layers and health, as observed (not a verdict)."""

    from ..runtime.extension_control_runtime import _layer_payload, current_extension_control_snapshot

    snapshot = current_extension_control_snapshot()
    if snapshot is None:
        return None
    return {
        "health": snapshot.health.value,
        "layers": sorted((_layer_payload(layer) for layer in snapshot.layers), key=lambda layer: str(layer["kind"])),
    }


def composition_inputs(
    *,
    cli_action: object,
    canonical_harness: str,
    configured_action: object,
    has_command_text: bool,
    has_configured_override: bool,
    has_narrow_override: bool,
    harness: str,
    home_dir: Path | None,
    native_edge_result: Mapping[str, object] | None,
    payload: Mapping[str, object],
    runtime_artifact_checked: bool,
    runtime_workspace: Path | None,
) -> dict[str, object]:
    """Payload and configuration facts for the resident composition query."""

    from .commands_support_runtime_artifacts import _hook_event_name

    prompt = payload.get("prompt")
    # Only PreToolUse verdicts read the raw tool call; other events skip the host probes.
    native_request = (
        _native_request(payload, runtime_workspace, home_dir)
        if _hook_event_name(dict(payload)) == "PreToolUse"
        else None
    )
    inputs: dict[str, object] = {
        "harness": harness,
        "canonical_harness": canonical_harness,
        "event_fields": {key: payload[key] for key in _EVENT_KEYS if key in payload},
        "tool_name_text": str(payload.get("tool_name", "")),
        "configured_action": configured_action,
        "has_configured_override": has_configured_override,
        "has_narrow_override": has_narrow_override,
        "runtime_artifact_checked": runtime_artifact_checked,
        "prompt_nonblank": isinstance(prompt, str) and bool(prompt.strip()),
        "has_command_text": has_command_text,
        "cli_action": cli_action,
        "has_payload_action": "policy_action" in payload,
        "payload_action": payload.get("policy_action"),
        "native_edge": (
            {key: native_edge_result.get(key) for key in ("policy_action", "minimum_action", "decision", "reason_code")}
            if isinstance(native_edge_result, Mapping)
            else None
        ),
        "daemon_status": payload.get("daemon_status"),
        "fail_mode": payload.get("fail_mode"),
        "permission_decision_reason": payload.get("permission_decision_reason"),
    }
    if native_request is not None:
        # Omitted, never null: the resident digests its canonical form of the request.
        inputs["native_request"] = native_request
    return inputs


__all__ = ["composition_inputs", "hook_classifiers"]
