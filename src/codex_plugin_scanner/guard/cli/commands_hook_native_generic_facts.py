"""Facts the generic hook transport hands the resident decision op.

The resident owns every decision (see ``native_hook_decision``). This module
only gathers inputs: payload fields as given, and the classifier verdicts the
resident asks for by name. A classifier runs only when the resident needs its
verdict, and its boolean is a fact, not a decision.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

_EVENT_KEYS = ("event", "hook_event_name", "hookEventName", "hook_name")


def hook_classifiers(
    *,
    canonical_harness: str,
    guard_home: Path | None,
    home_dir: Path | None,
    payload: Mapping[str, object],
    runtime_artifact_checked: bool,
    runtime_workspace: Path | None,
) -> dict[str, Callable[[str | None], bool]]:
    """Classifier verdicts keyed by the fact name the resident requests."""

    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input", payload.get("arguments"))

    def prompt_clean(_event: str | None) -> bool:
        from ..native_prompt import extract_prompt_requests
        from .commands_support_codex_paths import _codex_prompt_credential_file_artifact
        from .commands_support_codex_prompt_attachments import _codex_prompt_attachment_artifact

        prompt_text = payload.get("prompt")
        if not isinstance(prompt_text, str) or extract_prompt_requests(prompt_text, guard_home=guard_home):
            return False
        credential = _codex_prompt_credential_file_artifact(
            prompt_text=prompt_text,
            cwd=runtime_workspace,
            config_path="<runtime>",
        )
        if credential is not None:
            return False
        return (
            home_dir is None
            or _codex_prompt_attachment_artifact(
                prompt_text=prompt_text,
                home_dir=home_dir,
                guard_home=guard_home,
                config_path="<runtime>",
            )
            is None
        )

    def post_tool_read_only_inspection(_event: str | None) -> bool:
        from .commands_support_codex_commands import _codex_post_tool_command_is_read_only_source_inspection

        return _codex_post_tool_command_is_read_only_source_inspection(
            payload=dict(payload),
            cwd=runtime_workspace,
            home_dir=home_dir,
        )

    def verified_apply_patch(event: str | None) -> bool:
        from .commands_support_apply_patch_policy import verified_non_sensitive_codex_apply_patch

        return verified_non_sensitive_codex_apply_patch(
            canonical_harness=canonical_harness,
            event_name=event,
            home_dir=home_dir,
            payload=payload,
            runtime_artifact_checked=runtime_artifact_checked,
            runtime_workspace=runtime_workspace,
        )

    def benign_native_file_read(_event: str | None) -> bool:
        from ..runtime.secret_file_requests import is_explicitly_benign_native_file_read_request

        return is_explicitly_benign_native_file_read_request(
            tool_name,
            tool_input,
            cwd=runtime_workspace,
            home_dir=home_dir,
        )

    def benign_tool_action(_event: str | None) -> bool:
        from ..runtime.secret_file_requests import is_explicitly_benign_tool_action_request

        return is_explicitly_benign_tool_action_request(
            tool_name,
            tool_input,
            cwd=runtime_workspace,
            home_dir=home_dir,
        )

    return {
        "prompt_clean": prompt_clean,
        "post_tool_read_only_inspection": post_tool_read_only_inspection,
        "verified_apply_patch": verified_apply_patch,
        "benign_native_file_read": benign_native_file_read,
        "benign_tool_action": benign_tool_action,
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
    native_edge_result: Mapping[str, object] | None,
    payload: Mapping[str, object],
    runtime_artifact_checked: bool,
) -> dict[str, object]:
    """Payload and configuration facts for the resident composition query."""

    prompt = payload.get("prompt")
    return {
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
            {key: native_edge_result.get(key) for key in ("policy_action", "minimum_action", "decision")}
            if isinstance(native_edge_result, Mapping)
            else None
        ),
        "daemon_status": payload.get("daemon_status"),
        "fail_mode": payload.get("fail_mode"),
        "permission_decision_reason": payload.get("permission_decision_reason"),
    }


__all__ = ["composition_inputs", "hook_classifiers"]
