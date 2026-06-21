"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .commands_support_codex_commands import (
        _codex_command_parts_may_read_local_content,
        _codex_command_reads_environment_pipeline,
        _codex_local_secret_source_label,
        _codex_pipeline_segment_may_read_local_content,
        _codex_post_tool_command_is_read_only_source_inspection,
        _codex_post_tool_command_text,
        _codex_shell_split,
        _codex_source_inspection_can_skip_secret_output,
    )
    from .commands_support_codex_paths import (
        _codex_prompt_credential_file_artifact,
        _collect_codex_tool_response_text,
        _with_codex_prompt_display_metadata,
    )
    from .commands_support_codex_reads import _split_codex_safe_read_only_pipeline
    from .commands_support_codex_tool_output_messages import (
        _codex_tool_output_request_summary,
        _codex_tool_output_runtime_summary,
    )
    from .commands_support_hook_payload import _coalesce_string
    from .commands_support_runtime_policy import _runtime_data_flow_summary
    from .commands_support_runtime_resolution import _canonical_harness_name, _runtime_policy_path


from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_codex_commands import (
    _codex_command_parts_may_read_local_content,
    _codex_command_reads_environment_pipeline,
    _codex_local_secret_source_label,
    _codex_pipeline_segment_may_read_local_content,
    _codex_post_tool_command_is_read_only_source_inspection,
    _codex_post_tool_command_text,
    _codex_shell_split,
    _codex_source_inspection_can_skip_secret_output,
)
from .commands_support_codex_reads import _split_codex_safe_read_only_pipeline
from .commands_support_codex_tool_output import (
    _codex_command_captures_combined_shell_output,
    _codex_command_is_focused_pytest_verification,
    _codex_command_references_sensitive_local_source,
    _codex_existing_local_path_match,
    _codex_focused_pytest_can_skip_secret_output,
    _codex_path_token_is_url_path,
    _codex_sensitive_local_source_matches,
    _codex_sensitive_path_matches_in_text,
    _codex_token_is_url,
    _codex_token_prefix_is_url_scheme,
    _codex_url_like_local_path_tokens,
    _dedupe_codex_secret_path_matches,
)
from .commands_support_codex_tool_output_messages import (
    _codex_tool_output_request_summary,
    _codex_tool_output_runtime_reason,
    _codex_tool_output_runtime_summary,
)


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


_HOOK_EVENT_NAME_MAP = {
    "userpromptsubmitted": "UserPromptSubmit",
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
}


def _hook_event_name(payload: dict[str, object]) -> str | None:
    for key in ("event", "hook_event_name", "hookEventName", "hook_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.strip()
            return _HOOK_EVENT_NAME_MAP.get(normalized.lower(), normalized)
    return None


def _artifact_id_from_event(harness: str, payload: dict[str, object]) -> str:
    source_scope = _coalesce_string(payload.get("source_scope"), "project")
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name.strip():
        normalized_tool = tool_name.strip()
        if _canonical_harness_name(harness) == "claude-code":
            from ..adapters.claude_code import claude_hook_fallback_artifact_id

            return claude_hook_fallback_artifact_id(source_scope, normalized_tool)
        return f"{harness}:{source_scope}:{normalized_tool}"
    event_name = _hook_event_name(payload)
    if isinstance(event_name, str) and event_name.strip():
        return f"{harness}:{source_scope}:{event_name.strip().lower()}"
    return f"{harness}:{source_scope}:hook"


def _string_list(value: object | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.strip()]


def _merged_prompt_runtime_artifact(harness: str, artifacts: list[GuardArtifact]) -> GuardArtifact:
    if len(artifacts) == 1:
        return artifacts[0]
    prompt_signals: list[str] = []
    prompt_matched_texts: list[str] = []
    prompt_request_classes: list[str] = []
    prompt_display_texts: list[str] = []
    request_identity = "|".join(sorted(artifact.artifact_id for artifact in artifacts))
    for artifact in artifacts:
        metadata = artifact.metadata
        prompt_signals.extend(_string_list(metadata.get("prompt_signals")))
        matched_text = metadata.get("prompt_matched_text")
        if isinstance(matched_text, str) and matched_text.strip():
            prompt_matched_texts.append(matched_text.strip())
        display_text = metadata.get("prompt_display_text")
        if isinstance(display_text, str) and display_text.strip():
            prompt_display_texts.append(display_text.strip())
        request_class = metadata.get("prompt_request_class")
        if isinstance(request_class, str) and request_class.strip():
            prompt_request_classes.append(request_class.strip())
    deduped_signals = list(dict.fromkeys(prompt_signals))
    deduped_matches = list(dict.fromkeys(prompt_matched_texts))
    deduped_classes = list(dict.fromkeys(prompt_request_classes))
    deduped_display = list(dict.fromkeys(prompt_display_texts))
    request_summary = (
        deduped_display[0] if len(deduped_display) == 1 else "Prompt matches multiple guarded request classes."
    )
    return GuardArtifact(
        artifact_id=f"{harness}:session:prompt:multi:{hashlib.sha256(request_identity.encode('utf-8')).hexdigest()[:24]}",
        name="prompt multi-signal request",
        harness=harness,
        artifact_type="prompt_request",
        source_scope=artifacts[0].source_scope,
        config_path=artifacts[0].config_path,
        metadata={
            "prompt_signals": deduped_signals,
            "prompt_summary": "Prompt matches multiple guarded request classes.",
            "prompt_matched_texts": deduped_matches,
            "prompt_display_text": request_summary,
            "prompt_request_classes": deduped_classes,
            "request_summary": request_summary,
            "runtime_request_summary": request_summary,
        },
    )


def _hook_runtime_artifact(
    *,
    harness: str,
    payload: dict[str, object],
    action_envelope: GuardActionEnvelope | None,
    data_flow_signals: tuple[RiskSignalV2, ...] = (),
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
) -> GuardArtifact | None:
    harness = _canonical_harness_name(harness)
    event_name = _hook_event_name(payload)
    if harness in {"codex", "pi"} and event_name == "PostToolUse":
        output_artifact = _codex_post_tool_output_artifact(
            harness=harness,
            payload=payload,
            config_path=str(_runtime_policy_path(harness, home_dir, workspace)),
            source_scope=_coalesce_string(payload.get("source_scope"), "project"),
            cwd=workspace,
            home_dir=home_dir,
        )
        if output_artifact is not None:
            return output_artifact
        if _codex_post_tool_command_is_read_only_source_inspection(payload=payload, cwd=workspace, home_dir=home_dir):
            return None
    if event_name == "UserPromptSubmit":
        prompt_text = payload.get("prompt")
        if isinstance(prompt_text, str) and prompt_text.strip():
            config_path = str(_runtime_policy_path(harness, home_dir, workspace))
            prompt_detection = HarnessDetection(
                harness=harness,
                installed=True,
                command_available=True,
                config_paths=(config_path,),
                artifacts=(),
            )
            prompt_context = HarnessContext(
                home_dir=home_dir,
                guard_home=guard_home,
                workspace_dir=workspace,
            )
            prompt_requests = extract_prompt_requests(prompt_text)
            if prompt_requests:
                prompt_artifacts = prompt_requests_to_artifacts(
                    detection=prompt_detection,
                    context=prompt_context,
                    requests=prompt_requests,
                )
                if prompt_artifacts:
                    if harness == "codex":
                        prompt_artifacts = [
                            _with_codex_prompt_display_metadata(artifact, prompt_text=prompt_text)
                            for artifact in prompt_artifacts
                        ]
                    return _merged_prompt_runtime_artifact(harness, prompt_artifacts)
            prompt_file_artifact = _codex_prompt_credential_file_artifact(
                prompt_text=prompt_text,
                cwd=workspace,
                config_path=config_path,
            )
            if prompt_file_artifact is not None:
                return prompt_file_artifact
    request = extract_sensitive_file_read_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=workspace,
        home_dir=home_dir,
    )
    if request is None:
        request = (
            extract_sensitive_file_read_request_from_action(action_envelope, cwd=workspace, home_dir=home_dir)
            if action_envelope is not None
            else None
        )
    source_scope = _coalesce_string(payload.get("source_scope"), "project")
    config_path = str(_runtime_policy_path(harness, home_dir, workspace))
    if request is not None:
        return build_file_read_request_artifact(
            harness=harness,
            request=request,
            config_path=config_path,
            source_scope=source_scope,
        )
    package_intent = extract_package_intent_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        action_envelope_command=action_envelope.command if action_envelope is not None else None,
        workspace=workspace,
    )
    if package_intent is not None:
        return build_package_request_artifact(
            harness=harness,
            intent=package_intent,
            config_path=config_path,
            source_scope=source_scope,
        )
    tool_request = extract_sensitive_tool_action_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=workspace,
        home_dir=home_dir,
    )
    if tool_request is None:
        if action_envelope is None or not data_flow_signals:
            return None
        return _runtime_data_flow_artifact(
            harness=harness,
            action_envelope=action_envelope,
            data_flow_signals=data_flow_signals,
            config_path=config_path,
            source_scope=source_scope,
        )
    return build_tool_action_request_artifact(
        harness=harness,
        request=tool_request,
        config_path=config_path,
        source_scope=source_scope,
    )


def _runtime_data_flow_artifact(
    *,
    harness: str,
    action_envelope: GuardActionEnvelope,
    data_flow_signals: tuple[RiskSignalV2, ...],
    config_path: str,
    source_scope: str,
) -> GuardArtifact:
    command_text = action_envelope.command or action_envelope.tool_name or action_envelope.action_type
    signal_ids = tuple(signal.signal_id for signal in data_flow_signals)
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "command_text": command_text,
                "signal_ids": signal_ids,
                "source_scope": source_scope,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:data-flow:{fingerprint}",
        name=f"{action_envelope.tool_name or 'runtime'} data-flow exfiltration",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "action_class": "credential exfiltration shell command",
            "command_text": command_text,
            "guard_default_action": "require-reapproval",
            "request_summary": _runtime_data_flow_summary(data_flow_signals),
            "runtime_request_signals": [signal.plain_reason for signal in data_flow_signals],
            "runtime_request_summary": _runtime_data_flow_summary(data_flow_signals),
            "runtime_request_reason": (
                "Guard detected local-secret data flow in the runtime action before the command could send it away."
            ),
        },
    )


_CODEX_PROMPT_SECRET_KEY_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "PASS", "API_KEY", "API-KEY", "AUTH", "CREDENTIAL")

_CODEX_TOOL_RESPONSE_MAX_DEPTH = 5

_CODEX_TOOL_RESPONSE_TEXT_LIMIT = 20000

_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH = 24


def _codex_post_tool_output_artifact(
    *,
    harness: str = "codex",
    payload: dict[str, object],
    config_path: str,
    source_scope: str,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> GuardArtifact | None:
    canonical_harness = _canonical_harness_name(harness)
    harness_label = "Pi" if canonical_harness == "pi" else "Codex"
    response_text = _collect_codex_tool_response_text(payload.get("tool_response"))
    tool_name = _coalesce_string(payload.get("tool_name"), "Bash")
    command_text = _codex_post_tool_command_text(payload)
    if not command_text:
        command_text = tool_name
    local_source_matches = _codex_sensitive_local_source_matches(command_text, cwd=cwd)
    sensitive_file_request = extract_sensitive_file_read_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=cwd,
        home_dir=home_dir,
    )
    references_local_content = (
        bool(local_source_matches)
        or sensitive_file_request is not None
        or _codex_command_may_read_local_content(command_text, cwd=cwd)
    )
    content_matches = classify_secret_content(response_text)
    if not content_matches and references_local_content:
        content_matches = classify_secret_content(response_text, suppress_samples=False)
    if not content_matches:
        return None
    if _codex_source_inspection_can_skip_secret_output(
        command_text=command_text,
        response_text=response_text,
        content_matches=content_matches,
        cwd=cwd,
        home_dir=home_dir,
    ):
        return None
    if _codex_focused_pytest_can_skip_secret_output(
        command_text=command_text,
        response_text=response_text,
        content_matches=content_matches,
        cwd=cwd,
        home_dir=home_dir,
    ):
        return None
    merged_output_capture = _codex_command_captures_combined_shell_output(command_text)
    focused_pytest = _codex_command_is_focused_pytest_verification(command_text)
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "tool_name": tool_name,
                "command_text": command_text,
                "output_class": "credential-looking output",
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    local_secret_source = _codex_local_secret_source_label(
        local_source_matches,
        command_text=command_text,
    )
    runtime_default_action = "require-reapproval" if references_local_content else "warn"
    runtime_request_signals = ["tool output contains credential-looking material"]
    if references_local_content:
        source_signal = "command references local secrets"
        if local_secret_source is not None:
            source_signal = f"command references local secrets from {local_secret_source}"
        runtime_request_signals.append(source_signal)
    local_secret_source = _codex_local_secret_source_label(
        local_source_matches,
        command_text=command_text,
    )
    if local_secret_source is None and sensitive_file_request is not None:
        local_secret_source = sensitive_file_request.path_match.family
    request_summary = _codex_tool_output_request_summary(
        harness_label=harness_label,
        tool_name=tool_name,
        command_text=command_text,
        local_secret_source=local_secret_source,
        focused_pytest=focused_pytest,
        merged_output_capture=merged_output_capture,
    )
    runtime_request_summary = _codex_tool_output_runtime_summary(
        local_secret_source,
        harness_label=harness_label,
        focused_pytest=focused_pytest,
        merged_output_capture=merged_output_capture,
    )
    metadata: dict[str, object] = {
        "tool_name": tool_name,
        "command_text": command_text,
        "action_class": (
            "credential exfiltration shell command" if references_local_content else "credential-looking tool output"
        ),
        "guard_default_action": runtime_default_action,
        "request_summary": request_summary,
        "runtime_request_signals": runtime_request_signals,
        "runtime_request_summary": runtime_request_summary,
        "runtime_request_reason": _codex_tool_output_runtime_reason(
            local_secret_source,
            harness_label=harness_label,
            focused_pytest=focused_pytest,
            merged_output_capture=merged_output_capture,
        ),
    }
    if merged_output_capture:
        metadata["output_capture_mode"] = "merged-stderr"
    if local_secret_source is not None:
        metadata["secret_source_family"] = local_secret_source
    return GuardArtifact(
        artifact_id=f"{canonical_harness}:{source_scope}:tool-output:{fingerprint}",
        name=f"{tool_name} credential-looking output",
        harness=canonical_harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata=metadata,
    )


def _codex_text_contains_sensitive_path_token(text: str, *, cwd: Path | None) -> bool:
    return bool(_codex_sensitive_path_matches_in_text(text, cwd=cwd))


def _codex_command_may_read_local_content(command_text: str, *, cwd: Path | None) -> bool:
    if _codex_command_references_sensitive_local_source(command_text, cwd=cwd):
        return True
    if _codex_command_reads_environment_pipeline(command_text):
        return True
    if any(marker in command_text for marker in ("$(", "${", "`")):
        return True
    pipeline_segments = _split_codex_safe_read_only_pipeline(command_text)
    if pipeline_segments is not None:
        return any(
            _codex_pipeline_segment_may_read_local_content(segment, index=index, cwd=cwd)
            for index, segment in enumerate(pipeline_segments)
        )
    try:
        parts = _codex_shell_split(command_text)
    except ValueError:
        return True
    return _codex_command_parts_may_read_local_content(parts, cwd=cwd)


__all__ = [
    "_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH",
    "_CODEX_PROMPT_SECRET_KEY_MARKERS",
    "_CODEX_TOOL_RESPONSE_MAX_DEPTH",
    "_CODEX_TOOL_RESPONSE_TEXT_LIMIT",
    "_HOOK_EVENT_NAME_MAP",
    "_artifact_id_from_event",
    "_codex_command_may_read_local_content",
    "_codex_command_references_sensitive_local_source",
    "_codex_existing_local_path_match",
    "_codex_path_token_is_url_path",
    "_codex_post_tool_output_artifact",
    "_codex_sensitive_local_source_matches",
    "_codex_sensitive_path_matches_in_text",
    "_codex_text_contains_sensitive_path_token",
    "_codex_token_is_url",
    "_codex_token_prefix_is_url_scheme",
    "_codex_url_like_local_path_tokens",
    "_dedupe_codex_secret_path_matches",
    "_hook_event_name",
    "_hook_runtime_artifact",
    "_merged_prompt_runtime_artifact",
    "_optional_string",
    "_runtime_data_flow_artifact",
    "_string_list",
]
