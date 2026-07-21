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
        _codex_post_tool_command_texts,
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

    # These helpers are injected by commands_support's shared registry at
    # runtime. Local signatures retain type safety without introducing a
    # type-only import cycle with commands_support_runtime_resolution.
    def _canonical_harness_name(value: str) -> str: ...

    def _runtime_policy_path(
        harness: str,
        home_dir: Path,
        workspace: Path | None,
        *,
        payload: dict[str, object] | None = None,
    ) -> Path: ...


from ..runtime.command_extensions import risk_classes_for_command_action
from ..runtime.command_model import parse_shell_command
from ..runtime.kubernetes_commands import kubernetes_secret_read_source
from ..runtime.shell_command_wrappers import normalize_transparent_shell_command
from ..runtime.shell_execution_context import (
    model_shell_execution_context,
    shell_execution_context_metadata,
    validate_shell_execution_segment,
)
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_codex_commands import (
    _codex_command_parts_may_read_local_content,
    _codex_command_reads_environment_pipeline,
    _codex_local_secret_source_label,
    _codex_pipeline_segment_may_read_local_content,
    _codex_post_tool_command_is_read_only_source_inspection,
    _codex_post_tool_command_texts,
    _codex_shell_split,
    _codex_source_inspection_can_skip_secret_output,
)
from .commands_support_codex_git import _codex_git_diff_selection_identity
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


def _runtime_hook_tool_name(payload: Mapping[str, object]) -> object:
    return payload.get("tool_name", payload.get("toolName"))


def _runtime_hook_tool_arguments(payload: Mapping[str, object]) -> object:
    value = payload.get("tool_input")
    if value is None:
        value = payload.get("arguments")
    if value is None:
        value = payload.get("tool_args", payload.get("toolArgs"))
    if not isinstance(value, str):
        return value
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return {"command": value}
    return decoded


def _runtime_hook_raw_command_text(
    payload: Mapping[str, object],
    action_envelope: GuardActionEnvelope | None,
) -> str | None:
    command_text = command_text_from_tool_payload(
        _runtime_hook_tool_name(payload),
        _runtime_hook_tool_arguments(payload),
    )
    if command_text is not None:
        return command_text
    return action_envelope.command if action_envelope is not None else None


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


def _runtime_artifact_declared_risk_classes(artifact: GuardArtifact) -> list[str]:
    risk_classes: list[str] = []
    if artifact.artifact_type == "package_request":
        risk_classes.append("package_script")
    elif artifact.artifact_type == "file_read_request":
        risk_classes.append("local_secret_read")
    metadata_classes = artifact.metadata.get("risk_classes")
    if isinstance(metadata_classes, list):
        risk_classes.extend(value.strip() for value in metadata_classes if isinstance(value, str) and value.strip())
    action_class = artifact.metadata.get("action_class")
    if artifact.artifact_type == "tool_action_request" and isinstance(action_class, str):
        risk_classes.extend(risk_classes_for_command_action(action_class))
    return list(dict.fromkeys(risk_classes))


def _unmodeled_shell_runtime_artifact(
    *,
    harness: str,
    command_text: str,
    config_path: str,
    source_scope: str,
    workspace: Path | None,
    home_dir: Path,
) -> GuardArtifact | None:
    canonical_command = parse_shell_command(command_text, cwd=workspace, home_dir=home_dir)
    execution_context = model_shell_execution_context(command_text, cwd=workspace, workspace_root=workspace)
    if canonical_command.confidence == "exact" and execution_context.complete:
        return None
    if canonical_command.confidence == "exact" and not execution_context.complete:
        home_execution_context = low_risk_compound_developer_execution_context(
            command_text,
            home_dir=home_dir,
        )
        if home_execution_context is not None:
            return None
        home_execution_context = model_shell_execution_context(
            command_text, cwd=home_dir, workspace_root=home_dir, home_dir=home_dir
        )
        github_assessment = classify_github_shell_capabilities(command_text, home_dir=home_dir)
        if (
            github_assessment is not None
            and not github_capability_requires_confirmation(github_assessment)
            and shell_execution_context_starts_with_literal_cd(home_execution_context)
        ):
            return None
    context_metadata = shell_execution_context_metadata(execution_context)
    reason_code = canonical_command.uncertainty_reason
    if reason_code is None:
        reason_code = _optional_string(context_metadata.get("shell_execution_context_reason_code"))
    if reason_code is None:
        raw_reason_codes = context_metadata.get("shell_execution_context_reason_codes")
        if isinstance(raw_reason_codes, list):
            reason_code = next((value for value in raw_reason_codes if isinstance(value, str) and value), None)
    reason_code = reason_code or "compound_command_incomplete"
    identity_payload = {
        "version": 1,
        "command_security_identity": canonical_command.security_identity,
        "shell_execution_context_hash": execution_context.context_hash,
        "reason_code": reason_code,
    }
    fingerprint = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:unmodeled-shell:{fingerprint}",
        name="unmodeled compound shell command",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata={
            "action_class": "unmodeled shell command",
            "guard_default_action": "require-reapproval",
            "risk_classes": ["execution"],
            "request_summary": "Requested a shell command that Guard could not model completely.",
            "runtime_request_signals": [f"cannot completely model the shell command: {reason_code}"],
            "runtime_request_summary": "Guard requires one review because part of this shell command is unresolved.",
            "runtime_request_reason": (
                "Guard could not prove the complete compound command structure, so it kept the whole command in "
                "one fail-closed review."
            ),
            "command_security_identity": canonical_command.security_identity,
            "command_parse_confidence": canonical_command.confidence,
            "command_uncertainty_reason": reason_code,
            **context_metadata,
        },
    )


def _compound_runtime_artifact(
    *,
    artifacts: list[GuardArtifact],
    command_text: str | None,
    workspace: Path | None,
    home_dir: Path,
) -> GuardArtifact | None:
    if not artifacts:
        return None
    primary = next((artifact for artifact in artifacts if artifact.artifact_type == "package_request"), artifacts[0])
    canonical_command = (
        parse_shell_command(command_text, cwd=workspace, home_dir=home_dir) if command_text is not None else None
    )
    requires_full_command_binding = len(artifacts) > 1
    if canonical_command is not None:
        requires_full_command_binding = requires_full_command_binding or bool(
            len(canonical_command.segments) > 1
            or canonical_command.redirects
            or canonical_command.embedded_commands
            or canonical_command.wrapper_chain
            or canonical_command.confidence != "exact"
        )
    if not requires_full_command_binding:
        return primary

    signals: list[str] = []
    summaries: list[str] = []
    reasons: list[str] = []
    risk_classes: list[str] = []
    rule_matches: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    for artifact in artifacts:
        artifact_risk_classes = _runtime_artifact_declared_risk_classes(artifact)
        risk_classes.extend(artifact_risk_classes)
        signals.extend(_string_list(artifact.metadata.get("runtime_request_signals")))
        summary = _optional_string(artifact.metadata.get("runtime_request_summary"))
        if summary is not None:
            summaries.append(summary)
        reason = _optional_string(artifact.metadata.get("runtime_request_reason"))
        if reason is not None:
            reasons.append(reason)
        raw_rule_matches = artifact.metadata.get("command_rule_matches")
        if isinstance(raw_rule_matches, list):
            rule_matches.extend(item for item in raw_rule_matches if isinstance(item, dict))
        findings.append(
            {
                "artifact_id": artifact.artifact_id,
                "artifact_type": artifact.artifact_type,
                "risk_classes": artifact_risk_classes,
                "summary": summary or artifact.name,
            }
        )

    deduped_signals = list(dict.fromkeys(signals))
    deduped_summaries = list(dict.fromkeys(summaries))
    deduped_reasons = list(dict.fromkeys(reasons))
    deduped_risk_classes = list(dict.fromkeys(risk_classes))
    deduped_rule_matches = list(
        {json.dumps(match, sort_keys=True, separators=(",", ":")): match for match in rule_matches}.values()
    )
    segment_coordinates = (
        [
            {
                "index": index,
                "execution_context": segment.execution_context,
                "pipeline_index": segment.pipeline_index,
                "executable": segment.executable,
                "span": {"source": "normalized", "start": segment.start, "end": segment.end},
            }
            for index, segment in enumerate(canonical_command.segments)
        ]
        if canonical_command is not None
        else []
    )
    compound_summary = "Compound command findings: " + " ".join(deduped_summaries)
    metadata = dict(primary.metadata)
    metadata.update(
        {
            "compound_complete": canonical_command is not None and canonical_command.confidence == "exact",
            "compound_findings": findings,
            "compound_finding_count": len(findings),
            "compound_segments": segment_coordinates,
            "compound_segment_count": len(canonical_command.segments) if canonical_command is not None else 0,
            "risk_classes": deduped_risk_classes,
            "request_summary": compound_summary,
            "runtime_request_signals": deduped_signals,
            "runtime_request_summary": compound_summary,
            "runtime_request_reason": " ".join(deduped_reasons),
            "command_rule_matches": deduped_rule_matches,
            "command_security_identity": (
                canonical_command.security_identity if canonical_command is not None else "command-security-unavailable"
            ),
            "command_parse_confidence": canonical_command.confidence if canonical_command is not None else "uncertain",
            "command_uncertainty_reason": (
                canonical_command.uncertainty_reason if canonical_command is not None else "command_text_unavailable"
            ),
        }
    )
    if command_text is not None:
        execution_context = model_shell_execution_context(command_text, cwd=workspace, workspace_root=workspace)
        metadata.update(shell_execution_context_metadata(execution_context))
        metadata["compound_complete"] = metadata["compound_complete"] is True and execution_context.complete
    if metadata["compound_complete"] is not True or metadata.get("shell_execution_context_complete") is False:
        metadata["guard_default_action"] = "require-reapproval"
    identity_payload = {
        "version": 1,
        "primary_artifact_id": primary.artifact_id,
        "finding_artifact_ids": [artifact.artifact_id for artifact in artifacts],
        "command_security_identity": metadata["command_security_identity"],
    }
    fingerprint = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    artifact_id_prefix = primary.artifact_id.rsplit(":", 1)[0]
    return replace(
        primary,
        artifact_id=f"{artifact_id_prefix}:{fingerprint}",
        name=f"compound {primary.name}",
        metadata=metadata,
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
            config_path=str(_runtime_policy_path(harness, home_dir, workspace, payload=payload)),
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
            config_path = str(_runtime_policy_path(harness, home_dir, workspace, payload=payload))
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
    tool_name = _runtime_hook_tool_name(payload)
    tool_arguments = _runtime_hook_tool_arguments(payload)
    raw_command_text = _runtime_hook_raw_command_text(payload, action_envelope)
    request = extract_sensitive_file_read_request(
        tool_name,
        tool_arguments,
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
    config_path = str(_runtime_policy_path(harness, home_dir, workspace, payload=payload))
    if request is not None:
        return build_file_read_request_artifact(
            harness=harness,
            request=request,
            config_path=config_path,
            source_scope=source_scope,
        )
    file_write_request = extract_sensitive_file_write_request(
        tool_name,
        tool_arguments,
        cwd=workspace,
        home_dir=home_dir,
        protected_paths=_runtime_protected_file_write_paths(
            harness=harness,
            home_dir=home_dir,
            workspace=workspace,
        ),
    )
    if file_write_request is not None:
        return build_file_write_request_artifact(
            harness=harness,
            request=file_write_request,
            config_path=config_path,
            source_scope=source_scope,
        )
    package_intent = None
    if not _post_tool_package_request_was_already_evaluated(payload=payload, action_envelope=action_envelope):
        package_intent = extract_package_intent_request(
            tool_name,
            tool_arguments,
            action_envelope_command=action_envelope.command if action_envelope is not None else raw_command_text,
            workspace=workspace,
        )
    runtime_artifacts: list[GuardArtifact] = []
    if package_intent is not None:
        runtime_artifacts.append(
            build_package_request_artifact(
                harness=harness,
                intent=package_intent,
                config_path=config_path,
                source_scope=source_scope,
            )
        )
    tool_request = extract_sensitive_tool_action_request(
        tool_name,
        tool_arguments,
        cwd=workspace,
        home_dir=home_dir,
    )
    if tool_request is not None:
        runtime_artifacts.append(
            build_tool_action_request_artifact(
                harness=harness,
                request=tool_request,
                config_path=config_path,
                source_scope=source_scope,
            )
        )
    if raw_command_text is not None:
        unmodeled_artifact = _unmodeled_shell_runtime_artifact(
            harness=harness,
            command_text=raw_command_text,
            config_path=config_path,
            source_scope=source_scope,
            workspace=workspace,
            home_dir=home_dir,
        )
        if unmodeled_artifact is not None:
            runtime_artifacts.append(unmodeled_artifact)
    if action_envelope is not None and data_flow_signals:
        runtime_artifacts.append(
            _runtime_data_flow_artifact(
                harness=harness,
                action_envelope=action_envelope,
                data_flow_signals=data_flow_signals,
                config_path=config_path,
                source_scope=source_scope,
            )
        )
    return _compound_runtime_artifact(
        artifacts=runtime_artifacts,
        command_text=raw_command_text,
        workspace=workspace,
        home_dir=home_dir,
    )


def _runtime_protected_file_write_paths(
    *,
    harness: str,
    home_dir: Path,
    workspace: Path | None,
) -> dict[str, str]:
    protected_paths: dict[str, str] = {}
    if harness == "codex":
        protected_paths[str(home_dir / ".codex" / "config.toml")] = "Codex config"
        protected_paths[str(home_dir / ".codex" / "hooks.json")] = "Codex hooks"
        if workspace is not None:
            protected_paths[str(workspace / ".codex" / "config.toml")] = "Codex config"
            protected_paths[str(workspace / ".codex" / "hooks.json")] = "Codex hooks"
    return protected_paths


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
            "risk_classes": ["data_flow_exfiltration"],
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

_CODEX_TOOL_RESPONSE_TEXT_LIMIT = 5 * 1024 * 1024

_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH = 24


def _direct_codex_git_pathspec_identity(command_text: str, *, cwd: Path | None) -> str | None:
    pipeline = _split_codex_safe_read_only_pipeline(command_text)
    git_segment = pipeline[0] if pipeline else command_text
    try:
        parts = shlex.split(git_segment)
    except ValueError:
        return None
    if not parts or Path(parts[0]).name != "git":
        return None
    return _codex_git_diff_selection_identity(parts[1:], cwd=cwd)


def _codex_git_pathspec_identity_for_command(command_text: str, *, cwd: Path | None) -> str | None:
    execution_context = model_shell_execution_context(command_text, cwd=cwd, workspace_root=cwd)
    if not execution_context.directory_change_present:
        return _direct_codex_git_pathspec_identity(command_text, cwd=cwd)
    if not execution_context.complete:
        return None
    identities: list[tuple[int, str]] = []
    for segment in execution_context.segments:
        if segment.directory_operation is not None:
            continue
        segment_cwd, reason = validate_shell_execution_segment(execution_context, segment)
        if segment_cwd is None or reason is not None:
            return None
        identity = _direct_codex_git_pathspec_identity(segment.command_text, cwd=segment_cwd)
        if identity is not None:
            identities.append((segment.segment_index, identity))
    if not identities:
        return None
    if len(identities) == 1:
        return identities[0][1]
    canonical = json.dumps(
        {"schema": "codex-git-pathspec-context-v1", "identities": identities},
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    stdout_text = _optional_string(payload.get("stdout"))
    if stdout_text:
        response_text = f"{response_text}\n{stdout_text}".strip() if response_text else stdout_text
    tool_name = _coalesce_string(payload.get("tool_name"), "Bash")
    command_texts = _codex_post_tool_command_texts(payload)
    command_text = command_texts[0] if command_texts else tool_name
    local_source_matches = _codex_sensitive_local_source_matches(command_text, cwd=cwd)
    normalized_command = normalize_transparent_shell_command(
        command_text, cwd=cwd, home_dir=home_dir
    ).normalized_command
    kubernetes_secret_source = kubernetes_secret_read_source(normalized_command)
    for candidate_command_text in command_texts[1:]:
        candidate_local_source_matches = _codex_sensitive_local_source_matches(candidate_command_text, cwd=cwd)
        candidate_normalized_command = normalize_transparent_shell_command(
            candidate_command_text, cwd=cwd, home_dir=home_dir
        ).normalized_command
        candidate_kubernetes_secret_source = kubernetes_secret_read_source(candidate_normalized_command)
        candidate_references_local_content = (
            bool(candidate_local_source_matches)
            or candidate_kubernetes_secret_source is not None
            or _codex_command_may_read_local_content(candidate_command_text, cwd=cwd)
        )
        if not candidate_references_local_content:
            continue
        command_text = candidate_command_text
        local_source_matches = candidate_local_source_matches
        normalized_command = candidate_normalized_command
        kubernetes_secret_source = candidate_kubernetes_secret_source
        if candidate_kubernetes_secret_source is not None:
            break
    sensitive_file_request = extract_sensitive_file_read_request(
        payload.get("tool_name"),
        payload.get("tool_input", payload.get("arguments")),
        cwd=cwd,
        home_dir=home_dir,
    )
    references_local_content = (
        bool(local_source_matches)
        or kubernetes_secret_source is not None
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
        payload=payload,
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
    execution_context = model_shell_execution_context(command_text, cwd=cwd, workspace_root=cwd)
    git_pathspec_selection_identity = _codex_git_pathspec_identity_for_command(normalized_command, cwd=cwd)
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "tool_name": tool_name,
                "command_text": command_text,
                "output_class": "credential-looking output",
                "shell_execution_context_hash": (
                    execution_context.context_hash if execution_context.directory_change_present else None
                ),
                "git_pathspec_selection_identity": git_pathspec_selection_identity,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    local_secret_source = kubernetes_secret_source or _codex_local_secret_source_label(
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
    local_secret_source = kubernetes_secret_source or _codex_local_secret_source_label(
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
            (
                "Kubernetes secret read command"
                if kubernetes_secret_source is not None
                else "credential exfiltration shell command"
            )
            if references_local_content
            else "credential-looking tool output"
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
    if execution_context.directory_change_present:
        metadata.update(shell_execution_context_metadata(execution_context))
    if git_pathspec_selection_identity is not None:
        metadata["git_pathspec_selection_identity"] = git_pathspec_selection_identity
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


def _post_tool_package_request_was_already_evaluated(
    *,
    payload: Mapping[str, object],
    action_envelope: GuardActionEnvelope | None,
) -> bool:
    event_name = _hook_event_name(dict(payload))
    if event_name != "PostToolUse":
        return False
    pre_execution_result = _optional_string(payload.get("pre_execution_result"))
    if pre_execution_result is None:
        pre_execution_result = _optional_string(payload.get("preExecutionResult"))
    if pre_execution_result is None and action_envelope is not None:
        pre_execution_result = _optional_string(action_envelope.pre_execution_result)
    return pre_execution_result is not None


def _codex_text_contains_sensitive_path_token(text: str, *, cwd: Path | None) -> bool:
    return bool(_codex_sensitive_path_matches_in_text(text, cwd=cwd))


def _codex_command_may_read_local_content(command_text: str, *, cwd: Path | None) -> bool:
    execution_context = model_shell_execution_context(command_text, cwd=cwd, workspace_root=cwd)
    if execution_context.directory_change_present:
        if not execution_context.complete:
            return True
        for segment in execution_context.segments:
            if segment.directory_operation is not None:
                continue
            segment_cwd, reason = validate_shell_execution_segment(execution_context, segment)
            if segment_cwd is None or reason is not None:
                return True
            if _codex_command_may_read_local_content(segment.command_text, cwd=segment_cwd):
                return True
        return False
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
