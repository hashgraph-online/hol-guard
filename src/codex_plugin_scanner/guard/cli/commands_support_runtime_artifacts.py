"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import Any

from ..native_codex_tool_output import codex_tool_output_native
from ..native_context import bound_context_digest_home
from ..native_path_anchor import anchor_to_process_directory
from ..native_rich_command_model import NativeCommandModelError
from ..native_sensitive_request import (
    NativeSensitiveRequestError,
    native_compound_artifact,
    native_unmodeled_shell_artifact,
)
from ..runtime.command_decision_adapter import effect_decision_to_dict
from ..runtime.direct_vitest import direct_local_typescript_execution_context
from ..runtime.extension_allow_hint import compute_extension_allow_hint
from ..runtime.jsonc import loads_jsonc
from ..runtime.native_command_evaluation import NativeCommandEvaluation, review_command_native
from ..runtime.node_semver import node_semver_spec_matches as _routine_semver_spec_matches
from ..runtime.package_intent_common import PackageExecutionFileEvidence, PackageIntent
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_codex_commands import _codex_post_tool_command_texts
from .commands_support_codex_paths import (
    _CODEX_PROMPT_FILE_FINGERPRINT_LENGTH,
    _CODEX_TOOL_RESPONSE_MAX_DEPTH,
    _CODEX_TOOL_RESPONSE_TEXT_LIMIT,
    _codex_prompt_credential_file_artifact,
    _collect_codex_tool_response_text,
    _with_codex_prompt_display_metadata,
)
from .commands_support_codex_prompt_attachments import _codex_prompt_attachment_artifact
from .commands_support_hook_payload import _coalesce_string
from .commands_support_runtime_policy import _runtime_data_flow_summary
from .commands_support_runtime_resolution import _canonical_harness_name, _runtime_policy_path


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


_HOOK_EVENT_NAME_MAP = {
    "userpromptsubmitted": "UserPromptSubmit",
    "pretooluse": "PreToolUse",
    "posttooluse": "PostToolUse",
    "permissionrequest": "PermissionRequest",
    "permissionrequestv2": "PermissionRequest",
}


def _hook_event_name(payload: dict[str, object]) -> str | None:
    for key in ("event", "hook_event_name", "hookEventName", "hook_name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.strip()
            return _HOOK_EVENT_NAME_MAP.get(normalized.lower(), normalized)
    return None


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


def _routine_local_runner_has_complete_evidence(intent: PackageIntent) -> bool:
    """Return whether a routine JS runner is already bound to local project state."""

    if intent.package_manager not in {"bunx", "npx"} or len(intent.local_executions) != 1:
        return False
    execution = intent.local_executions[0]
    if execution.package_name not in {"eslint", "jest", "tsc", "vitest"}:
        return False
    if len(intent.targets) != 1:
        return False
    target = intent.targets[0]
    if target.raw_spec != execution.package_name or target.requested_specifier is not None:
        return False
    if target.source_kind is not None or target.source_url is not None:
        return False
    if "--package" in intent.command_tokens or any(token.startswith("--package=") for token in intent.command_tokens):
        return False
    if execution.package_name != execution.executable_name or execution.declared_version is None:
        return False
    if execution.declared_version.lower().startswith(("file:", "git+", "git://", "github:", "http:", "https:")):
        return False
    evidence_files = (execution.manager, execution.local_executable, *execution.manifests, *execution.lockfiles)
    if not execution.manifests or not execution.lockfiles:
        return False
    if any(
        evidence is None
        or evidence.status != "available"
        or evidence.resolved_path is None
        or evidence.file_identity is None
        or evidence.content_hash is None
        for evidence in evidence_files
    ):
        return False
    executable = execution.local_executable
    if executable is None or executable.resolved_path is None:
        return False
    try:
        workspace = Path(execution.effective_cwd).resolve(strict=True)
        node_modules = (workspace / "node_modules").resolve(strict=True)
        package_root = (node_modules / execution.package_name).resolve(strict=True)
        package_root.relative_to(node_modules)
        Path(executable.resolved_path).resolve(strict=True).relative_to(package_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return not intent.execution_context_reason_codes and _routine_local_runner_versions_match(
        workspace,
        execution.package_name,
        execution.declared_version,
        execution.lockfiles,
    )


def _routine_local_runner_versions_match(
    workspace: Path,
    package_name: str,
    declared_version: str,
    lockfiles: tuple[PackageExecutionFileEvidence, ...],
) -> bool:
    try:
        manifest = json.loads((workspace / "package.json").read_text(encoding="utf-8"))
        installed = json.loads((workspace / "node_modules" / package_name / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict) or not isinstance(installed, dict):
        return False
    dependency_groups = (manifest.get("dependencies"), manifest.get("devDependencies"))
    if not any(isinstance(group, dict) and group.get(package_name) == declared_version for group in dependency_groups):
        return False
    installed_version = installed.get("version")
    if installed.get("name") != package_name or not isinstance(installed_version, str):
        return False
    locked_versions: set[str] = set()
    for evidence in lockfiles:
        if evidence.resolved_path is None:
            continue
        try:
            lock_text = Path(evidence.resolved_path).read_text(encoding="utf-8")
            lock = loads_jsonc(lock_text) if Path(evidence.resolved_path).name == "bun.lock" else json.loads(lock_text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        if not isinstance(lock, dict):
            return False
        packages = lock.get("packages")
        if not isinstance(packages, dict):
            return False
        package_lock_entry = packages.get(f"node_modules/{package_name}")
        if isinstance(package_lock_entry, dict) and isinstance(package_lock_entry.get("version"), str):
            locked_versions.add(package_lock_entry["version"])
        bun_entry = packages.get(package_name)
        if isinstance(bun_entry, list) and bun_entry and isinstance(bun_entry[0], str):
            prefix = f"{package_name}@"
            if bun_entry[0].startswith(prefix):
                locked_versions.add(bun_entry[0][len(prefix) :])
    return locked_versions == {installed_version} and _routine_semver_spec_matches(declared_version, installed_version)


def _unmodeled_shell_runtime_artifact(
    *,
    harness: str,
    command_text: str,
    config_path: str,
    source_scope: str,
    workspace: Path | None,
    home_dir: Path,
) -> GuardArtifact | None:
    review = native_unmodeled_shell_artifact(command_text, workspace=workspace, home_dir=home_dir)
    if review is None:
        return None
    fingerprint, metadata = review
    return GuardArtifact(
        artifact_id=f"{harness}:{source_scope}:unmodeled-shell:{fingerprint}",
        name="unmodeled compound shell command",
        harness=harness,
        artifact_type="tool_action_request",
        source_scope=source_scope,
        config_path=config_path,
        metadata=metadata,
    )


def _compound_runtime_artifact(
    *,
    artifacts: list[GuardArtifact],
    command_text: str | None,
    native_review: NativeCommandEvaluation | None,
    workspace: Path | None,
    home_dir: Path,
) -> GuardArtifact | None:
    if not artifacts:
        return None
    if command_text is None and len(artifacts) == 1:
        return artifacts[0]
    if native_review is None:
        decision: dict[str, object] = {
            "command_action_floor": "require-reapproval",
            "command_evaluation_status": "native_unavailable",
        }
    else:
        plane = native_review.evaluation.decision_plane
        decision = {"command_action_floor": plane.action, "command_decision_plane": effect_decision_to_dict(plane)}
    return native_compound_artifact(
        artifacts, command_text=command_text, decision=decision, workspace=workspace, home_dir=home_dir
    )


def _hook_runtime_artifact(**kwargs: Any) -> GuardArtifact | None:
    try:
        with bound_context_digest_home(kwargs.get("guard_home")):
            return _hook_runtime_artifact_with_native(**kwargs)
    except (NativeCommandModelError, NativeSensitiveRequestError):
        harness = _canonical_harness_name(kwargs["harness"])
        return GuardArtifact(
            artifact_id=f"{harness}:native-command-unavailable",
            name="native command runtime unavailable",
            harness=harness,
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(
                _runtime_policy_path(harness, kwargs["home_dir"], kwargs.get("workspace"), payload=kwargs["payload"])
            ),
            metadata={
                "guard_default_action": "block",
                "native_command_evaluation_status": "unavailable",
                "runtime_request_reason": "Native command runtime is unavailable; repair it before retrying.",
            },
        )


def _hook_runtime_artifact_with_native(
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
    if harness in {"codex", "cline", "pi", "omp"} and event_name == "PostToolUse":
        output_artifact, read_only = _codex_post_tool_output_review(
            harness=harness,
            payload=payload,
            config_path=str(_runtime_policy_path(harness, home_dir, workspace, payload=payload)),
            source_scope=_coalesce_string(payload.get("source_scope"), "project"),
            cwd=workspace,
            home_dir=home_dir,
        )
        if output_artifact is not None:
            return output_artifact
        if read_only:
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
            prompt_requests = extract_prompt_requests(prompt_text, guard_home=guard_home)
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
            if harness == "codex":
                attachment_artifact = _codex_prompt_attachment_artifact(
                    prompt_text=prompt_text,
                    home_dir=home_dir,
                    config_path=config_path,
                    guard_home=guard_home,
                )
                if attachment_artifact is not None:
                    return attachment_artifact
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
            home_dir=home_dir,
            guard_home=guard_home,
        )
    runtime_artifacts: list[GuardArtifact] = []
    native_review = (
        review_command_native(
            raw_command_text,
            guard_home=guard_home,
            cwd=workspace,
            home_dir=home_dir,
        )
        if raw_command_text is not None
        else None
    )
    verified_local_runner = isinstance(raw_command_text, str) and (
        direct_local_typescript_execution_context(
            raw_command_text,
            cwd=workspace,
            home_dir=home_dir,
        )
    )
    if (
        package_intent is not None
        and not verified_local_runner
        # Test and lint runners execute repository-controlled code. Local
        # identity is evidence, not authority to omit their package review.
        and not (
            _routine_local_runner_has_complete_evidence(package_intent)
            and all(item.package_name == "tsc" for item in package_intent.local_executions)
        )
    ):
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
        canonical_command=(native_review.evaluation.command if native_review is not None else None),
        native_evaluation=(native_review.evaluation if native_review is not None else None),
    )
    if tool_request is not None:
        runtime_artifacts.append(
            build_tool_action_request_artifact(
                harness=harness,
                request=tool_request,
                config_path=config_path,
                source_scope=source_scope,
                extension_control_snapshot=(native_review.snapshot if native_review is not None else None),
                native_extension_evidence=(native_review.payload if native_review is not None else None),
                native_evaluation=(native_review.evaluation if native_review is not None else None),
                extension_allow_hint=(
                    compute_extension_allow_hint(
                        native_review.evaluation,
                        command_text=raw_command_text,
                        snapshot=native_review.snapshot,
                        native_evidence=native_review.payload,
                        cwd=workspace,
                        home_dir=home_dir,
                    )
                    if native_review is not None and raw_command_text is not None
                    else None
                ),
            )
        )
    if raw_command_text is not None and (action_envelope is None or action_envelope.action_type == "shell_command"):
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
        native_review=native_review,
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


def _codex_post_tool_output_review(
    *,
    harness: str = "codex",
    payload: dict[str, object],
    config_path: str,
    source_scope: str,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> tuple[GuardArtifact | None, bool]:
    """Review a post-tool output in the resident: the artifact, and whether the commands were read-only."""

    canonical_harness = _canonical_harness_name(harness)
    harness_label = {"cline": "Cline", "pi": "Pi", "omp": "Oh My Pi"}.get(canonical_harness, "Codex")
    response_text = _collect_codex_tool_response_text(payload.get("tool_response"))
    stdout_text = _optional_string(payload.get("stdout"))
    if stdout_text:
        response_text = f"{response_text}\n{stdout_text}".strip() if response_text else stdout_text
    tool_label = _coalesce_string(payload.get("tool_name"), "Bash")
    answer = codex_tool_output_native(
        "post_tool_output",
        body={
            "harness_label": harness_label,
            "tool_label": tool_label,
            "tool_name": payload.get("tool_name"),
            "tool_input": payload.get("tool_input"),
            "arguments": payload.get("arguments"),
            "tool_input_present": "tool_input" in payload,
            "command_texts": list(_codex_post_tool_command_texts(payload)),
            "response_text": response_text,
            "cwd": None if cwd is None else anchor_to_process_directory(cwd),
            "home_dir": None if home_dir is None else anchor_to_process_directory(home_dir),
            "deadline_ms": 8_000,
        },
        timeout_seconds=9.0,
    )
    if not answer.allowed or answer.value is None or answer.error_code is not None:
        raise NativeSensitiveRequestError(answer.error_code or "native_codex_post_tool_unavailable")
    decoded = json.loads(answer.value)
    found = decoded.get("artifact")
    if found is None:
        return None, decoded.get("read_only") is True
    return (
        GuardArtifact(
            artifact_id=f"{canonical_harness}:{source_scope}:tool-output:{found['fingerprint']}",
            name=f"{tool_label} credential-looking output",
            harness=canonical_harness,
            artifact_type="tool_action_request",
            source_scope=source_scope,
            config_path=config_path,
            metadata={key: value for key, value in found["metadata"]},
        ),
        False,
    )


def _codex_post_tool_output_artifact(**kwargs: Any) -> GuardArtifact | None:
    return _codex_post_tool_output_review(**kwargs)[0]


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


__all__ = [
    "_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH",
    "_CODEX_PROMPT_SECRET_KEY_MARKERS",
    "_CODEX_TOOL_RESPONSE_MAX_DEPTH",
    "_CODEX_TOOL_RESPONSE_TEXT_LIMIT",
    "_HOOK_EVENT_NAME_MAP",
    "_codex_post_tool_output_artifact",
    "_hook_event_name",
    "_hook_runtime_artifact",
    "_merged_prompt_runtime_artifact",
    "_optional_string",
    "_runtime_data_flow_artifact",
    "_string_list",
]
