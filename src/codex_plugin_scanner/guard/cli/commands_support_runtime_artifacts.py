"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import Any

from ..daemon.native_review_allow_hint import reviewed_command_extension_allow_hint
from ..native_codex_tool_output import codex_tool_output_native
from ..native_context import bound_context_digest_home
from ..native_path_anchor import anchor_to_process_directory
from ..native_prompt import merge_prompt_artifacts
from ..native_rich_command_model import NativeCommandModelError
from ..native_runtime_artifact_identity import NativeRuntimeArtifactIdentityError
from ..native_sensitive_request import (
    NativeSensitiveRequestError,
    native_compound_artifact,
    native_unmodeled_shell_artifact,
)
from ..native_tool_action_identity import NativeToolActionIdentityError
from ..runtime.command_decision_adapter import effect_decision_to_dict
from ..runtime.direct_vitest import direct_local_typescript_execution_context
from ..runtime.native_command_evaluation import NativeCommandEvaluation, review_command_native
from ._commands_shared import *
from .commands_parser_helpers import *
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


def _merged_prompt_runtime_artifact(
    harness: str, artifacts: list[GuardArtifact], *, guard_home: Path | None = None
) -> GuardArtifact:
    """The one review a prompt's guarded requests are held under.

    A single request is its own review and needs no identity derived for it.
    Two or more are folded by the resident, which owns the merged artifact id
    the saved approval is keyed by.
    """
    if len(artifacts) == 1:
        return artifacts[0]
    return merge_prompt_artifacts(harness, artifacts, guard_home=guard_home)


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
    except (
        NativeCommandModelError,
        NativeRuntimeArtifactIdentityError,
        NativeSensitiveRequestError,
        NativeToolActionIdentityError,
    ):
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
    data_flow_artifact: GuardArtifact | None = None,
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
                    return _merged_prompt_runtime_artifact(harness, prompt_artifacts, guard_home=guard_home)
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
                )
                if attachment_artifact is not None:
                    return attachment_artifact
    tool_name = _runtime_hook_tool_name(payload)
    tool_arguments = _runtime_hook_tool_arguments(payload)
    raw_command_text = _runtime_hook_raw_command_text(payload, action_envelope)
    source_scope = _coalesce_string(payload.get("source_scope"), "project")
    config_path = str(_runtime_policy_path(harness, home_dir, workspace, payload=payload))
    naming = {"harness": harness, "config_path": config_path, "source_scope": source_scope}
    _read_request, read_artifact = extract_sensitive_file_read_request_artifact(
        tool_name,
        tool_arguments,
        cwd=workspace,
        home_dir=home_dir,
        **naming,
    )
    if read_artifact is None and action_envelope is not None:
        _read_request, read_artifact = extract_sensitive_file_read_request_artifact_from_action(
            action_envelope,
            cwd=workspace,
            home_dir=home_dir,
            **naming,
        )
    if read_artifact is not None:
        return read_artifact
    _write_request, write_artifact = extract_sensitive_file_write_request_artifact(
        tool_name,
        tool_arguments,
        cwd=workspace,
        home_dir=home_dir,
        protected_paths=_runtime_protected_file_write_paths(
            harness=harness,
            home_dir=home_dir,
            workspace=workspace,
        ),
        **naming,
    )
    if write_artifact is not None:
        return write_artifact
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
            package_intent.routine_local_runner
            and all(item.package_name == "tsc" for item in package_intent.local_executions)
        )
    ):
        runtime_artifacts.append(
            build_package_request_artifact(
                harness=harness,
                intent=package_intent,
                config_path=config_path,
                source_scope=source_scope,
                guard_home=guard_home,
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
                    reviewed_command_extension_allow_hint(
                        raw_command_text,
                        native_result=native_review.payload,
                        snapshot=native_review.snapshot,
                        guard_home=guard_home,
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
    if data_flow_artifact is not None:
        runtime_artifacts.append(data_flow_artifact)
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


_CODEX_PROMPT_SECRET_KEY_MARKERS = ("TOKEN", "SECRET", "PASSWORD", "PASS", "API_KEY", "API-KEY", "AUTH", "CREDENTIAL")


# How large the whole packed request may be once a tool response joins the
# flattened text, under the resident's own `CODEX_POST_TOOL_OUTPUT_MAX_BYTES`
# of `6 * 1024 * 1024 - 64 * 1024`. The margin leaves room for the framing the
# transport adds after this side has encoded the body.
_CODEX_POST_TOOL_REQUEST_BUDGET = 4 * 1024 * 1024

# How deeply a tool response may nest before this side keeps it back. The
# resident's walk reads five levels, so nothing below that is scanned anyway,
# and a response nested past the decoder's own recursion limit would cost the
# review rather than widen it.
_CODEX_TOOL_RESPONSE_MAX_NESTING = 64


def _codex_json_nesting_exceeds(value: object, limit: int, depth: int = 0) -> bool:
    """Whether ``value`` nests deeper than ``limit`` containers."""

    if depth > limit:
        return True
    if isinstance(value, Mapping):
        return any(_codex_json_nesting_exceeds(child, limit, depth + 1) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_codex_json_nesting_exceeds(child, limit, depth + 1) for child in value)
    return False


def _codex_tool_response_within_budget(body: Mapping[str, object], value: object) -> object | None:
    """The tool response to send whole beside ``body``, or ``None`` when it cannot travel.

    The response is kept back whenever adding it would cost the review rather
    than widen it: when the packed request would pass the resident's bound,
    when the response nests past what the decoder accepts, or when it holds
    something this side cannot encode at all, such as a lone surrogate or a
    non-finite number. In every one of those cases the request still carries
    the flattened text every caller sent before the resident could read the
    response itself.
    """

    if value is None:
        return None
    if _codex_json_nesting_exceeds(value, _CODEX_TOOL_RESPONSE_MAX_NESTING):
        return None
    packed = dict(body)
    packed["tool_response"] = value
    try:
        encoded = json.dumps(packed, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        return None
    if len(encoded) > _CODEX_POST_TOOL_REQUEST_BUDGET:
        return None
    return value


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
    body: dict[str, object] = {
        "harness_label": harness_label,
        "tool_label": tool_label,
        "tool_name": payload.get("tool_name"),
        "tool_input": payload.get("tool_input"),
        "arguments": payload.get("arguments"),
        "tool_input_present": "tool_input" in payload,
        "response_text": response_text,
        "cwd": None if cwd is None else anchor_to_process_directory(cwd),
        "home_dir": None if home_dir is None else anchor_to_process_directory(home_dir),
        "deadline_ms": 8_000,
    }
    # The flattened text is still sent, because only this side knows what it
    # appended to the response. The response itself travels whole beside it so
    # the resident decides what the scan reads, rather than trusting whichever
    # caller flattened it. It travels only when it fits: the resident refuses a
    # request over its bound, and a refused review is worse than the flattened
    # text every caller sent before the resident could read the response.
    whole_response = _codex_tool_response_within_budget(body, payload.get("tool_response"))
    if whole_response is not None:
        body["tool_response"] = whole_response
    answer = codex_tool_output_native(
        "post_tool_output",
        body=body,
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
    "_string_list",
]
