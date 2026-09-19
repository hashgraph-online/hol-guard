"""Normalize supported harness payloads into typed Guard action envelopes."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from ..adapters.hermes_runtime_hooks import prepare_hermes_hook_payload
from .actions_envelope import _SCHEMA_VERSION, GuardActionEnvelope, GuardActionType, stable_action_hash
from .actions_payload_fields import (
    _action_type,
    _hook_event_name,
    _mcp_details,
    _network_hosts,
    _normalized_shell_command,
    _payload_with_default_event,
    _prompt_value,
    _target_paths,
    _tool_call_from_payload,
    _tool_input_from_payload,
    _tool_name_from_payload,
    _workspace_hash,
    command_text_from_tool_payload,
)
from .actions_payload_fields import (
    _command_from_payload as _command_from_payload,
)
from .actions_payload_fields import (
    apply_patch_target_paths as apply_patch_target_paths,
)
from .actions_redaction import (
    _command_detail,
    _prompt_excerpt,
    _prompt_text,
    _redacted_payload,
    redacted_workspace_label,
)

_GROK_FILE_READ_TOOL_NAMES = frozenset({"grep", "glob", "list_dir", "listdir", "list_directory", "read"})


_GROK_SUBAGENT_TOOL_NAMES = frozenset({"task", "spawn_subagent"})


_GROK_LIFECYCLE_ENVELOPE_EVENTS = frozenset({"SessionStart", "SubagentStart"})


def _package_intent_parser_module():
    return importlib.import_module(".package_intent_parser", __package__)


def normalize_codex_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Codex hook payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="codex",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_claude_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Claude Code hook payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="claude-code",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_opencode_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize an OpenCode runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="opencode",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_copilot_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Copilot runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="copilot",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_gemini_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Gemini runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="gemini",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_hermes_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Hermes runtime payload into a typed action envelope."""
    return _normalize_action_payload(
        prepare_hermes_hook_payload(payload),
        harness="hermes",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_openclaw_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize an OpenClaw runtime payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness="openclaw",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_cursor_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Cursor IDE hook payload into a typed action envelope."""

    from ..adapters.cursor_hooks import prepare_cursor_hook_payload

    return _normalize_action_payload(
        prepare_cursor_hook_payload(payload),
        harness="cursor",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_grok_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Grok Build CLI hook payload into a typed action envelope."""

    from ..adapters.grok_hooks import prepare_grok_hook_payload

    envelope = _normalize_action_payload(
        prepare_grok_hook_payload(payload),
        harness="grok",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )
    if envelope.event_name in _GROK_LIFECYCLE_ENVELOPE_EVENTS:
        return replace(envelope, action_type="config_change")
    if envelope.event_name != "PreToolUse":
        return envelope
    tool_name = (envelope.tool_name or "").lower()
    if tool_name in _GROK_SUBAGENT_TOOL_NAMES:
        return replace(envelope, action_type="prompt")
    if tool_name in _GROK_FILE_READ_TOOL_NAMES:
        return replace(envelope, action_type="file_read")
    return envelope


def normalize_zcode_hook_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a z.ai ZCode hook payload into a typed action envelope.

    ZCode speaks the Claude Code wire protocol, so payloads normalize onto the
    shared Guard shape through the ZCode hook helpers.
    """

    from ..adapters.zcode_hooks import prepare_zcode_hook_payload

    return _normalize_action_payload(
        prepare_zcode_hook_payload(payload),
        harness="zcode",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def _normalize_pi_family_payload(
    payload: Mapping[str, object],
    *,
    harness: str,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Pi-family extension event payload into a typed action envelope."""

    return _normalize_action_payload(
        payload,
        harness=harness,
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


def normalize_pi_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    return _normalize_pi_family_payload(payload, harness="pi", workspace=workspace, home_dir=home_dir)


def normalize_omp_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    return _normalize_pi_family_payload(payload, harness="omp", workspace=workspace, home_dir=home_dir)


def normalize_kimi_payload(
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize a Kimi Code native-hook payload into a typed action envelope."""

    from ..adapters.kimi_hooks import normalize_kimi_prompt

    normalized_payload = dict(payload)
    normalized_payload["prompt"] = normalize_kimi_prompt(normalized_payload.get("prompt"))
    return _normalize_action_payload(
        normalized_payload,
        harness="kimi",
        default_event_name=None,
        workspace=workspace,
        home_dir=home_dir,
    )


_ACTION_PAYLOAD_NORMALIZERS = {
    "codex": normalize_codex_hook_payload,
    "claude": normalize_claude_hook_payload,
    "claude-code": normalize_claude_hook_payload,
    "opencode": normalize_opencode_payload,
    "copilot": normalize_copilot_payload,
    "gemini": normalize_gemini_payload,
    "hermes": normalize_hermes_payload,
    "openclaw": normalize_openclaw_payload,
    "cursor": normalize_cursor_hook_payload,
    "grok": normalize_grok_hook_payload,
    "kimi": normalize_kimi_payload,
    "pi": normalize_pi_payload,
    "omp": normalize_omp_payload,
    "zcode": normalize_zcode_hook_payload,
    "zai": normalize_zcode_hook_payload,
}


def action_envelope_harnesses() -> tuple[str, ...]:
    """Return every harness name accepted by the shared action-envelope boundary."""

    return tuple(_ACTION_PAYLOAD_NORMALIZERS)


def normalize_harness_payload(
    harness: str,
    event_name: str,
    payload: Mapping[str, object],
    *,
    workspace: Path | str | None = None,
    home_dir: Path | str | None = None,
) -> GuardActionEnvelope:
    """Normalize any supported Guard harness payload into a typed action envelope."""

    normalized_harness = harness.strip().lower()
    normalizer = _ACTION_PAYLOAD_NORMALIZERS.get(normalized_harness)
    if normalizer is None:
        raise ValueError(f"Unsupported Guard harness for action normalization: {harness}")
    normalized_payload = _payload_with_default_event(payload, event_name)
    return normalizer(normalized_payload, workspace=workspace, home_dir=home_dir)


def _normalize_action_payload(
    payload: Mapping[str, object],
    *,
    harness: str,
    default_event_name: str | None,
    workspace: Path | str | None,
    home_dir: Path | str | None,
) -> GuardActionEnvelope:
    normalized_payload = dict(payload)
    if default_event_name is not None:
        normalized_payload = _payload_with_default_event(normalized_payload, default_event_name)
    event_name = _hook_event_name(normalized_payload)
    explicit_tool_name = _tool_name_from_payload(normalized_payload)
    tool_call_name, tool_call_input = _tool_call_from_payload(
        normalized_payload.get("toolCalls"),
        expected_tool_name=explicit_tool_name,
    )
    tool_name = explicit_tool_name or tool_call_name
    tool_input = _tool_input_from_payload(normalized_payload)
    if not tool_input and tool_call_input is not None:
        tool_input = tool_call_input
    raw_command = command_text_from_tool_payload(tool_name, tool_input)
    normalized_command, wrapper_chain = _normalized_shell_command(
        tool_name,
        raw_command,
        cwd=Path(workspace) if workspace is not None else None,
        home_dir=Path(home_dir) if home_dir is not None else None,
    )
    if wrapper_chain and isinstance(tool_input, Mapping):
        normalized_payload["tool_input"] = {
            **dict(tool_input),
            "guard_inner_command": normalized_command,
            "guard_shell_wrappers": list(wrapper_chain),
        }
    command = _command_detail(normalized_command, home_dir=home_dir)
    prompt_text = _prompt_text(_prompt_value(normalized_payload))
    prompt_excerpt = _prompt_excerpt(prompt_text)
    mcp_server, mcp_tool = _mcp_details(normalized_payload, tool_name)
    action_type = _action_type(
        event_name=event_name,
        tool_name=tool_name,
        command=normalized_command,
        prompt_excerpt=prompt_excerpt,
        mcp_server=mcp_server,
    )
    target_paths = _target_paths(
        tool_name=tool_name,
        tool_input=tool_input,
        command=normalized_command,
        prompt_text=prompt_text,
        home_dir=home_dir,
    )
    network_hosts = _network_hosts(raw_command, prompt_text)
    workspace_label = redacted_workspace_label(workspace, home_dir=home_dir)
    workspace_hash = _workspace_hash(workspace)
    workspace_path = Path(workspace) if workspace is not None else None
    package_intent = (
        _package_intent_parser_module().parse_package_intent(normalized_command, workspace=workspace_path)
        if normalized_command
        else None
    )
    package_targets = (
        tuple(target.raw_spec for target in package_intent.targets if target.raw_spec)
        if package_intent is not None
        else ()
    )
    primary_package_name = None
    if package_intent is not None:
        for target in package_intent.targets:
            if target.package_name:
                primary_package_name = target.package_name
                break
    return GuardActionEnvelope(
        schema_version=_SCHEMA_VERSION,
        action_id="",
        harness=harness,
        event_name=event_name,
        action_type=action_type,
        workspace=workspace_label,
        workspace_hash=workspace_hash,
        tool_name=tool_name,
        command=command,
        prompt_excerpt=prompt_excerpt,
        prompt_text=prompt_text,
        target_paths=target_paths,
        network_hosts=network_hosts,
        mcp_server=mcp_server,
        mcp_tool=mcp_tool,
        package_manager=package_intent.package_manager if package_intent is not None else None,
        package_name=primary_package_name,
        package_intent_kind=package_intent.intent_kind if package_intent is not None else None,
        package_targets=package_targets,
        pre_execution_result=None,
        script_name=None,
        raw_payload_redacted=_redacted_payload(normalized_payload, home_dir=home_dir),
    )


__all__ = [
    "GuardActionEnvelope",
    "GuardActionType",
    "action_envelope_harnesses",
    "normalize_claude_hook_payload",
    "normalize_codex_hook_payload",
    "normalize_copilot_payload",
    "normalize_gemini_payload",
    "normalize_harness_payload",
    "normalize_opencode_payload",
    "redacted_workspace_label",
    "stable_action_hash",
]
