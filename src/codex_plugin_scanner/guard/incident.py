"""User-facing incident summaries for blocked Guard artifacts."""

from __future__ import annotations

from pathlib import Path

from .models import GuardAction, GuardArtifact

_HARNESS_LABELS = {
    "codex": "Codex",
    "claude-code": "Claude Code",
    "cursor": "Cursor",
    "gemini": "Gemini",
    "opencode": "OpenCode",
}

_ARTIFACT_LABELS = {
    "mcp_server": "MCP server",
    "hook": "Hook",
    "agent": "Agent",
    "command": "Command",
    "prompt_request": "Prompt request",
    "file_read_request": "File read request",
    "artifact": "Artifact",
}


def build_incident_context(
    *,
    harness: str,
    artifact: GuardArtifact | None,
    artifact_id: str,
    artifact_name: str,
    artifact_type: str | None,
    source_scope: str | None,
    config_path: str | None,
    changed_fields: list[str],
    policy_action: GuardAction,
    launch_target: str | None,
    risk_summary: str | None,
) -> dict[str, str]:
    harness_label = _HARNESS_LABELS.get(harness, harness.title())
    artifact_label = _ARTIFACT_LABELS.get(artifact_type or "artifact", "Artifact")
    normalized_scope = source_scope or "project"
    if artifact_type == "prompt_request":
        source_label = f"{harness_label} session prompt"
        trigger_summary = (
            f"Guard paused the {artifact_label} `{artifact_name or artifact_id}` from the active "
            f"{harness_label} prompt."
        )
    elif artifact_type == "file_read_request":
        source_label = f"{harness_label} runtime tool call"
        trigger_summary = (
            f"Guard paused the {artifact_label} `{artifact_name or artifact_id}` from an active "
            f"{harness_label} tool call."
        )
    else:
        short_config_path = _short_config_path(config_path)
        source_label = f"{normalized_scope} {harness_label} config"
        action_verb = _trigger_verb(policy_action=policy_action, changed_fields=changed_fields)
        trigger_summary = (
            f"Guard {action_verb} the {artifact_label} `{artifact_name or artifact_id}` from "
            f"`{short_config_path}` for {harness_label}."
        )
    why_now = _why_now_text(changed_fields, policy_action, harness_label)
    launch_summary = _launch_summary(artifact=artifact, launch_target=launch_target)
    risk_headline = risk_summary or "Guard could not classify a high-confidence secret or network signal."
    return {
        "artifact_label": artifact_label,
        "source_label": source_label,
        "trigger_summary": trigger_summary,
        "why_now": why_now,
        "launch_summary": launch_summary,
        "risk_headline": risk_headline,
    }


def _why_now_text(changed_fields: list[str], policy_action: GuardAction, harness_label: str) -> str:
    normalized = {field.strip().lower() for field in changed_fields}
    if len(normalized) == 0 and policy_action == "allow":
        return "Guard matched an existing allow rule for this exact version, so the launch can continue."
    if "prompt_request" in normalized:
        return (
            "The prompt asks the agent to read a local .env file directly, "
            "so Guard paused it until you approve that secret access."
        )
    if "file_read_request" in normalized:
        return "The tool requested a protected local secret file, so Guard paused the read until you approve it."
    if "first_seen" in normalized:
        return f"It is new in this {harness_label.lower()} workspace, so Guard paused it for review."
    if "removed" in normalized:
        return "It disappeared from the harness config, so Guard paused the change until you confirm the removal."
    if "command" in normalized or "args" in normalized:
        return "Its launch command changed, so Guard is treating this as a new executable fingerprint."
    if "url" in normalized or "transport" in normalized:
        return "Its connection target changed, so Guard is treating this as a new remote endpoint."
    if "publisher" in normalized:
        return "Its publisher or source changed, so Guard needs a fresh trust decision."
    if policy_action == "sandbox-required":
        return "Guard requires extra isolation before this launch can continue."
    if policy_action == "block":
        return "Guard blocked this definition because the configured policy does not trust it yet."
    return "Guard found a meaningful config change and paused the launch for review."


def _trigger_verb(*, policy_action: GuardAction, changed_fields: list[str]) -> str:
    if len(changed_fields) == 0 and policy_action == "allow":
        return "matched"
    if policy_action == "allow":
        return "reviewed"
    return "paused"


def _launch_summary(*, artifact: GuardArtifact | None, launch_target: str | None) -> str:
    if artifact is not None:
        request_summary = artifact.metadata.get("request_summary")
        if isinstance(request_summary, str) and request_summary:
            return request_summary
        prompt_summary = artifact.metadata.get("prompt_summary")
        if isinstance(prompt_summary, str) and prompt_summary:
            return prompt_summary
        if artifact.url:
            return f"Connects to `{artifact.url}`."
        if artifact.command:
            command_parts = [artifact.command, *artifact.args]
            return f"Launches with `{_truncate(' '.join(command_parts))}`."
    if launch_target:
        return f"Launches with `{_truncate(launch_target)}`."
    return "Launch details were not available."


def _short_config_path(config_path: str | None) -> str:
    if not config_path:
        return "unknown config"
    path = Path(config_path)
    parts = path.parts
    if ".codex" in parts:
        index = parts.index(".codex")
        return str(Path(*parts[index:]))
    if ".claude" in parts:
        index = parts.index(".claude")
        return str(Path(*parts[index:]))
    if ".opencode" in parts:
        index = parts.index(".opencode")
        return str(Path(*parts[index:]))
    if len(parts) >= 3:
        return str(Path(*parts[-3:]))
    if len(parts) >= 2:
        return str(Path(*parts[-2:]))
    return path.name or config_path


def _truncate(value: str, limit: int = 140) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 1]}…"
