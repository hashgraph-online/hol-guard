"""User-facing incident summaries for blocked Guard artifacts."""

from __future__ import annotations

from pathlib import Path

from .models import GuardAction, GuardArtifact

_HARNESS_LABELS = {
    "codex": "Codex",
    "claude-code": "Claude Code",
    "copilot": "Copilot CLI",
    "cursor": "Cursor",
    "gemini": "Gemini",
    "opencode": "OpenCode",
    "pi": "Pi",
}

_ARTIFACT_LABELS = {
    "mcp_server": "MCP server",
    "tool_call": "Tool call",
    "hook": "Hook",
    "agent": "Agent",
    "command": "Command",
    "package_request": "Package request",
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
    action_verb = _trigger_verb(policy_action=policy_action, changed_fields=changed_fields)
    if artifact_type == "prompt_request":
        source_label = f"{harness_label} session prompt"
        trigger_summary = (
            f"HOL Guard {action_verb} the {artifact_label} `{artifact_name or artifact_id}` from the active "
            f"{harness_label} prompt."
        )
    elif artifact_type == "file_read_request":
        source_label = f"{harness_label} runtime tool call"
        trigger_summary = (
            f"HOL Guard {action_verb} the {artifact_label} `{artifact_name or artifact_id}` from an active "
            f"{harness_label} tool call."
        )
    elif artifact_type == "tool_action_request":
        source_label = f"{harness_label} runtime tool call"
        trigger_summary = (
            f"HOL Guard {action_verb} the native tool action `{artifact_name or artifact_id}` from an active "
            f"{harness_label} tool call."
        )
    elif artifact_type == "package_request":
        source_label = f"{harness_label} runtime tool call"
        trigger_summary = (
            f"HOL Guard {action_verb} the package request `{artifact_name or artifact_id}` from an active "
            f"{harness_label} tool call."
        )
    else:
        short_config_path = _short_config_path(config_path)
        source_label = f"{normalized_scope} {harness_label} config"
        trigger_summary = (
            f"HOL Guard {action_verb} the {artifact_label} `{artifact_name or artifact_id}` from "
            f"`{short_config_path}` for {harness_label}."
        )
    why_now = _why_now_text(changed_fields, policy_action, harness_label, artifact_type)
    launch_summary = _launch_summary(artifact=artifact, launch_target=launch_target)
    risk_headline = risk_summary or _fallback_risk_headline(policy_action)
    return {
        "artifact_label": artifact_label,
        "source_label": source_label,
        "trigger_summary": trigger_summary,
        "why_now": why_now,
        "launch_summary": launch_summary,
        "risk_headline": risk_headline,
    }


def _fallback_risk_headline(policy_action: GuardAction) -> str:
    match policy_action:
        case "allow":
            return "Policy allows this action; Guard found no high-confidence secret or network signal."
        case "warn":
            return "Policy allows this action with a warning."
        case "review":
            return "Policy requires review before this action can continue."
        case "require-reapproval":
            return "Policy requires fresh approval before this action can continue."
        case "sandbox-required":
            return "Policy requires this action to use an approved sandbox."
        case "block":
            return "Policy blocks this action."


def _why_now_text(
    changed_fields: list[str],
    policy_action: GuardAction,
    harness_label: str,
    artifact_type: str | None,
) -> str:
    normalized = {field.strip().lower() for field in changed_fields}
    if policy_action == "block":
        return "HOL Guard blocked this action because the authoritative policy does not permit it."
    if policy_action == "sandbox-required":
        return "HOL Guard requires an approved sandbox before this action can continue."
    if policy_action in {"allow", "warn"}:
        return _nonblocking_why_now_text(
            normalized=normalized,
            policy_action=policy_action,
            harness_label=harness_label,
            artifact_type=artifact_type,
        )
    if "prompt_request" in normalized:
        return (
            "The prompt asks the agent to read a local .env file directly, "
            "so HOL Guard paused it until you approve that secret access."
        )
    if "file_read_request" in normalized:
        return "The tool requested a protected local secret file, so HOL Guard paused the read until you approve it."
    if artifact_type == "tool_action_request" or "tool_action_request" in normalized:
        return "HOL Guard paused this native tool action because it can change the local machine before you confirm it."
    if artifact_type == "package_request" or "package_request" in normalized:
        return "HOL Guard paused this package change until you confirm the dependency action."
    if "first_seen" in normalized:
        return f"It is new in this {harness_label.lower()} workspace, so HOL Guard paused it for review."
    if "removed" in normalized:
        return "It disappeared from the harness config, so HOL Guard paused the change until you confirm the removal."
    if "command" in normalized or "args" in normalized:
        return "Its launch command changed, so HOL Guard is treating this as a new executable fingerprint."
    if "url" in normalized or "transport" in normalized:
        return "Its connection target changed, so HOL Guard is treating this as a new remote endpoint."
    if "publisher" in normalized:
        return "Its publisher or source changed, so HOL Guard needs a fresh trust decision."
    return "HOL Guard found a meaningful config change and paused the launch for review."


def _nonblocking_why_now_text(
    *,
    normalized: set[str],
    policy_action: GuardAction,
    harness_label: str,
    artifact_type: str | None,
) -> str:
    outcome = (
        "Policy allows the action to continue."
        if policy_action == "allow"
        else "Policy allows the action to continue with a warning."
    )
    if not normalized and policy_action == "allow":
        return "HOL Guard matched an existing allow rule for this exact version. The launch can continue."
    if "removed" in normalized:
        return f"HOL Guard recorded that the artifact was removed from the harness config. {outcome}"
    if "prompt_request" in normalized:
        return f"HOL Guard reviewed the prompt's request to read a local .env file. {outcome}"
    if "file_read_request" in normalized:
        return f"HOL Guard reviewed the request to read a protected local secret file. {outcome}"
    if artifact_type == "tool_action_request" or "tool_action_request" in normalized:
        return f"HOL Guard reviewed this native tool action because it can change the local machine. {outcome}"
    if artifact_type == "package_request" or "package_request" in normalized:
        return f"HOL Guard reviewed this package dependency action. {outcome}"
    if "first_seen" in normalized:
        return f"HOL Guard reviewed this new entry in the {harness_label.lower()} workspace. {outcome}"
    if "command" in normalized or "args" in normalized:
        return f"HOL Guard reviewed the changed executable fingerprint. {outcome}"
    if "url" in normalized or "transport" in normalized:
        return f"HOL Guard reviewed the changed remote endpoint. {outcome}"
    if "publisher" in normalized:
        return f"HOL Guard reviewed the changed publisher or source. {outcome}"
    return f"HOL Guard reviewed a meaningful config change. {outcome}"


def _trigger_verb(*, policy_action: GuardAction, changed_fields: list[str]) -> str:
    if len(changed_fields) == 0 and policy_action == "allow":
        return "matched"
    if policy_action == "allow":
        return "reviewed"
    if policy_action == "warn":
        return "flagged"
    if policy_action == "block":
        return "blocked"
    return "paused"


def _launch_summary(*, artifact: GuardArtifact | None, launch_target: str | None) -> str:
    if launch_target:
        return f"Launches with `{_truncate(launch_target)}`."
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
