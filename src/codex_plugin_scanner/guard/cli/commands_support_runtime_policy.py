"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405, I001

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *

def _claude_notification_tool_name(payload: dict[str, object]) -> str | None:
    direct_name = _optional_string(payload.get("tool_name"))
    if direct_name is not None:
        return direct_name
    for key in ("message", "title"):
        value = _optional_string(payload.get(key))
        if value is None:
            continue
        match = re.search(r"\buse\s+([A-Za-z][A-Za-z0-9_]*)\b", value)
        if match is not None:
            return match.group(1)
    return None

def _claude_notification_tool_display_name(payload: dict[str, object]) -> str | None:
    tool_name = _claude_notification_tool_name(payload)
    if tool_name and tool_name.strip():
        return tool_name.strip()
    return None

def _approval_delivery_payload(
    harness: str,
    *,
    managed_install: dict[str, object] | None = None,
) -> dict[str, object]:
    return approval_delivery_payload(approval_prompt_flow(harness, managed_install=managed_install))

def _native_hook_reason(*values: object | None) -> str:
    messages: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            candidate = value.strip()
            if candidate not in messages:
                messages.append(candidate)
    if messages:
        return " ".join(messages)
    return "HOL Guard flagged this tool call for review."

def _ensure_terminal_punctuation(message: str) -> str:
    trimmed = message.strip()
    if trimmed.endswith((".", "!", "?")):
        return trimmed
    return f"{trimmed}."

def _native_hook_reason_for_harness(harness: str, *values: object | None) -> str:
    reason = _native_hook_reason(*values)
    if harness != "codex":
        return reason
    if "open hol guard to approve or keep this blocked:" in reason.lower():
        return reason
    if "approve it in hol guard, then retry." in reason.lower():
        return reason
    if _HOOK_DAEMON_UNREACHABLE_REASON_MARKER in reason.lower():
        return f"{reason} Restart HOL Guard, then retry."
    return f"{reason} Approve it in HOL Guard, then retry."

def _native_approval_center_context(response_payload: dict[str, object], *, harness: str) -> str | None:
    approval_center_url = response_payload.get("approval_center_url")
    if not isinstance(approval_center_url, str) or not approval_center_url.strip():
        return None
    review_url = _preferred_approval_review_url(response_payload, harness=harness) or approval_center_url.strip()
    canonical_harness = _canonical_harness_name(harness)
    harness_label = {
        "claude-code": "Claude Code",
        "codex": "Codex",
        "copilot": "Copilot",
        "guard-cli": "package install",
        "opencode": "OpenCode",
        "kimi": "Kimi",
        "kimi-code": "Kimi Code",
    }.get(canonical_harness, "the harness")
    if canonical_harness in {
        "npm",
        "npx",
        "pnpm",
        "yarn",
        "bun",
        "pip",
        "pip3",
        "pipenv",
        "pipx",
        "poetry",
        "uv",
        "uvx",
        "cargo",
        "go",
        "composer",
        "bundle",
        "mvn",
        "gradle",
    }:
        harness_label = "package install"
    return (
        f"Open HOL Guard to approve or keep this blocked: {review_url}. "
        f"After you choose, retry the same {harness_label} action."
    )

def _localize_pending_approval_copy(response_payload: dict[str, object], *, harness: str) -> None:
    review_context = _native_approval_center_context(response_payload, harness=harness)
    if review_context is None:
        return
    queued = response_payload.get("approval_requests")
    review_url = _preferred_approval_review_url(response_payload, harness=harness)
    if review_url is None:
        return
    decision_v2 = response_payload.get("decision_v2_json")
    if isinstance(decision_v2, dict):
        _localize_decision_v2_review_copy(decision_v2, review_context)
    supply_chain_evaluation = response_payload.get("supply_chain_evaluation")
    if isinstance(supply_chain_evaluation, dict):
        user_copy = supply_chain_evaluation.get("user_copy")
        if isinstance(user_copy, dict):
            harness_message = _optional_string(user_copy.get("harness_message"))
            if harness_message is not None:
                user_copy["harness_message"] = _approval_center_routed_message(harness_message, review_context)
            user_copy["dashboard_url"] = review_url
    if isinstance(queued, list):
        for item in queued:
            if not isinstance(item, dict):
                continue
            decision_v2 = item.get("decision_v2_json")
            if isinstance(decision_v2, dict):
                _localize_decision_v2_review_copy(decision_v2, review_context)

def _localize_decision_v2_review_copy(decision_v2: dict[str, object], review_context: str) -> None:
    harness_message = _optional_string(decision_v2.get("harness_message"))
    if harness_message is not None:
        decision_v2["harness_message"] = _approval_center_routed_message(harness_message, review_context)
    action = _optional_string(decision_v2.get("action"))
    if action in {"ask", "block"}:
        decision_v2["retry_instruction"] = review_context

def _approval_center_routed_message(message: str, review_context: str) -> str:
    normalized = _strip_cloud_inbox_urls(message)
    normalized = normalized.replace("Review this request in HOL Guard, then retry.", "").strip()
    normalized = _strip_legacy_approval_center_sentence(normalized)
    normalized = " ".join(normalized.split())
    normalized = _strip_review_evidence_tail(normalized)
    if not normalized:
        return review_context
    return f"{_ensure_terminal_punctuation(normalized)} {review_context}"

def _strip_review_evidence_tail(message: str) -> str:
    stripped = message.strip()
    lower_stripped = stripped.lower()
    for suffix in ("Review evidence: .", "Review evidence:.", "Review evidence:"):
        if lower_stripped.endswith(suffix.lower()):
            return stripped[: -len(suffix)].rstrip()
    return stripped

def _strip_legacy_approval_center_sentence(message: str) -> str:
    lower_message = message.lower()
    start = lower_message.find("open hol guard to approve or keep this blocked:")
    if start == -1:
        return message.strip()
    retry_start = lower_message.find("after you choose, retry the same ", start)
    if retry_start == -1:
        return message[:start].strip()
    end = lower_message.find(" action.", retry_start)
    if end == -1:
        return message[:start].strip()
    end += len(" action.")
    return f"{message[:start]} {message[end:]}".strip()

def _strip_cloud_inbox_urls(message: str) -> str:
    kept_tokens: list[str] = []
    for token in message.split():
        candidate = token.strip("([{<'\"")
        candidate = candidate.rstrip(")]}>'\".,;:!?")
        if _is_cloud_inbox_url(candidate):
            continue
        kept_tokens.append(token)
    return " ".join(kept_tokens).strip()

def _is_cloud_inbox_url(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme in {"http", "https"} and parsed.path.rstrip("/") == "/guard/inbox"

def _runtime_stored_policy_action(
    *,
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    artifact_id: str,
    artifact_hash: str,
    workspace: str | None,
) -> str | None:
    decision = store.resolve_policy_decision(
        harness,
        artifact_id,
        artifact_hash,
        workspace,
        artifact.publisher,
    )
    if decision is None:
        return None
    action = _optional_string(decision.get("action"))
    if action is None:
        return None
    scope = _optional_string(decision.get("scope"))
    if (
        action in {"allow", "warn", "review"}
        and scope in {"workspace", "publisher", "harness", "global"}
        and _runtime_artifact_risk_classes(artifact)
    ):
        if scope == "workspace":
            decision_artifact_id = _optional_string(decision.get("artifact_id"))
            decision_artifact_hash = _optional_string(decision.get("artifact_hash"))
            if decision_artifact_id == artifact_id and (
                decision_artifact_hash is None or decision_artifact_hash == artifact_hash
            ):
                return action
        return None
    return action

def _runtime_artifact_policy_action(config: GuardConfig, artifact: GuardArtifact, harness: str) -> str:
    if _prompt_requires_hard_block(artifact):
        return "block"
    canonical_harness = _canonical_harness_name(harness)
    risk_classes = _runtime_artifact_risk_classes(artifact)
    has_configured_risk_action = any(
        _resolve_configured_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes
    )
    if has_configured_risk_action:
        risk_actions = [
            _resolve_configured_risk_action(config, risk_class, harness=canonical_harness)
            or resolve_risk_action(config, risk_class, harness=canonical_harness)
            for risk_class in risk_classes
        ]
        resolved_actions = [action for action in risk_actions if action in VALID_GUARD_ACTIONS]
        if resolved_actions:
            return max(resolved_actions, key=guard_action_severity)
    guard_default_action = _runtime_artifact_guard_default_action(artifact)
    risk_actions = [resolve_risk_action(config, risk_class, harness=canonical_harness) for risk_class in risk_classes]
    resolved_actions = [action for action in risk_actions if action in VALID_GUARD_ACTIONS]
    if resolved_actions:
        resolved = max(resolved_actions, key=guard_action_severity)
        if guard_default_action is not None and guard_action_severity(guard_default_action) > guard_action_severity(
            resolved
        ):
            return guard_default_action
        return resolved
    if guard_default_action is not None:
        return guard_default_action
    return SAFE_CHANGED_HASH_ACTION

def _resolve_configured_risk_action(config: GuardConfig, risk_class: str, *, harness: str) -> str | None:
    if config.harness_risk_actions is not None:
        harness_actions = config.harness_risk_actions.get(harness)
        if harness_actions is not None and risk_class in harness_actions:
            return harness_actions[risk_class]
    if config.risk_actions is not None and risk_class in config.risk_actions:
        return config.risk_actions[risk_class]
    return None

def _runtime_artifact_guard_default_action(artifact: GuardArtifact) -> str | None:
    value = artifact.metadata.get("guard_default_action")
    if value in VALID_GUARD_ACTIONS:
        return str(value)
    return None

def _runtime_action_data_flow_signals(
    action_envelope: GuardActionEnvelope | None,
    *,
    workspace: Path | None,
) -> tuple[RiskSignalV2, ...]:
    if action_envelope is None:
        return ()
    return detect_data_flow_exfiltration(action_envelope, workspace=workspace)

def _runtime_data_flow_summary(signals: tuple[RiskSignalV2, ...]) -> str:
    sink_type = _runtime_data_flow_sink_type(signals)
    if signals:
        return f"This command sends local secret to {sink_type}. Guard kept raw secret contents out of the evidence."
    return f"This command sends local secret to {sink_type}."

def _runtime_data_flow_sink_type(signals: tuple[RiskSignalV2, ...]) -> str:
    signal_ids = {signal.signal_id for signal in signals}
    if any(signal.category == "network" for signal in signals):
        return "network host"
    if "data-flow:clipboard-secret" in signal_ids:
        return "clipboard"
    if "data-flow:world-readable-temp-secret" in signal_ids:
        return "world-readable temp file"
    if "data-flow:git-remote-token" in signal_ids:
        return "git remote configuration"
    return "external sink"

def _runtime_artifact_risk_classes(artifact: GuardArtifact) -> list[str]:
    if artifact.artifact_type == "file_read_request":
        return ["local_secret_read"]
    if artifact.artifact_type == "package_request":
        return ["package_script"]
    if artifact.artifact_type == "prompt_request":
        prompt_classes = _prompt_request_classes(artifact)
        risk_classes: list[str] = []
        if "secret_read" in prompt_classes:
            risk_classes.append("local_secret_read")
        if "exfil_intent" in prompt_classes:
            risk_classes.append("credential_exfiltration")
        if "destructive_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        if "subprocess_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        if "prompt_injection_intent" in prompt_classes:
            risk_classes.append("destructive_shell")
        return risk_classes
    if artifact.artifact_type != "tool_action_request":
        return []
    action_class = artifact.metadata.get("action_class")
    if not isinstance(action_class, str):
        return []
    action_risk_classes = {
        "credential exfiltration shell command": [
            "data_flow_exfiltration",
            "credential_exfiltration",
            "network_egress",
        ],
        "docker-sensitive command": ["network_egress", "destructive_shell"],
        "docker client config access": ["local_secret_read"],
        "encoded or encrypted shell command": ["encoded_execution"],
        "shell file upload command": ["credential_exfiltration", "network_egress"],
        "destructive shell command": ["destructive_shell"],
    }
    return action_risk_classes.get(action_class.strip().lower(), [])

def _guard_settings_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "generated_at": _now(),
        "guard_home": str(config.guard_home),
        "config_path": str(config.guard_home / "config.toml"),
        "settings": editable_guard_settings(config),
    }

_PRESET_DESCRIPTIONS: dict[str, str] = {
    "gentle": (
        "Warn-only mode. All risky actions surface as warnings so you stay informed "
        "without blocking any agent workflows."
    ),
    "balanced": (
        "Default preset. High-severity actions (secret reads, exfiltration) require "
        "re-approval; network egress is warned."
    ),
    "strict": (
        "Elevated protection. Data-flow exfiltration is blocked; all other high-risk "
        "actions require explicit re-approval."
    ),
    "paranoid": (
        "Maximum protection. Every risk class is blocked outright. "
        "Recommended for high-security or air-gapped environments."
    ),
    "custom": "Fully custom action map. Each risk class uses the action you configured explicitly.",
}

def _guard_settings_explain_payload(config: GuardConfig) -> dict[str, object]:
    preset = config.security_level
    description = _PRESET_DESCRIPTIONS.get(preset, f"Unknown preset '{preset}'.")
    effective = editable_guard_settings(config).get("risk_actions") or {}
    return {
        "generated_at": _now(),
        "preset": preset,
        "description": description,
        "effective_risk_actions": effective,
    }

def _guard_settings_doctor_payload(config: GuardConfig) -> dict[str, object]:
    issues: list[dict[str, str]] = []
    if config.mode == "observe":
        issues.append(
            {
                "severity": "warning",
                "message": "Guard is in observe mode. No actions will be blocked or reviewed.",
            }
        )
    if config.security_level not in VALID_SECURITY_LEVELS:
        fallback = DEFAULT_SECURITY_LEVEL
        issues.append(
            {
                "severity": "error",
                "message": f"Unknown security level '{config.security_level}'. Falling back to '{fallback}'.",
            }
        )
    if config.approval_wait_timeout_seconds < 10:
        issues.append(
            {
                "severity": "warning",
                "message": (
                    f"approval_wait_timeout_seconds={config.approval_wait_timeout_seconds} is very low. "
                    "Approvals may time out before you can respond."
                ),
            }
        )
    return {
        "generated_at": _now(),
        "issues": issues,
        "healthy": len(issues) == 0,
    }

def _guard_cli_settings_payload(config: GuardConfig) -> dict[str, object]:
    payload = _guard_settings_payload(config)
    settings = payload.get("settings")
    if not isinstance(settings, dict):
        return payload
    cli_settings = dict(settings)
    cli_settings.pop("billing", None)
    return {
        **payload,
        "settings": cli_settings,
    }

def _runtime_detector_registry_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "enabled": config.runtime_detector_registry,
        "debug_trace": config.runtime_detector_debug_trace,
        "timeout_ms": config.runtime_detector_timeout_ms,
        "disabled_detector_ids": list(config.runtime_detector_disabled_ids),
    }

def _runtime_detector_perf_payload(config: GuardConfig) -> list[dict[str, object]]:
    from ..runtime.actions import GuardActionEnvelope
    from ..runtime.detectors import (
        _SLOW_DETECTOR_THRESHOLD_MS,
        DetectorContext,
    )
    from ..runtime.runner import _get_default_detector_registry

    probe_action = GuardActionEnvelope(
        schema_version=1,
        action_id="perf-probe",
        harness="doctor",
        event_name="HarnessStart",
        action_type="harness_start",
        workspace=None,
        workspace_hash=None,
        tool_name=None,
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    probe_context = DetectorContext(
        config=config,
        workspace=None,
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    result = _get_default_detector_registry().run(
        probe_action,
        probe_context,
        timeout_ms=config.runtime_detector_timeout_ms,
        disabled_detector_ids=config.runtime_detector_disabled_ids,
    )
    return [
        {
            **t.to_dict(),
            "slow": t.elapsed_ms >= _SLOW_DETECTOR_THRESHOLD_MS,
        }
        for t in result.telemetry
    ]

__all__ = [
    "_PRESET_DESCRIPTIONS", "_approval_center_routed_message", "_approval_delivery_payload",
    "_claude_notification_tool_display_name", "_claude_notification_tool_name", "_ensure_terminal_punctuation",
    "_guard_cli_settings_payload", "_guard_settings_doctor_payload", "_guard_settings_explain_payload",
    "_guard_settings_payload", "_is_cloud_inbox_url", "_localize_decision_v2_review_copy",
    "_localize_pending_approval_copy", "_native_approval_center_context", "_native_hook_reason",
    "_native_hook_reason_for_harness", "_resolve_configured_risk_action", "_runtime_action_data_flow_signals",
    "_runtime_artifact_guard_default_action", "_runtime_artifact_policy_action", "_runtime_artifact_risk_classes",
    "_runtime_data_flow_sink_type", "_runtime_data_flow_summary", "_runtime_detector_perf_payload",
    "_runtime_detector_registry_payload", "_runtime_stored_policy_action", "_strip_cloud_inbox_urls",
    "_strip_legacy_approval_center_sentence", "_strip_review_evidence_tail",
]
