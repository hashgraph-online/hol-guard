"""Deterministic projections of persisted Guard action facts into Everyday explanations.

This foundation deliberately uses only typed fields already persisted by Core. It does not
parse shell syntax. Rich command semantics are layered on by the canonical command builder.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath, PureWindowsPath
from typing import cast

from codex_plugin_scanner.guard.redaction import redact_text

from .action_explanation_contract import (
    ACTION_EXPLANATION_REDACTION_VERSION,
    ACTION_EXPLANATION_RENDERER_VERSION,
    ACTION_EXPLANATION_SCHEMA_VERSION,
    ACTION_EXPLANATION_VERSION,
    GuardActionExplanationV1,
    parse_action_explanation,
)

_KIND_BY_ACTION_TYPE = {
    "file_read": "file_read",
    "file_write": "file_write",
    "file_delete": "file_delete",
    "file_move": "file_move",
    "network_request": "network_read",
    "network_read": "network_read",
    "network_send": "network_send",
    "mcp_tool": "mcp_tool",
    "browser_action": "browser_action",
    "prompt": "prompt_submission",
    "prompt_submission": "prompt_submission",
    "package_script": "package_script",
    "harness_start": "process_start",
    "config_change": "system_change",
    "extension_change": "extension_change",
    "guard_control_change": "guard_control_change",
}

_COPY_BY_KIND: dict[str, tuple[str, str, str, str, str]] = {
    "file_read": ("Read a file", "read", "The app can learn information stored in the selected file.", "Confirm the file is expected and does not contain private data you did not intend to share.", "medium"),
    "file_write": ("Change a file", "change", "Existing file content may be added, replaced, or removed.", "Confirm the target and keep a backup of important work.", "medium"),
    "file_delete": ("Delete a file or folder", "delete", "Deleted data may be difficult or impossible to recover.", "Confirm the target and back up important work first.", "high"),
    "file_move": ("Move or rename a file", "move or rename", "Apps or links that expect the previous location may stop working.", "Confirm the source and destination before continuing.", "medium"),
    "network_read": ("Connect to a website or service", "contact", "The destination can observe request details and return untrusted content.", "Confirm the destination is expected and trusted.", "medium"),
    "network_send": ("Send data to a website or service", "send data to", "Information can leave this device and may be retained by the destination.", "Confirm the destination and the exact data being sent.", "high"),
    "mcp_tool": ("Use a connected tool", "use", "The connected tool may act on external accounts, files, or services within its granted capabilities.", "Confirm the tool and requested action are expected.", "medium"),
    "browser_action": ("Use the browser", "act on", "The action may change a page, account, or information visible in the browser.", "Confirm the page and requested browser action.", "medium"),
    "prompt_submission": ("Send information to an AI app", "submit", "The submitted information may be processed outside the current local action.", "Review the information before sending it.", "medium"),
    "package_script": ("Run a project or package script", "run", "The script can change files, start processes, or contact the network.", "Inspect the script definition and run only the expected target.", "medium"),
    "process_start": ("Start an AI app or process", "start", "The process can use the capabilities granted to it while it runs.", "Confirm the app or process is expected.", "medium"),
    "system_change": ("Change a system setting", "change", "The change may affect how this device or its protections behave.", "Confirm the setting and expected effect before continuing.", "high"),
    "extension_change": ("Change a Guard protection", "change", "The change may affect which supported actions Guard detects or interrupts.", "Review the exact protection change before saving it.", "high"),
    "guard_control_change": ("Change Guard protection", "change", "The change may affect local protection or Guard availability.", "Keep protection enabled unless this change is intentional and understood.", "critical"),
}


def project_action_explanation(
    action_envelope: Mapping[str, object] | None,
    *,
    action_identity: str,
    actor_label: str,
    exact_details_authorized: bool = False,
    retained: bool = True,
    receipt_id: str | None = None,
) -> GuardActionExplanationV1 | None:
    """Project persisted typed facts into the v1 contract without reparsing commands."""

    if not isinstance(action_envelope, Mapping) or not action_identity:
        return None
    action_type = _text(action_envelope.get("action_type")) or "unknown_action"
    kind = _KIND_BY_ACTION_TYPE.get(action_type, "unknown_action")
    target_kind, target_label = _safe_target(action_envelope, kind)
    if kind == "unknown_action":
        headline = "Run an action Guard could not fully explain"
        summary = f"{_safe_text(actor_label, 120)} wants to perform an action. Guard could not confirm the exact intent from the retained typed facts."
        impact = "The action may change files, accounts, services, or other resources."
        recommendation = "Stop it unless you expected this action, or review the retained technical details."
        confidence = "limited"
        uncertainty = ["semantic_rule_unavailable"]
        severity = "high"
    else:
        headline, verb, impact, recommendation, severity = _COPY_BY_KIND[kind]
        summary = f"{_safe_text(actor_label, 120)} wants to {verb} {target_label}."
        confidence = "derived"
        uncertainty = []

    raw_command = _text(action_envelope.get("command"))
    command_redaction = redact_text(raw_command) if raw_command else None
    technical_available = bool(retained and exact_details_authorized and raw_command)
    unavailable_reason: str | None
    if technical_available:
        unavailable_reason = None
    elif not retained:
        unavailable_reason = "The exact action was not retained."
    elif raw_command:
        unavailable_reason = "Exact technical details require deliberate local disclosure."
    else:
        unavailable_reason = "No exact command was retained for this action."

    omitted_fields = [] if technical_available else ["technical.command_display"]
    payload: dict[str, object] = {
        "schema_version": ACTION_EXPLANATION_SCHEMA_VERSION,
        "explanation_version": ACTION_EXPLANATION_VERSION,
        "renderer_version": ACTION_EXPLANATION_RENDERER_VERSION,
        "action_identity": _safe_text(action_identity, 512),
        "canonical_identity": None,
        "catalog_digest": None,
        "locale": "en-US",
        "kind": kind,
        "confidence": confidence,
        "uncertainty_reasons": uncertainty,
        "everyday": {
            "headline_message_id": f"guard.everyday.{kind}.headline",
            "headline": headline,
            "summary_message_id": f"guard.everyday.{kind}.summary",
            "summary": _safe_text(summary, 800),
            "impact_message_id": f"guard.everyday.{kind}.impact",
            "impact": impact,
            "why_guard_intervened_message_id": None,
            "why_guard_intervened": None,
            "recommendation_message_id": f"guard.everyday.{kind}.recommendation",
            "recommendation": recommendation,
            "actor_label": _safe_text(actor_label, 120),
            "targets": [{"kind": target_kind, "label": target_label, "scope": None, "sensitivity": "normal"}],
            "consequences": [{"message_id": f"guard.everyday.{kind}.consequence", "message": impact, "severity": severity, "confirmed": False}],
            "safer_alternatives": [{"message_id": f"guard.everyday.{kind}.alternative.review", "message": recommendation, "kind": "review"}],
        },
        "technical": {
            "available": technical_available,
            "unavailable_reason": unavailable_reason,
            "action_type": action_type,
            "command_display": command_redaction.text if technical_available and command_redaction else None,
            "normalized_command_display": None,
            "executable": None,
            "arguments_display": None,
            "dialect": None,
            "transport": None,
            "working_scope_display": None,
            "wrappers": [],
            "segments": [],
            "extension_ids": [],
            "rule_ids": [],
            "reason_codes": [],
            "policy_source": None,
            "parse_confidence": None,
            "proof_level": None,
            "receipt_id": _safe_optional(receipt_id, 256),
            "action_id": _safe_text(action_identity, 512),
        },
        "redaction": {
            "level": "redacted" if (command_redaction and command_redaction.count) or not technical_available else "none",
            "policy_version": ACTION_EXPLANATION_REDACTION_VERSION,
            "omitted_fields": omitted_fields,
            "truncated_fields": [],
            "secret_like_values_removed": bool(command_redaction and command_redaction.count),
        },
    }
    return parse_action_explanation(cast(dict[str, object], payload))


def _safe_target(envelope: Mapping[str, object], kind: str) -> tuple[str, str]:
    if kind.startswith("file_"):
        paths = _strings(envelope.get("target_paths"))
        if paths:
            return "filesystem_item", f"the item named {_basename(paths[0])}"
        return "filesystem_item", "a file or folder Guard could not safely name"
    if kind.startswith("network_"):
        hosts = _strings(envelope.get("network_hosts"))
        return "network_host", f"the service {_safe_text(hosts[0], 253)}" if hosts else "an external service"
    if kind == "mcp_tool":
        server = _safe_optional(_text(envelope.get("mcp_server")), 120)
        tool = _safe_optional(_text(envelope.get("mcp_tool")), 120)
        label = " / ".join(value for value in (server, tool) if value) or "a connected tool"
        return "connected_tool", label
    if kind == "browser_action":
        return "browser", "the current browser context"
    if kind == "package_script":
        script = _safe_optional(_text(envelope.get("script_name")), 120)
        package = _safe_optional(_text(envelope.get("package_name")), 120)
        return "package_script", script or package or "a project script"
    if kind in {"process_start", "system_change", "extension_change", "guard_control_change"}:
        tool = _safe_optional(_text(envelope.get("tool_name")), 120)
        return "local_system", tool or "this device"
    if kind == "prompt_submission":
        return "prompt", "information prepared for the AI app"
    return "action", "an action Guard could not safely label"


def _basename(value: str) -> str:
    clean = value.replace("\\", "/").rstrip("/")
    name = PurePath(clean).name or PureWindowsPath(value).name or "an item"
    return _safe_text(name, 160)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())[:32]


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _safe_optional(value: str | None, limit: int) -> str | None:
    return _safe_text(value, limit) if value else None


def _safe_text(value: str, limit: int) -> str:
    redacted = redact_text(value).text.replace("\n", " ").replace("\r", " ").replace("\x1b", "")
    return redacted[:limit]
