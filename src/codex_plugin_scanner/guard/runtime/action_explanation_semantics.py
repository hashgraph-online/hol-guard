"""Core-owned semantic facts for Everyday action explanations.

Shell commands are interpreted only through Guard's existing side-effect-free canonical
parser and built-in command extension registry. This module does not execute commands and
does not make policy decisions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import PurePath, PureWindowsPath

from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .command_model import CanonicalCommand, CommandSegment, parse_shell_command
from .command_rules import CommandSafetyRule


@dataclass(frozen=True, slots=True)
class ExplanationTarget:
    kind: str
    label: str
    sensitivity: str = "normal"


@dataclass(frozen=True, slots=True)
class ExplanationConsequence:
    message: str
    severity: str


@dataclass(frozen=True, slots=True)
class ActionExplanationSemantics:
    action_type: str
    kind: str
    headline: str
    summary: str
    impact: str
    recommendation: str
    confidence: str
    uncertainty_reasons: tuple[str, ...]
    targets: tuple[ExplanationTarget, ...]
    consequences: tuple[ExplanationConsequence, ...]
    safer_alternatives: tuple[str, ...]
    canonical_command: CanonicalCommand | None = None
    canonical_identity: str | None = None
    catalog_digest: str | None = None
    extension_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()


_KIND_BY_ACTION_TYPE = {
    "file_read": "file_read",
    "file_write": "file_write",
    "file_delete": "file_delete",
    "file_move": "file_move",
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
    "file_read": (
        "Read a file",
        "read",
        "The app can learn information stored in the selected file.",
        "Confirm the file is expected and does not contain private data you did not intend to share.",
        "medium",
    ),
    "file_write": (
        "Change a file",
        "change",
        "Existing file content may be added, replaced, or removed.",
        "Confirm the target and keep a backup of important work.",
        "medium",
    ),
    "file_delete": (
        "Delete a file or folder",
        "delete",
        "Deleted data may be difficult or impossible to recover.",
        "Confirm the target and back up important work first.",
        "high",
    ),
    "file_move": (
        "Move or rename a file",
        "move or rename",
        "Apps or links that expect the previous location may stop working.",
        "Confirm the source and destination before continuing.",
        "medium",
    ),
    "network_read": (
        "Connect to a website or service",
        "contact",
        "The destination can observe request details and return untrusted content.",
        "Confirm the destination is expected and trusted.",
        "medium",
    ),
    "network_send": (
        "Send data to a website or service",
        "send data to",
        "Information can leave this device and may be retained by the destination.",
        "Confirm the destination and the exact data being sent.",
        "high",
    ),
    "mcp_tool": (
        "Use a connected tool",
        "use",
        "The connected tool may act on external accounts, files, or services within its granted capabilities.",
        "Confirm the tool and requested action are expected.",
        "medium",
    ),
    "browser_action": (
        "Use the browser",
        "act on",
        "The action may change a page, account, or information visible in the browser.",
        "Confirm the page and requested browser action.",
        "medium",
    ),
    "prompt_submission": (
        "Send information to an AI app",
        "submit",
        "The submitted information may be processed outside the current local action.",
        "Review the information before sending it.",
        "medium",
    ),
    "package_script": (
        "Run a project or package script",
        "run",
        "The script can change files, start processes, or contact the network.",
        "Inspect the script definition and run only the expected target.",
        "medium",
    ),
    "process_start": (
        "Start an AI app or process",
        "start",
        "The process can use the capabilities granted to it while it runs.",
        "Confirm the app or process is expected.",
        "medium",
    ),
    "system_change": (
        "Change a system setting",
        "change",
        "The change may affect how this device or its protections behave.",
        "Confirm the setting and expected effect before continuing.",
        "high",
    ),
    "extension_change": (
        "Change a Guard protection",
        "change",
        "The change may affect which supported actions Guard detects or interrupts.",
        "Review the exact protection change before saving it.",
        "high",
    ),
    "guard_control_change": (
        "Change Guard protection",
        "change",
        "The change may affect local protection or Guard availability.",
        "Keep protection enabled unless this change is intentional and understood.",
        "critical",
    ),
}


def derive_action_semantics(
    envelope: Mapping[str, object],
    *,
    actor_label: str,
) -> ActionExplanationSemantics:
    action_type = _text(envelope.get("action_type")) or "unknown_action"
    if action_type == "shell_command":
        return _derive_shell_semantics(envelope, actor_label=actor_label)
    kind = _KIND_BY_ACTION_TYPE.get(action_type)
    if kind is None:
        reason = "network_direction_unavailable" if action_type == "network_request" else "semantic_rule_unavailable"
        return _unknown_semantics(action_type, actor_label=actor_label, reason=reason)
    headline, verb, impact, recommendation, severity = _COPY_BY_KIND[kind]
    target = _typed_target(envelope, kind)
    return ActionExplanationSemantics(
        action_type=action_type,
        kind=kind,
        headline=headline,
        summary=f"{actor_label} wants to {verb} {target.label}.",
        impact=impact,
        recommendation=recommendation,
        confidence="derived",
        uncertainty_reasons=(),
        targets=(target,),
        consequences=(ExplanationConsequence(impact, severity),),
        safer_alternatives=(recommendation,),
    )


def _derive_shell_semantics(
    envelope: Mapping[str, object],
    *,
    actor_label: str,
) -> ActionExplanationSemantics:
    command_text = _text(envelope.get("command"))
    if command_text is None:
        return _unknown_semantics("shell_command", actor_label=actor_label, reason="command_not_retained")
    command = parse_shell_command(command_text)
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(command)
    effective = tuple(item for item in observations if item.effective_evidence)
    uncertainty = tuple(
        dict.fromkeys(
            [
                *([command.uncertainty_reason] if command.uncertainty_reason else []),
                *(reason.value for item in observations for reason in item.uncertainty_reasons),
            ]
        )
    )
    if not effective:
        reason = uncertainty[0] if uncertainty else "semantic_rule_unavailable"
        return replace(
            _unknown_semantics("shell_command", actor_label=actor_label, reason=reason),
            canonical_command=command,
            canonical_identity=command.security_identity,
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            uncertainty_reasons=uncertainty or (reason,),
        )

    rule_ids = tuple(dict.fromkeys(item.rule.rule_id for item in effective))[:64]
    extension_ids = tuple(dict.fromkeys(item.extension.extension_id for item in effective))[:64]
    targets = _shell_targets(command, effective)
    if len(effective) == 1:
        item = effective[0]
        rule = item.rule
        kind = _kind_for_rule(item.extension.extension_id, rule)
        headline = rule.title
        program = targets[0].label if targets else "the requested command"
        summary = f"{actor_label} wants to run {program}. Guard identified {rule.title.lower()}."
        impact = rule.description
        alternatives = rule.safer_alternatives or item.extension.safer_alternatives
        recommendation = alternatives[0] if alternatives else "Review the exact action before continuing."
        consequences = (ExplanationConsequence(rule.description, rule.severity),)
    else:
        kind = "compound_action"
        headline = "Run several protected actions"
        summary = f"{actor_label} wants to run a command containing {len(effective)} protected actions."
        impact = (
            "The command combines multiple actions that can affect files, credentials, "
            "systems, or external services."
        )
        alternatives = tuple(
            dict.fromkeys(
                alternative
                for item in effective
                for alternative in (item.rule.safer_alternatives or item.extension.safer_alternatives)
            )
        )[:12]
        recommendation = (
            alternatives[0]
            if alternatives
            else "Review each protected action separately before continuing."
        )
        consequences = tuple(
            ExplanationConsequence(item.rule.description, item.rule.severity)
            for item in effective[:16]
        )

    return ActionExplanationSemantics(
        action_type="shell_command",
        kind=kind,
        headline=headline,
        summary=summary,
        impact=impact,
        recommendation=recommendation,
        confidence="limited" if uncertainty or command.confidence != "exact" else "exact",
        uncertainty_reasons=uncertainty,
        targets=targets or (ExplanationTarget("command", "the requested command", "unknown"),),
        consequences=consequences,
        safer_alternatives=tuple(alternatives)[:12],
        canonical_command=command,
        canonical_identity=command.security_identity,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        extension_ids=extension_ids,
        rule_ids=rule_ids,
    )


def _unknown_semantics(
    action_type: str,
    *,
    actor_label: str,
    reason: str,
) -> ActionExplanationSemantics:
    impact = "The action may change files, accounts, services, or other resources."
    recommendation = "Stop it unless you expected this action, or review the retained technical details."
    return ActionExplanationSemantics(
        action_type=action_type,
        kind="unknown_action",
        headline="Run an action Guard could not fully explain",
        summary=(
            f"{actor_label} wants to perform an action. "
            "Guard could not confirm the exact intent from retained facts."
        ),
        impact=impact,
        recommendation=recommendation,
        confidence="limited",
        uncertainty_reasons=(reason,),
        targets=(ExplanationTarget("action", "an action Guard could not safely label", "unknown"),),
        consequences=(ExplanationConsequence(impact, "high"),),
        safer_alternatives=(recommendation,),
    )


def _shell_targets(
    command: CanonicalCommand,
    observations: tuple[object, ...],
) -> tuple[ExplanationTarget, ...]:
    indexes: list[int] = []
    for observation in observations:
        evidence = getattr(observation, "effective_evidence", ())
        for item in evidence:
            index = getattr(item, "segment_index", None)
            if isinstance(index, int) and index not in indexes:
                indexes.append(index)
    targets: list[ExplanationTarget] = []
    for index in indexes[:16]:
        if not 0 <= index < len(command.segments):
            continue
        program = _program_label(command.segments[index])
        if program and all(target.label != program for target in targets):
            targets.append(ExplanationTarget("command", program))
    return tuple(targets)


def _program_label(segment: CommandSegment) -> str | None:
    if not segment.executable:
        return None
    executable = segment.executable.replace("\\", "/")
    basename = executable.rsplit("/", 1)[-1].strip()
    return f"the {basename} command" if basename else None


def _kind_for_rule(extension_id: str, rule: CommandSafetyRule) -> str:
    rule_id = rule.rule_id.lower()
    action_text = " ".join(rule.action_classes).lower()
    if extension_id == "command.filesystem":
        return "permission_change" if "permission" in rule_id or "ownership" in rule_id else "file_delete"
    if extension_id == "command.git":
        if any(token in rule_id for token in ("force-push", "push", "remote", "fetch")):
            return "git_remote_change"
        if any(token in rule_id for token in ("reset", "rebase", "history", "branch-delete")):
            return "git_history_rewrite"
        if any(token in rule_id for token in ("read", "inspect", "status", "diff", "log", "show")):
            return "git_read"
        return "git_local_change"
    if "secret" in rule_id or "credential" in rule_id or "secret" in action_text or "credential" in action_text:
        return "secret_send" if any(token in rule_id for token in ("send", "upload", "exfil")) else "secret_read"
    if "download" in rule_id and any(token in rule_id for token in ("execute", "script", "pipe")):
        return "download_and_execute"
    if "download" in rule_id:
        return "download"
    if "package" in extension_id or "package" in rule_id:
        if any(token in rule_id for token in ("remove", "uninstall")):
            return "package_remove"
        if "update" in rule_id or "upgrade" in rule_id:
            return "package_update"
        return "package_install"
    if "container" in extension_id or "docker" in rule_id or "podman" in rule_id:
        return "container_change"
    if "kubernetes" in extension_id or "kubectl" in rule_id or "cluster" in action_text:
        return "cluster_change"
    if any(token in extension_id for token in ("cloud", "terraform", "aws", "azure", "gcp")):
        return "cloud_change"
    if "database" in extension_id or "database" in action_text or "sql" in rule_id:
        return "database_read" if "read" in rule_id else "database_change"
    if "guard" in extension_id or "guard" in action_text:
        return "guard_control_change"
    if "windows" in extension_id or "system" in extension_id:
        return "disk_change" if any(token in rule_id for token in ("disk", "partition", "format")) else "system_change"
    if any(token in rule_id for token in ("upload", "egress", "remote-body", "publish")):
        return "network_send"
    return "system_change"


def _typed_target(envelope: Mapping[str, object], kind: str) -> ExplanationTarget:
    if kind.startswith("file_"):
        paths = _strings(envelope.get("target_paths"))
        label = (
            f"the item named {_basename(paths[0])}"
            if paths
            else "a file or folder Guard could not safely name"
        )
        return ExplanationTarget("filesystem_item", label)
    if kind.startswith("network_"):
        hosts = _strings(envelope.get("network_hosts"))
        return ExplanationTarget(
            "network_host",
            f"the service {hosts[0]}" if hosts else "an external service",
        )
    if kind == "mcp_tool":
        server = _text(envelope.get("mcp_server"))
        tool = _text(envelope.get("mcp_tool"))
        label = " / ".join(value for value in (server, tool) if value) or "a connected tool"
        return ExplanationTarget("connected_tool", label)
    if kind == "browser_action":
        return ExplanationTarget("browser", "the current browser context")
    if kind == "package_script":
        script = _text(envelope.get("script_name"))
        return ExplanationTarget("package_script", script or "a project script")
    if kind in {"process_start", "system_change", "extension_change", "guard_control_change"}:
        tool = _text(envelope.get("tool_name"))
        return ExplanationTarget("local_system", tool or "this device")
    if kind == "prompt_submission":
        return ExplanationTarget("prompt", "information prepared for the AI app", "private")
    return ExplanationTarget("action", "an action Guard could not safely label", "unknown")


def _basename(value: str) -> str:
    clean = value.replace("\\", "/").rstrip("/")
    return PurePath(clean).name or PureWindowsPath(value).name or "an item"


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    )[:32]


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
