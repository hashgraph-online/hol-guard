"""Core-owned semantic facts for Everyday action explanations.

Shell commands are interpreted only through Guard's existing side-effect-free canonical
parser and built-in command extension registry. This module does not execute commands and
does not make policy decisions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import PurePath, PureWindowsPath

from .action_explanation_rule_kinds import kind_for_rule
from .command_extension_observations import CommandExtensionObservation
from .command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
)
from .command_model import CanonicalCommand, CommandSegment, parse_shell_command
from .command_rules import CommandSafetyRule
from .kubernetes_commands import kubernetes_secret_read_source


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
        return _unknown_semantics(
            "shell_command",
            actor_label=actor_label,
            reason="command_not_retained",
        )
    command = parse_shell_command(command_text)
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(command)
    effective = tuple(item for item in observations if item.effective_evidence)
    rule_matches = _shell_rule_matches(command_text, effective)
    uncertainty = _shell_uncertainty(command, observations)
    if not rule_matches:
        return _unknown_shell_semantics(
            command,
            actor_label=actor_label,
            uncertainty=uncertainty,
        )
    targets = _shell_targets(command, effective) or _fallback_shell_targets(command)
    return _build_shell_semantics(
        command,
        actor_label=actor_label,
        rule_matches=rule_matches,
        targets=targets,
        uncertainty=uncertainty,
    )


def _shell_rule_matches(
    command_text: str,
    effective: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
) -> tuple[tuple[CommandSafetyExtension, CommandSafetyRule], ...]:
    matches = tuple((item.extension, item.rule) for item in effective)
    if matches:
        return matches
    compatibility = _presentation_compatibility_rule(command_text)
    return (compatibility,) if compatibility is not None else ()


def _shell_uncertainty(
    command: CanonicalCommand,
    observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
) -> tuple[str, ...]:
    reasons = [command.uncertainty_reason] if command.uncertainty_reason else []
    reasons.extend(reason.value for item in observations for reason in item.uncertainty_reasons)
    return tuple(dict.fromkeys(reasons))


def _unknown_shell_semantics(
    command: CanonicalCommand,
    *,
    actor_label: str,
    uncertainty: tuple[str, ...],
) -> ActionExplanationSemantics:
    reason = uncertainty[0] if uncertainty else "semantic_rule_unavailable"
    return replace(
        _unknown_semantics("shell_command", actor_label=actor_label, reason=reason),
        canonical_command=command,
        canonical_identity=command.security_identity,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        uncertainty_reasons=uncertainty or (reason,),
    )


def _fallback_shell_targets(command: CanonicalCommand) -> tuple[ExplanationTarget, ...]:
    if not command.segments:
        return ()
    program = _program_label(command.segments[0])
    return (ExplanationTarget("command", program),) if program else ()


def _build_shell_semantics(
    command: CanonicalCommand,
    *,
    actor_label: str,
    rule_matches: tuple[tuple[CommandSafetyExtension, CommandSafetyRule], ...],
    targets: tuple[ExplanationTarget, ...],
    uncertainty: tuple[str, ...],
) -> ActionExplanationSemantics:
    if len(rule_matches) == 1:
        copy = _single_shell_copy(rule_matches[0], actor_label=actor_label, targets=targets)
    else:
        copy = _compound_shell_copy(rule_matches, actor_label=actor_label)
    kind, headline, summary, impact, recommendation, alternatives, consequences = copy
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
        safer_alternatives=alternatives,
        canonical_command=command,
        canonical_identity=command.security_identity,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        extension_ids=tuple(dict.fromkeys(extension.extension_id for extension, _rule in rule_matches))[:64],
        rule_ids=tuple(dict.fromkeys(rule.rule_id for _extension, rule in rule_matches))[:64],
    )


def _single_shell_copy(
    match: tuple[CommandSafetyExtension, CommandSafetyRule],
    *,
    actor_label: str,
    targets: tuple[ExplanationTarget, ...],
) -> tuple[
    str,
    str,
    str,
    str,
    str,
    tuple[str, ...],
    tuple[ExplanationConsequence, ...],
]:
    extension, rule = match
    alternatives = tuple(rule.safer_alternatives or extension.safer_alternatives)[:12]
    recommendation = alternatives[0] if alternatives else "Review the exact action before continuing."
    program = targets[0].label if targets else "the requested command"
    return (
        kind_for_rule(extension.extension_id, rule),
        rule.title,
        f"{actor_label} wants to run {program}. Guard identified {rule.title.lower()}.",
        rule.description,
        recommendation,
        alternatives,
        (ExplanationConsequence(rule.description, rule.severity),),
    )


def _compound_shell_copy(
    rule_matches: tuple[tuple[CommandSafetyExtension, CommandSafetyRule], ...],
    *,
    actor_label: str,
) -> tuple[
    str,
    str,
    str,
    str,
    str,
    tuple[str, ...],
    tuple[ExplanationConsequence, ...],
]:
    alternatives = tuple(
        dict.fromkeys(
            alternative
            for extension, rule in rule_matches
            for alternative in (rule.safer_alternatives or extension.safer_alternatives)
        )
    )[:12]
    recommendation = alternatives[0] if alternatives else "Review each protected action separately before continuing."
    consequences = tuple(
        ExplanationConsequence(rule.description, rule.severity) for _extension, rule in rule_matches[:16]
    )
    return (
        "compound_action",
        "Run several protected actions",
        f"{actor_label} wants to run a command containing {len(rule_matches)} protected actions.",
        "The command combines multiple actions that can affect files, credentials, systems, or external services.",
        recommendation,
        alternatives,
        consequences,
    )


def _presentation_compatibility_rule(
    command_text: str,
) -> tuple[CommandSafetyExtension, CommandSafetyRule] | None:
    """Project a legacy compatibility rule without changing command enforcement."""

    if kubernetes_secret_read_source(command_text) is None:
        return None
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.kubernetes-secrets")
    rule = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get_rule("command.kubernetes-secrets.secret-read")
    if extension is None or rule is None:
        return None
    return extension, rule


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
            f"{actor_label} wants to perform an action. Guard could not confirm the exact intent from retained facts."
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
    observations: tuple[CommandExtensionObservation[CommandSafetyExtension], ...],
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


def _typed_target(envelope: Mapping[str, object], kind: str) -> ExplanationTarget:
    if kind.startswith("file_"):
        paths = normalized_string_sequence(envelope.get("target_paths"))
        label = f"the item named {_basename(paths[0])}" if paths else "a file or folder Guard could not safely name"
        return ExplanationTarget("filesystem_item", label)
    if kind.startswith("network_"):
        hosts = normalized_string_sequence(envelope.get("network_hosts"))
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


def normalized_string_sequence(value: object) -> tuple[str, ...]:
    """Normalize a bounded sequence of non-empty string values."""

    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())[:32]


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None
