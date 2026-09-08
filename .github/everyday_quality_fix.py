from pathlib import Path
import re

SEMANTICS = Path("src/codex_plugin_scanner/guard/runtime/action_explanation_semantics.py")
PROJECTION = Path("src/codex_plugin_scanner/guard/runtime/action_explanation_projection.py")
RULE_KINDS = Path("src/codex_plugin_scanner/guard/runtime/action_explanation_rule_kinds.py")
TESTS = Path("tests/test_guard_action_explanation_projection.py")

semantics = SEMANTICS.read_text()
old_import = "from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY\n"
new_import = '''from .action_explanation_rule_kinds import kind_for_rule
from .command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
)
from .kubernetes_commands import kubernetes_secret_read_source
'''
if semantics.count(old_import) != 1:
    raise SystemExit("expected exactly one command extension import")
semantics = semantics.replace(old_import, new_import)

new_derive = '''def _derive_shell_semantics(
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
    effective: tuple[object, ...],
) -> tuple[tuple[CommandSafetyExtension, CommandSafetyRule], ...]:
    matches = tuple((item.extension, item.rule) for item in effective)
    if matches:
        return matches
    compatibility = _presentation_compatibility_rule(command_text)
    return (compatibility,) if compatibility is not None else ()


def _shell_uncertainty(
    command: CanonicalCommand,
    observations: tuple[object, ...],
) -> tuple[str, ...]:
    reasons = [command.uncertainty_reason] if command.uncertainty_reason else []
    reasons.extend(
        reason.value
        for item in observations
        for reason in item.uncertainty_reasons
    )
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
        extension_ids=tuple(
            dict.fromkeys(extension.extension_id for extension, _rule in rule_matches)
        )[:64],
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
    recommendation = (
        alternatives[0]
        if alternatives
        else "Review each protected action separately before continuing."
    )
    consequences = tuple(
        ExplanationConsequence(rule.description, rule.severity)
        for _extension, rule in rule_matches[:16]
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
    rule = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get_rule(
        "command.kubernetes-secrets.secret-read"
    )
    if extension is None or rule is None:
        return None
    return extension, rule
'''
semantics, count = re.subn(
    r"def _derive_shell_semantics\(.*?\n\ndef _unknown_semantics",
    new_derive + "\n\ndef _unknown_semantics",
    semantics,
    flags=re.DOTALL,
)
if count != 1:
    raise SystemExit("expected exactly one shell semantics function")

semantics, count = re.subn(
    r"def _kind_for_rule\(.*?\n\ndef _typed_target",
    "def _typed_target",
    semantics,
    flags=re.DOTALL,
)
if count != 1:
    raise SystemExit("expected exactly one Everyday classifier block")

semantics = semantics.replace(
    '_strings(envelope.get("target_paths"))',
    'normalized_string_sequence(envelope.get("target_paths"))',
)
semantics = semantics.replace(
    '_strings(envelope.get("network_hosts"))',
    'normalized_string_sequence(envelope.get("network_hosts"))',
)
old_sequence = '''def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    )[:32]
'''
new_sequence = '''def normalized_string_sequence(value: object) -> tuple[str, ...]:
    """Normalize a bounded sequence of non-empty string values."""

    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    )[:32]
'''
if semantics.count(old_sequence) != 1:
    raise SystemExit("expected exactly one semantics sequence helper")
SEMANTICS.write_text(semantics.replace(old_sequence, new_sequence))

RULE_KINDS.write_text('''"""Presentation-only mapping from Guard command rules to Everyday action kinds."""

from __future__ import annotations

from .command_rules import CommandSafetyRule


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def _git_rule_kind(rule_id: str) -> str:
    if _contains_any(rule_id, ("force-push", "push", "remote", "fetch")):
        return "git_remote_change"
    if _contains_any(rule_id, ("reset", "rebase", "history", "branch-delete")):
        return "git_history_rewrite"
    if _contains_any(rule_id, ("read", "inspect", "status", "diff", "log", "show")):
        return "git_read"
    return "git_local_change"


def _package_rule_kind(rule_id: str) -> str:
    if _contains_any(rule_id, ("remove", "uninstall")):
        return "package_remove"
    if "update" in rule_id or "upgrade" in rule_id:
        return "package_update"
    return "package_install"


def _filesystem_or_git_kind(
    extension_id: str,
    rule_id: str,
    _action_text: str,
) -> str | None:
    if extension_id == "command.filesystem":
        return (
            "permission_change"
            if "permission" in rule_id or "ownership" in rule_id
            else "file_delete"
        )
    if extension_id == "command.git":
        return _git_rule_kind(rule_id)
    return None


def _sensitive_or_transfer_kind(
    extension_id: str,
    rule_id: str,
    action_text: str,
) -> str | None:
    if _contains_any(rule_id, ("secret", "credential")) or _contains_any(
        action_text, ("secret", "credential")
    ):
        return (
            "secret_send"
            if _contains_any(rule_id, ("send", "upload", "exfil"))
            else "secret_read"
        )
    if "download" in rule_id:
        return (
            "download_and_execute"
            if _contains_any(rule_id, ("execute", "script", "pipe"))
            else "download"
        )
    if "package" in extension_id or "package" in rule_id:
        return _package_rule_kind(rule_id)
    return None


def _infrastructure_rule_kind(
    extension_id: str,
    rule_id: str,
    action_text: str,
) -> str | None:
    if "container" in extension_id or "docker" in rule_id or "podman" in rule_id:
        return "container_change"
    if "kubernetes" in extension_id or "kubectl" in rule_id or "cluster" in action_text:
        return "cluster_change"
    if _contains_any(extension_id, ("cloud", "terraform", "aws", "azure", "gcp")):
        return "cloud_change"
    if "database" in extension_id or "database" in action_text or "sql" in rule_id:
        return "database_read" if "read" in rule_id else "database_change"
    return None


def _system_or_network_rule_kind(
    extension_id: str,
    rule_id: str,
    action_text: str,
) -> str | None:
    if "guard" in extension_id or "guard" in action_text:
        return "guard_control_change"
    if "windows" in extension_id or "system" in extension_id:
        return (
            "disk_change"
            if _contains_any(rule_id, ("disk", "partition", "format"))
            else "system_change"
        )
    if _contains_any(rule_id, ("upload", "egress", "remote-body", "publish")):
        return "network_send"
    return None


def kind_for_rule(extension_id: str, rule: CommandSafetyRule) -> str:
    rule_id = rule.rule_id.lower()
    action_text = " ".join(rule.action_classes).lower()
    classifiers = (
        _filesystem_or_git_kind,
        _sensitive_or_transfer_kind,
        _infrastructure_rule_kind,
        _system_or_network_rule_kind,
    )
    for classifier in classifiers:
        kind = classifier(extension_id, rule_id, action_text)
        if kind is not None:
            return kind
    return "system_change"
''')

projection = PROJECTION.read_text()
old_projection_import = (
    "from .action_explanation_semantics import ActionExplanationSemantics, derive_action_semantics\n"
)
new_projection_import = '''from .action_explanation_semantics import (
    ActionExplanationSemantics,
    derive_action_semantics,
    normalized_string_sequence,
)
'''
if projection.count(old_projection_import) != 1:
    raise SystemExit("expected exactly one semantics import")
projection = projection.replace(old_projection_import, new_projection_import)
projection = projection.replace("_string_sequence(", "normalized_string_sequence(")
old_projection_sequence = '''def normalized_string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    )[:32]


'''
if projection.count(old_projection_sequence) != 1:
    raise SystemExit("expected exactly one projection sequence helper after rename")
PROJECTION.write_text(projection.replace(old_projection_sequence, ""))

tests = TESTS.read_text()
old_test_expression = "str(explanation.everyday.to_dict())"
if tests.count(old_test_expression) != 2:
    raise SystemExit("expected exactly two nested Everyday serialization assertions")
TESTS.write_text(
    tests.replace(old_test_expression, 'str(explanation.to_dict()["everyday"])')
)
