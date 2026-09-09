"""Public command-mapping rows for the extension directory catalog.

These rows document matcher-derived command signatures and catalog default
floors. They are not workspace activation, enablement, or a safety rating.
"""

from __future__ import annotations

from typing import cast

from .command_extensions import CommandSafetyExtension
from .command_matcher_contracts import CommandMatcher
from .command_path_set_matcher import ExecutablePathSetMatcher
from .command_permission_catalog import CommandPermissionSpec
from .command_rules import (
    AllMatcher,
    AnyMatcher,
    ArgumentMatcher,
    CommandRuleMode,
    CommandSafetyRule,
    ExecutableMatcher,
    PipelineMatcher,
    example_for_matcher,
)

_LAUNCHER_SUFFIXES = (".exe", ".cmd")
_MAX_OPERATIONS = 256
_MAX_COMMANDS = 24
_MAX_SAFE_VARIANTS = 8
_MAX_TITLE = 128
_MAX_DESCRIPTION = 400
_MAX_COMMAND = 128
_MAX_SAFE_VARIANT = 64
_MAX_PERMISSION_ID = 288
_ACTION_RANK = {
    "block": 0,
    "require-reapproval": 1,
    "review": 2,
    "sandbox-required": 3,
    "warn": 4,
    "allow": 5,
}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_MODE_FLOOR: dict[CommandRuleMode, str] = {
    "disabled": "allow",
    "monitor": "warn",
    "review": "review",
    "enforce": "block",
    "required": "review",
}


def _bounded(value: str, maximum: int) -> str:
    text = " ".join(value.split())
    if not text:
        return text
    if len(text) <= maximum:
        return text
    return text[: maximum - 1].rstrip() + "…"


def _canonical_executable(names: frozenset[str]) -> str:
    cleaned: set[str] = set()
    for name in names:
        lower = name.strip().lower()
        for suffix in _LAUNCHER_SUFFIXES:
            if lower.endswith(suffix):
                lower = lower[: -len(suffix)]
                break
        if lower:
            cleaned.add(lower)
    if not cleaned:
        return ""
    return sorted(cleaned, key=lambda value: (len(value), value))[0]


def _signature(executable: str, tokens: tuple[str, ...]) -> str | None:
    if not executable:
        return None
    joined = " ".join((executable, *tokens)).strip()
    if not joined or len(joined) > _MAX_COMMAND:
        return None
    return joined


def command_signatures_for_matcher(matcher: object | None, *, limit: int = _MAX_COMMANDS) -> tuple[str, ...]:
    """Return deterministic public command signatures for one matcher tree."""

    found: list[str] = []
    seen: set[str] = set()

    def add(value: str | None) -> None:
        if not value or value in seen or len(found) >= limit:
            return
        seen.add(value)
        found.append(value)

    def walk(node: object | None) -> None:
        if node is None or len(found) >= limit:
            return
        if isinstance(node, ExecutableMatcher):
            add(
                _signature(
                    _canonical_executable(node.executables),
                    (*node.subcommands, *sorted(node.required_flags)),
                )
            )
            return
        if isinstance(node, ExecutablePathSetMatcher):
            executable = _canonical_executable(node.executables)
            flags = tuple(sorted(node.required_flags))
            for path in sorted(node.paths, key=lambda item: (len(item), item)):
                add(_signature(executable, (*path, *flags)))
            return
        if isinstance(node, ArgumentMatcher):
            add(
                _signature(
                    _canonical_executable(node.executables),
                    tuple(sorted(node.required_arguments)),
                )
            )
            return
        if isinstance(node, (AnyMatcher, AllMatcher)):
            for child in node.matchers:
                walk(child)
            return
        if isinstance(node, PipelineMatcher):
            walk(node.producer)
            walk(node.consumer)
            return
        if hasattr(node, "match"):
            add(example_for_matcher(cast(CommandMatcher, node)))

    walk(matcher)
    return tuple(found)


def _required_flags(matcher: object | None) -> tuple[str, ...]:
    flags: set[str] = set()

    def walk(node: object | None) -> None:
        if node is None:
            return
        if isinstance(node, (ExecutableMatcher, ExecutablePathSetMatcher)):
            flags.update(node.required_flags)
            return
        if isinstance(node, (AnyMatcher, AllMatcher)):
            for child in node.matchers:
                walk(child)
            return
        if isinstance(node, PipelineMatcher):
            walk(node.producer)
            walk(node.consumer)

    walk(matcher)
    return tuple(sorted(flags))


def _safe_variant_labels(rule: CommandSafetyRule) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    base_flags = set(_required_flags(rule.matcher))
    for variant in rule.safe_variants:
        added = tuple(flag for flag in _required_flags(variant.matcher) if flag not in base_flags)
        candidates = added or (variant.variant_id,)
        for candidate in candidates:
            label = _bounded(candidate, _MAX_SAFE_VARIANT)
            if not label or label in seen:
                continue
            seen.add(label)
            labels.append(label)
            if len(labels) >= _MAX_SAFE_VARIANTS:
                return labels
    return labels


def _permission_for_rule(extension: CommandSafetyExtension, rule: CommandSafetyRule) -> CommandPermissionSpec | None:
    for permission in extension.permissions:
        if rule.rule_id in permission.rule_ids:
            return permission
    return None


def _default_action(
    extension: CommandSafetyExtension, rule: CommandSafetyRule, permission: CommandPermissionSpec | None
) -> str:
    if extension.required and rule.severity == "critical":
        return "block"
    if extension.required:
        return "review"
    if permission is not None:
        return permission.baseline_floor
    return _MODE_FLOOR[rule.default_mode]


def public_operations(extension: CommandSafetyExtension) -> list[dict[str, object]]:
    """Project inspectable command-mapping rows for one native extension."""

    rows: list[dict[str, object]] = []
    for rule in extension.rules:
        permission = _permission_for_rule(extension, rule)
        commands = list(command_signatures_for_matcher(rule.matcher))
        example = rule.example_command or (commands[0] if commands else None)
        if example:
            example = _bounded(example, _MAX_COMMAND) or None
        title = _bounded(rule.title, _MAX_TITLE) or rule.rule_id
        description = _bounded(rule.description, _MAX_DESCRIPTION) or title
        permission_id = None
        if permission is not None:
            permission_id = _bounded(permission.permission_id, _MAX_PERMISSION_ID) or None
        rows.append(
            {
                "id": rule.rule_id,
                "title": title,
                "description": description,
                "commands": commands,
                "example": example,
                "severity": rule.severity,
                "defaultMode": rule.default_mode,
                "defaultAction": _default_action(extension, rule, permission),
                "safeVariants": _safe_variant_labels(rule),
                "permissionId": permission_id,
            }
        )
        if len(rows) >= _MAX_OPERATIONS:
            break
    rows.sort(
        key=lambda row: (
            _ACTION_RANK.get(str(row["defaultAction"]), 9),
            _SEVERITY_RANK.get(str(row["severity"]), 9),
            str(row["id"]),
        )
    )
    return rows
