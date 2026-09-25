"""Public operation rows projected from generated command catalog metadata."""

from __future__ import annotations

from .command_extensions import CommandPermissionSpec, CommandSafetyExtension, CommandSafetyRule

_MAX_OPERATIONS = 256
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
_MODE_FLOOR = {"disabled": "allow", "monitor": "warn", "review": "review", "enforce": "block", "required": "review"}


def _bounded(value: str, maximum: int) -> str:
    text = " ".join(value.split())
    return text if len(text) <= maximum else text[: maximum - 1].rstrip() + "…"


def _permission_for_rule(extension: CommandSafetyExtension, rule: CommandSafetyRule) -> CommandPermissionSpec | None:
    return next((permission for permission in extension.permissions if rule.rule_id in permission.rule_ids), None)


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
    """Project bounded UI rows without importing or interpreting matchers."""

    rows: list[dict[str, object]] = []
    for rule in extension.rules[:_MAX_OPERATIONS]:
        permission = _permission_for_rule(extension, rule)
        example = permission.example_command if permission is not None else None
        example = _bounded(example, _MAX_COMMAND) if example else None
        safe_variants: list[str] = []
        for variant in rule.safe_variants:
            label = _bounded(variant.title or variant.variant_id, _MAX_SAFE_VARIANT)
            if label and label not in safe_variants:
                safe_variants.append(label)
            if len(safe_variants) == 8:
                break
        rows.append(
            {
                "id": rule.rule_id,
                "title": _bounded(rule.title, _MAX_TITLE) or rule.rule_id,
                "description": _bounded(rule.description, _MAX_DESCRIPTION) or rule.title,
                "commands": [example] if example else [],
                "example": example,
                "severity": rule.severity,
                "defaultMode": rule.default_mode,
                "defaultAction": _default_action(extension, rule, permission),
                "safeVariants": safe_variants,
                "permissionId": _bounded(permission.permission_id, _MAX_PERMISSION_ID) if permission else None,
            }
        )
    rows.sort(
        key=lambda row: (
            _ACTION_RANK.get(str(row["defaultAction"]), 9),
            _SEVERITY_RANK.get(str(row["severity"]), 9),
            str(row["id"]),
        )
    )
    return rows
