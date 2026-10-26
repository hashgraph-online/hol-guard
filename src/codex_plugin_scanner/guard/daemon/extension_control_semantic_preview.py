"""Deterministic semantic preview for extension-control authority mutations.

The preview describes effective consequences without executing commands and without
changing detector metadata. The resident computes it with the same resolver command
enforcement uses, so neither the daemon nor the dashboard carries policy truth.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Final

from ..native_extension_control import preview_control_mutation, preview_event_targets
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_contract import ExtensionControlLayer

SEMANTIC_PREVIEW_SCHEMA: Final = "guard.daemon.extension-control-semantic-preview.v1"
_FIELDS: Final = (
    "schema_version",
    "global_lockdown",
    "changed_target_count",
    "affected_permission_count",
    "affected_rule_count",
    "changed_targets",
    "approval_required",
    "summary",
)


_MAX_CHANGED_TARGETS: Final = 4096
_MAX_LIST_ITEMS: Final = 4096
_MAX_WARNINGS: Final = 64
_TARGET_KINDS: Final = frozenset({"extension", "permission"})
_EXPLICIT_STATES: Final = frozenset({"inherited", "enabled", "disabled"})
_EFFECTIVE_STATES: Final = frozenset({"allowed", "blocked"})
_ID_LISTS: Final = (
    "affected_permission_ids",
    "affected_rule_ids",
    "affected_extension_ids",
    "dependency_permission_ids",
    "implied_permission_ids",
    "conflict_permission_ids",
    "provenance",
)
_OPTIONAL_TARGET_STRINGS: Final = ("baseline_risk", "baseline_floor", "extension_name")
_TARGET_FIELDS: Final = frozenset(
    {
        "target",
        "extension_id",
        "label",
        "before_explicit",
        "after_explicit",
        "before_effective",
        "after_effective",
        "warnings",
        *_ID_LISTS,
    }
)
_COUNT_FIELDS: Final = ("changed_target_count", "affected_permission_count", "affected_rule_count")
_SUMMARY_FIELDS: Final = ("newly_blocked_permissions", "newly_allowed_permissions", "effective_change_count")
_LOCKDOWN_FIELDS: Final = ("before", "after", "changed")
# What an audit event names of one changed target: its opaque reference, how
# its control and effective state changed, and the rules it alone touches.
_EVENT_TARGET_FIELDS: Final = (
    "kind",
    "target_ref",
    "before_explicit",
    "after_explicit",
    "before_effective",
    "after_effective",
    "affected_rule_ids",
)
_MAX_EVENT_TARGETS: Final = 512
_MAX_EVENT_RULE_IDS: Final = 1024
_HEX: Final = frozenset("0123456789abcdef")


def _keys(value: object, required: Iterable[str], optional: Iterable[str] = ()) -> dict[str, object]:
    """``value`` when it is a dict with every required key and no key outside ``required`` and ``optional``."""

    required_keys = set(required)
    if not isinstance(value, dict) or not required_keys <= set(value) <= required_keys | set(optional):
        raise TypeError
    return value


def _count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise TypeError
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _texts(value: object) -> None:
    if not isinstance(value, list) or len(value) > _MAX_LIST_ITEMS:
        raise TypeError
    for item in value:
        _text(item)


def _warning(value: object) -> None:
    entry = _keys(value, ("code", "message"), ("target_id", "count"))
    _text(entry["code"])
    _text(entry["message"])
    if "target_id" in entry:
        _text(entry["target_id"])
    if "count" in entry:
        _count(entry["count"])


def _changed_target(value: object) -> None:
    """The shape of one changed target. Which targets change, and how, is the resident's alone."""

    entry = _keys(value, _TARGET_FIELDS, _OPTIONAL_TARGET_STRINGS)
    target = _keys(entry["target"], ("kind", "target_id"))
    if target["kind"] not in _TARGET_KINDS:
        raise TypeError
    _text(target["target_id"])
    _text(entry["extension_id"])
    _text(entry["label"])
    for name in ("before_explicit", "after_explicit"):
        if entry[name] not in _EXPLICIT_STATES:
            raise TypeError
    for name in ("before_effective", "after_effective"):
        if entry[name] not in _EFFECTIVE_STATES:
            raise TypeError
    for name in _ID_LISTS:
        _texts(entry[name])
    for name in _OPTIONAL_TARGET_STRINGS:
        if name in entry:
            _text(entry[name])
    warnings = entry["warnings"]
    if not isinstance(warnings, list) or len(warnings) > _MAX_WARNINGS:
        raise TypeError
    for warning in warnings:
        _warning(warning)


def _render(value: object, invalid: Callable[[], RuntimeError]) -> dict[str, object]:
    """The resident's preview, in the field order the dashboard renders and digests.

    Checks shape only, all the way down: the dashboard and the apply digest read
    nested fields, so a reply whose nested shape is wrong is refused here rather
    than rendered or hashed. The values are the resident's.
    """

    try:
        fields = _keys(value, _FIELDS)
        if fields["schema_version"] != SEMANTIC_PREVIEW_SCHEMA or type(fields["approval_required"]) is not bool:
            raise TypeError
        counts = {name: _count(fields[name]) for name in _COUNT_FIELDS}
        targets = fields["changed_targets"]
        if (
            not isinstance(targets, list)
            or len(targets) > _MAX_CHANGED_TARGETS
            or counts["changed_target_count"] != len(targets)
        ):
            raise TypeError
        for target in targets:
            _changed_target(target)
        lockdown = _keys(fields["global_lockdown"], _LOCKDOWN_FIELDS)
        if any(type(lockdown[name]) is not bool for name in _LOCKDOWN_FIELDS):
            raise TypeError
        summary = _keys(fields["summary"], _SUMMARY_FIELDS)
        for name in _SUMMARY_FIELDS:
            _count(summary[name])
    except TypeError:
        raise invalid() from None
    return {name: fields[name] for name in _FIELDS}


def build_extension_control_semantic_preview(
    registry: CommandSafetyExtensionRegistry,
    current_layers: tuple[ExtensionControlLayer, ...],
    proposed_layers: tuple[ExtensionControlLayer, ...],
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    return preview_control_mutation(registry, current_layers, proposed_layers, _render, guard_home=guard_home)


def _event_target(value: object) -> dict[str, object]:
    entry = _keys(value, _EVENT_TARGET_FIELDS)
    reference = _text(entry["target_ref"])
    if entry["kind"] not in _TARGET_KINDS or len(reference) != 64 or not set(reference) <= _HEX:
        raise TypeError
    for name in ("before_explicit", "after_explicit"):
        if entry[name] not in _EXPLICIT_STATES:
            raise TypeError
    for name in ("before_effective", "after_effective"):
        if entry[name] not in _EFFECTIVE_STATES:
            raise TypeError
    rule_ids = entry["affected_rule_ids"]
    if not isinstance(rule_ids, list) or len(rule_ids) > _MAX_EVENT_RULE_IDS:
        raise TypeError
    for rule_id in rule_ids:
        _text(rule_id)
    return {name: entry[name] for name in _EVENT_TARGET_FIELDS}


def _render_event_targets(value: object, invalid: Callable[[], RuntimeError]) -> list[dict[str, object]]:
    """The resident's audit projection, in the order the event records it.

    Checks shape only: which targets changed, and how they are named, is the
    resident's. A reply with a target that has no reference, or with more
    targets than one event may hold, is refused here rather than recorded.
    """

    try:
        if not isinstance(value, list) or len(value) > _MAX_EVENT_TARGETS:
            raise TypeError
        return [_event_target(target) for target in value]
    except TypeError:
        raise invalid() from None


def build_extension_control_event_targets(
    registry: CommandSafetyExtensionRegistry,
    current_layers: tuple[ExtensionControlLayer, ...],
    proposed_layers: tuple[ExtensionControlLayer, ...],
    *,
    guard_home: Path | None = None,
) -> list[dict[str, object]]:
    """What the audit event of a committed mutation records of each target it changed."""

    return preview_event_targets(
        registry, current_layers, proposed_layers, _render_event_targets, guard_home=guard_home
    )
