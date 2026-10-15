"""Immutable, lossless evidence contract for command safety extensions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from codex_plugin_scanner.guard.action_lattice import is_guard_action
from codex_plugin_scanner.guard.models import GuardAction

_STABLE_ID: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*")
_SEMANTIC_VERSION: Final[re.Pattern[str]] = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    + r"(?:-[0-9a-z]+(?:[.-][0-9a-z]+)*)?(?:\+[0-9a-z]+(?:[.-][0-9a-z]+)*)?"
)


class EvidenceSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ExtensionRuleIdentity:
    extension_id: str
    extension_version: str
    rule_id: str
    rule_version: str

    def __post_init__(self) -> None:
        _require_stable_id(self.extension_id, "extension_id")
        _require_stable_id(self.rule_id, "rule_id")
        _require_stable_version(self.extension_version, "extension_version")
        _require_stable_version(self.rule_version, "rule_version")
        if not self.rule_id.startswith(f"{self.extension_id}."):
            raise ValueError("rule_id must be owned by extension_id")


def _require_stable_id(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable lowercase identifier")


def _require_stable_version(value: object, label: str) -> None:
    if not isinstance(value, str) or _SEMANTIC_VERSION.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable semantic version")


def _require_non_empty_frozenset(value: object, label: str) -> frozenset[object]:
    if not isinstance(value, frozenset) or not value:
        raise ValueError(f"{label} must be a non-empty frozenset")
    return value


def _require_enum_tuple(value: object, enum_type: type[Enum], label: str) -> None:
    items = _require_tuple(value, label)
    if any(not isinstance(item, enum_type) for item in items):
        raise ValueError(f"{label} members must be {enum_type.__name__} values")
    if len(items) != len(set(items)):
        raise ValueError(f"{label} cannot contain duplicates")


def _require_tuple(value: object, label: str) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{label} must be a tuple")
    return cast(tuple[object, ...], value)


def _require_guard_action(value: object, label: str) -> GuardAction:
    if not is_guard_action(value):
        raise ValueError(f"{label} must be a canonical GuardAction")
    return value


def _require_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{label} must be an exact {enum_type.__name__} value")


def _require_enum_frozenset(value: object, enum_type: type[Enum], label: str) -> None:
    items = _require_non_empty_frozenset(value, label)
    if any(not isinstance(item, enum_type) for item in items):
        raise ValueError(f"{label} members must be {enum_type.__name__} values")
