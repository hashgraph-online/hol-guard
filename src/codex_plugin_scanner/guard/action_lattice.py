"""Canonical normalization and ordering for Guard enforcement actions.

Guard actions form a total order from least to most restrictive::

    allow < warn < review < require-reapproval < sandbox-required < block

``require-reapproval`` invalidates a prior grant and requires a fresh user
decision. ``sandbox-required`` additionally requires an enforceable sandbox;
it is therefore strictly stronger and must never collapse to ``review``.

Values crossing an untyped boundary are normalized to ``review`` by default.
This is deliberately fail-closed: an action introduced by a newer producer,
or a malformed action, cannot receive a permissive sentinel rank and lose to
``allow`` or ``warn`` during composition.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, TypeGuard, get_args

from .models import GUARD_ACTION_VALUES, GuardAction

UNKNOWN_GUARD_ACTION_REASON: Final = "guard_action_unknown"
DEFAULT_UNKNOWN_GUARD_ACTION: Final[GuardAction] = "review"

_GUARD_ACTION_SEVERITY: dict[GuardAction, int] = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "require-reapproval": 3,
    "sandbox-required": 4,
    "block": 5,
}

# Exposed read-only for contracts, diagnostics, and exhaustiveness tests. Code
# should compose actions through the helpers below instead of indexing it.
GUARD_ACTION_SEVERITY: Final[Mapping[GuardAction, int]] = MappingProxyType(_GUARD_ACTION_SEVERITY)
GUARD_ACTION_LATTICE: Final[tuple[GuardAction, ...]] = tuple(_GUARD_ACTION_SEVERITY)

if (  # pragma: no cover - import-time invariant
    frozenset(GUARD_ACTION_LATTICE) != frozenset(GUARD_ACTION_VALUES)
    or frozenset(GUARD_ACTION_LATTICE) != frozenset(get_args(GuardAction))
):
    raise RuntimeError("GuardAction values and the canonical action lattice are out of sync")
if tuple(_GUARD_ACTION_SEVERITY.values()) != tuple(range(len(_GUARD_ACTION_SEVERITY))):  # pragma: no cover
    raise RuntimeError("GuardAction severity ranks must be unique and contiguous")


@dataclass(frozen=True, slots=True)
class GuardActionNormalization:
    """Normalized action plus safe diagnostics for an untyped input value."""

    action: GuardAction
    reason_code: str | None
    original_action: str | None
    original_type: str

    @property
    def recognized(self) -> bool:
        return self.reason_code is None


def is_guard_action(value: object) -> TypeGuard[GuardAction]:
    """Return whether ``value`` is an action covered by the canonical lattice."""

    return isinstance(value, str) and value in GUARD_ACTION_SEVERITY


def coerce_guard_action(value: object) -> GuardAction | None:
    """Return a typed action when recognized, otherwise ``None``.

    Use this only when absence is meaningful and the caller supplies its own
    already-typed policy fallback. Untyped enforcement inputs should use
    :func:`normalize_guard_action` so they fail closed.
    """

    return value if is_guard_action(value) else None


def normalize_guard_action_result(
    value: object,
    *,
    unknown_action: GuardAction = DEFAULT_UNKNOWN_GUARD_ACTION,
) -> GuardActionNormalization:
    """Normalize an untyped value and retain stable, non-coercive diagnostics."""

    if not is_guard_action(unknown_action):  # Defensive even for untyped callers.
        raise ValueError(f"unknown_action is not a GuardAction: {unknown_action!r}")
    if is_guard_action(value):
        return GuardActionNormalization(
            action=value,
            reason_code=None,
            original_action=value,
            original_type="str",
        )
    return GuardActionNormalization(
        action=unknown_action,
        reason_code=UNKNOWN_GUARD_ACTION_REASON,
        original_action=value if isinstance(value, str) else None,
        original_type=type(value).__name__,
    )


def normalize_guard_action(
    value: object,
    *,
    unknown_action: GuardAction = DEFAULT_UNKNOWN_GUARD_ACTION,
) -> GuardAction:
    """Return a known action, conservatively normalizing unknown values."""

    return normalize_guard_action_result(value, unknown_action=unknown_action).action


def guard_action_severity(
    action: object,
    *,
    unknown_action: GuardAction = DEFAULT_UNKNOWN_GUARD_ACTION,
) -> int:
    """Return the canonical rank; unknown inputs receive a conservative rank."""

    normalized = normalize_guard_action(action, unknown_action=unknown_action)
    return GUARD_ACTION_SEVERITY[normalized]


def most_restrictive_guard_action(
    *actions: object,
    unknown_action: GuardAction = DEFAULT_UNKNOWN_GUARD_ACTION,
) -> GuardAction:
    """Compose actions using the canonical total order.

    Every provided value is normalized independently. With no candidates, the
    conservative ``unknown_action`` is returned.
    """

    if not actions:
        return normalize_guard_action(None, unknown_action=unknown_action)
    normalized: tuple[GuardAction, ...] = tuple(
        normalize_guard_action(action, unknown_action=unknown_action) for action in actions
    )
    winner: GuardAction = normalized[0]
    for candidate in normalized[1:]:
        if GUARD_ACTION_SEVERITY[candidate] > GUARD_ACTION_SEVERITY[winner]:
            winner = candidate
    return winner
