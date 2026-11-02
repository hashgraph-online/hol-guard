"""Per-harness protection posture overrides.

The machine-wide ``protection_posture`` stays the baseline. A harness may carry
its own override (``watch``, ``protected`` or ``extra_careful``); a harness
without one inherits the baseline. Overrides live in ``config.toml`` under
``[harness_postures]`` with a per-harness ``[harness_watch_entered_at]`` stamp
for the 24h auto-revert. Writes go through ``update_guard_settings`` so the
approval gate and managed-policy locks apply exactly as they do to the global
posture.

Which posture an override actually resolves to is decided by the native
runtime: this module loads and stores the overrides and renders them, but it
never ranks two postures or derives a mode from one.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, NamedTuple, TypeGuard, cast

from .adapters.contracts import HARNESS_CONTRACTS, contract_for
from .config_file_io import ConfigFileTrustError
from .native_guard_config import resolve_native_guard_config
from .protection_posture import (
    VALID_PROTECTION_POSTURES,
    coerce_protection_posture,
)

if TYPE_CHECKING:
    from .config import GuardConfig
    from .models import GuardMode

HARNESS_POSTURES_KEY = "harness_postures"
HARNESS_WATCH_ENTERED_AT_KEY = "harness_watch_entered_at"
HARNESS_POSTURE_INHERIT = "inherit"
# A managed lock on any of these also locks per-harness overrides, because a
# per-harness Watch would otherwise route around the locked baseline.
HARNESS_POSTURE_LOCK_KEYS = frozenset({"protection_posture", "mode", "security_level", HARNESS_POSTURES_KEY})
# The fields `config_for_harness` reads off one harness's resolved posture.
_VIEW_FIELDS = ("posture", "mode", "security_level")


def known_harness_ids() -> tuple[str, ...]:
    return tuple(contract.harness for contract in HARNESS_CONTRACTS)


def canonical_harness_id(value: object) -> str | None:
    """Return the registry harness id for an id or install alias, else None."""

    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace("_", "-")
    contract = contract_for(key) if key else None
    return contract.harness if contract is not None else None


def runtime_harness_key(value: object) -> str | None:
    """Normalize a runtime harness name; unknown names simply match no override."""

    if not isinstance(value, str):
        return None
    key = value.strip().lower().replace("_", "-")
    if not key:
        return None
    contract = contract_for(key)
    return contract.harness if contract is not None else key


def protection_settings_payload(posture: object, *, harness: object, inherit: bool) -> dict[str, object]:
    """Settings payload for ``settings set protection [--harness ID [--inherit]]``."""

    if harness is None:
        if inherit:
            raise ValueError("--inherit needs --harness.")
        return {"protection_posture": coerce_protection_posture(posture)}
    harness_id = canonical_harness_id(harness)
    if harness_id is None:
        raise ValueError("Unknown Guard harness for protection posture.")
    if inherit:
        if posture is not None:
            raise ValueError("--inherit cannot be combined with a posture.")
        return {HARNESS_POSTURES_KEY: {harness_id: None}}
    return {HARNESS_POSTURES_KEY: {harness_id: coerce_protection_posture(posture)}}


def managed_locks_harness_postures(locked_settings: Iterable[str]) -> bool:
    return bool(HARNESS_POSTURE_LOCK_KEYS & set(locked_settings))


def harness_posture_override(config: GuardConfig, harness: object) -> str | None:
    key = runtime_harness_key(harness)
    postures = getattr(config, "harness_postures", None)
    if key is None or not isinstance(postures, Mapping):
        return None
    value = postures.get(key)
    return value if isinstance(value, str) else None


class _Postures(NamedTuple):
    """One native posture resolution: the baseline and what it resolves to."""

    baseline: str
    effective: Mapping[str, str]
    views: Mapping[str, Mapping[str, str]]


def _resolved_postures(config: GuardConfig) -> _Postures:
    """The native per-harness posture resolution for ``config``.

    The runtime ranks each override against the baseline and derives the mode
    and security level an override implies. Nothing here compares two postures
    or turns one into a mode, so a harness view and the verdicts taken under it
    come from the same evaluator. Resolutions are memoized per request, so the
    repeated lookups on the hot path cost one native call.
    """

    result = resolve_native_guard_config(
        "harness_postures",
        {
            "postures": {
                "protection_posture": config.protection_posture,
                "mode": config.mode,
                "security_level": config.security_level,
                # Only well-formed entries are sent; a malformed one overrides
                # nothing, exactly as ``harness_posture_override`` reads it.
                "harness_postures": {
                    harness: posture
                    for harness, posture in (config.harness_postures or {}).items()
                    if isinstance(harness, str) and isinstance(posture, str)
                },
            }
        },
    )
    baseline = result.get("baseline")
    effective = result.get("effective")
    views = result.get("views")
    if (
        not isinstance(baseline, str)
        or baseline not in VALID_PROTECTION_POSTURES
        or not _is_posture_map(effective)
        # A missing harness would silently read as the baseline, which is the
        # one answer an override exists to change.
        or not set(effective).issuperset(known_harness_ids())
        or not _is_view_map(views)
    ):
        raise ConfigFileTrustError("native_guard_config_invalid")
    return _Postures(baseline=baseline, effective=effective, views=views)


def _is_posture_map(value: object) -> TypeGuard[Mapping[str, str]]:
    return isinstance(value, Mapping) and all(
        isinstance(harness, str) and isinstance(posture, str) for harness, posture in value.items()
    )


def _is_view_map(value: object) -> TypeGuard[Mapping[str, Mapping[str, str]]]:
    return isinstance(value, Mapping) and all(
        isinstance(harness, str)
        and isinstance(view, Mapping)
        and all(isinstance(view.get(field), str) for field in _VIEW_FIELDS)
        for harness, view in value.items()
    )


def effective_harness_posture(config: GuardConfig, harness: object) -> str:
    """Posture that actually governs one harness."""

    resolved = _resolved_postures(config)
    key = runtime_harness_key(harness)
    if key is None:
        return resolved.baseline
    return resolved.effective.get(key, resolved.baseline)


def config_for_harness(config: GuardConfig, harness: object) -> GuardConfig:
    """Config as one harness sees it, for runtime paths that read ``mode``.

    Returns ``config`` unchanged unless the harness carries an override, so the
    hot path and every un-overridden harness are byte-for-byte unaffected.
    Asking the runtime first would fail launch when that resolution is
    unavailable, even for a harness that inherits the baseline.
    """

    if harness_posture_override(config, harness) is None:
        return config
    key = runtime_harness_key(harness)
    view = _resolved_postures(config).views.get(key) if key is not None else None
    if view is None:
        return config
    return replace(
        config,
        protection_posture=view["posture"],
        protection_posture_explicit=True,
        mode=cast("GuardMode", view["mode"]),
        security_level=view["security_level"] or config.security_level,
    )


def effective_harness_postures(config: GuardConfig) -> dict[str, str]:
    effective = _resolved_postures(config).effective
    return {harness: effective[harness] for harness in known_harness_ids()}


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def watch_auto_revert_due(config: GuardConfig, *, now: datetime | None = None) -> tuple[bool, tuple[str, ...]]:
    """Whether the machine-wide Watch posture and which harness overrides are due to revert.

    The runtime dates each revert, so only the clock is read here and the native answer stays
    memoized for an unchanged configuration. A naive ``now`` is read as UTC, like a naive stamp.
    """

    result = resolve_native_guard_config(
        "watch_auto_revert_deadlines",
        {
            "watch": {
                "auto_revert_hours": config.watch_auto_revert_hours,
                "protection_posture": config.protection_posture,
                "watch_entered_at": config.watch_entered_at,
                "harness_postures": dict(config.harness_postures or {}),
                "harness_watch_entered_at": dict(config.harness_watch_entered_at or {}),
            }
        },
    )
    posture_at = result.get("protection_posture")
    harness_at = result.get("harnesses")
    deadlines = cast("dict[object, object]", harness_at) if isinstance(harness_at, dict) else None
    if (
        deadlines is None
        or not all(isinstance(key, str) and type(at) is int for key, at in deadlines.items())
        or not (posture_at is None or type(posture_at) is int)
    ):
        raise ConfigFileTrustError("native_guard_config_invalid")
    current = now or datetime.now(timezone.utc)
    clock = (current.replace(tzinfo=current.tzinfo or timezone.utc) - _EPOCH) // timedelta(microseconds=1)
    due = tuple(sorted(key for key, at in cast("dict[str, int]", deadlines).items() if clock >= at))
    return posture_at is not None and clock >= posture_at, due


def harness_posture_summary(config: GuardConfig) -> dict[str, object]:
    """Compact per-harness fields merged into status/doctor payloads.

    ``harness_postures`` lists only harnesses with their own override;
    ``harnesses_in_watch`` lists every harness whose hooks currently only record.
    """

    overrides = dict(sorted((config.harness_postures or {}).items()))
    effective = _resolved_postures(config).effective
    return {
        "harness_postures": overrides,
        "harnesses_in_watch": [h for h in known_harness_ids() if effective.get(h) == "watch"],
    }


def harness_posture_line(payload: Mapping[str, object]) -> str:
    """Status-panel line listing per-app overrides, or empty when there are none."""

    overrides = payload.get("harness_postures")
    if not isinstance(overrides, Mapping) or not overrides:
        return ""
    parts = ", ".join(f"{harness} {str(posture).replace('_', ' ')}" for harness, posture in sorted(overrides.items()))
    return f"\nper app: {parts}"


def harness_posture_status(config: GuardConfig) -> list[dict[str, object]]:
    """Per-harness rows for status output and the settings surface."""

    rows: list[dict[str, object]] = []
    overrides = config.harness_postures or {}
    stamps = config.harness_watch_entered_at or {}
    resolved = _resolved_postures(config)
    for harness in known_harness_ids():
        override = overrides.get(harness)
        rows.append(
            {
                "harness": harness,
                "posture": resolved.effective.get(harness, resolved.baseline),
                "override": override,
                "inherited": override is None,
                "watch_entered_at": stamps.get(harness),
            }
        )
    return rows


__all__ = [
    "HARNESS_POSTURES_KEY",
    "HARNESS_POSTURE_INHERIT",
    "HARNESS_WATCH_ENTERED_AT_KEY",
    "VALID_PROTECTION_POSTURES",
    "canonical_harness_id",
    "config_for_harness",
    "effective_harness_posture",
    "effective_harness_postures",
    "harness_posture_line",
    "harness_posture_override",
    "harness_posture_status",
    "harness_posture_summary",
    "known_harness_ids",
    "managed_locks_harness_postures",
    "protection_settings_payload",
    "runtime_harness_key",
    "watch_auto_revert_due",
]
