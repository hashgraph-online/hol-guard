"""Per-harness protection posture overrides.

The machine-wide ``protection_posture`` stays the baseline. A harness may carry
its own override (``watch``, ``protected`` or ``extra_careful``); a harness
without one inherits the baseline. Overrides live in ``config.toml`` under
``[harness_postures]`` with a per-harness ``[harness_watch_entered_at]`` stamp
for the 24h auto-revert. Writes go through ``update_guard_settings`` so the
approval gate and managed-policy locks apply exactly as they do to the global
posture.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from .action_lattice import most_restrictive_guard_action
from .adapters.contracts import HARNESS_CONTRACTS, contract_for
from .models import GuardAction
from .protection_posture import (
    POSTURE_RISK_ACTIONS,
    VALID_PROTECTION_POSTURES,
    coerce_protection_posture,
    dual_write_from_posture,
    normalize_protection_posture,
    protection_is_off,
)

if TYPE_CHECKING:
    from .config import GuardConfig

HARNESS_POSTURES_KEY = "harness_postures"
HARNESS_WATCH_ENTERED_AT_KEY = "harness_watch_entered_at"
HARNESS_POSTURE_INHERIT = "inherit"
# A managed lock on any of these also locks per-harness overrides, because a
# per-harness Watch would otherwise route around the locked baseline.
HARNESS_POSTURE_LOCK_KEYS = frozenset({"protection_posture", "mode", "security_level", HARNESS_POSTURES_KEY})
_POSTURE_STRENGTH = {"watch": 0, "protected": 1, "extra_careful": 2}
_MAX_HARNESS_POSTURES = len(HARNESS_CONTRACTS) * 2


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


def coerce_harness_posture_patch(value: object) -> dict[str, str | None]:
    """Validate a settings write. ``None``/``"inherit"`` clears one harness."""

    if not isinstance(value, Mapping):
        raise ValueError("Harness postures must be a table.")
    patch: dict[str, str | None] = {}
    for key, raw in value.items():
        harness = canonical_harness_id(key)
        if harness is None:
            raise ValueError("Unknown Guard harness for protection posture.")
        if raw is None or (isinstance(raw, str) and raw.strip().lower() == HARNESS_POSTURE_INHERIT):
            patch[harness] = None
            continue
        posture = normalize_protection_posture(raw)
        if posture is None:
            raise ValueError("Invalid Guard protection posture.")
        patch[harness] = posture
    return patch


def coerce_loaded_harness_postures(value: object) -> dict[str, str]:
    """Read stored overrides; anything malformed is dropped (inherits baseline)."""

    if not isinstance(value, Mapping):
        return {}
    postures: dict[str, str] = {}
    for key, raw in value.items():
        harness = canonical_harness_id(key)
        posture = normalize_protection_posture(raw)
        if harness is not None and posture is not None and len(postures) < _MAX_HARNESS_POSTURES:
            postures[harness] = posture
    return postures


def coerce_loaded_harness_watch_entered_at(value: object, postures: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    stamps: dict[str, str] = {}
    for key, raw in value.items():
        harness = canonical_harness_id(key)
        if harness is None or postures.get(harness) != "watch" or not isinstance(raw, str) or not raw.strip():
            continue
        try:
            datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        stamps[harness] = raw.strip()
    return stamps


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


def managed_effective_harness_postures(
    local_postures: Mapping[str, str],
    *,
    locked_settings: Iterable[str],
    managed_settings: Mapping[str, object] | None,
) -> dict[str, str]:
    """Apply managed locks to overrides loaded from the user's own config.

    A locked ``harness_postures`` is replaced by the managed map. Any other
    posture/mode/level lock keeps only strengthening (Extra careful) overrides.
    """

    locked = set(locked_settings)
    if HARNESS_POSTURES_KEY in locked:
        return coerce_loaded_harness_postures((managed_settings or {}).get(HARNESS_POSTURES_KEY))
    if locked & HARNESS_POSTURE_LOCK_KEYS:
        return {harness: posture for harness, posture in local_postures.items() if posture == "extra_careful"}
    return dict(local_postures)


def reject_locked_harness_posture_patch(patch: Mapping[str, str | None], locked_settings: Iterable[str]) -> None:
    if not managed_locks_harness_postures(locked_settings):
        return
    if any(posture not in {None, "extra_careful"} for posture in patch.values()):
        raise ValueError("Managed policy locks prevent per-harness protection overrides.")


def apply_harness_posture_patch(
    next_payload: dict[str, object],
    patch: Mapping[str, str | None],
    *,
    now_iso: str,
) -> dict[str, object]:
    """Merge a validated patch into the config payload and refresh Watch stamps.

    Selecting Watch always stamps the harness, including re-selecting it while
    it is already in Watch, so the 24h revert window restarts.
    """

    updated = dict(next_payload)
    stored = coerce_loaded_harness_postures(updated.get(HARNESS_POSTURES_KEY))
    stamps = coerce_loaded_harness_watch_entered_at(updated.get(HARNESS_WATCH_ENTERED_AT_KEY), stored)
    for harness, posture in patch.items():
        if posture is None:
            stored.pop(harness, None)
            stamps.pop(harness, None)
            continue
        stored[harness] = posture
        if posture == "watch":
            stamps[harness] = now_iso
        else:
            stamps.pop(harness, None)
    for key, value in ((HARNESS_POSTURES_KEY, stored), (HARNESS_WATCH_ENTERED_AT_KEY, stamps)):
        if value:
            updated[key] = dict(sorted(value.items()))
        else:
            updated.pop(key, None)
    return updated


def harness_posture_override(config: GuardConfig, harness: object) -> str | None:
    key = runtime_harness_key(harness)
    postures = getattr(config, "harness_postures", None)
    if key is None or not isinstance(postures, Mapping):
        return None
    value = postures.get(key)
    return value if isinstance(value, str) else None


def global_effective_posture(config: GuardConfig) -> str:
    if protection_is_off(posture=config.protection_posture, mode=config.mode):
        return "watch"
    return config.protection_posture


def effective_harness_posture(config: GuardConfig, harness: object) -> str:
    """Posture that actually governs one harness.

    Watch is always honored. A non-Watch override can turn protection back on
    under a global Watch, but never weakens a stricter global baseline.
    """

    baseline = global_effective_posture(config)
    override = harness_posture_override(config, harness)
    if override is None:
        return baseline
    if override == "watch" or baseline == "watch":
        return override
    return max(baseline, override, key=lambda posture: _POSTURE_STRENGTH.get(posture, 1))


def harness_is_recording_only(config: GuardConfig | None, harness: object) -> bool:
    """True when hooks for this harness record but never stop (Watch)."""

    if config is None:
        return False
    return effective_harness_posture(config, harness) == "watch"


def config_for_harness(config: GuardConfig, harness: object) -> GuardConfig:
    """Config as one harness sees it, for runtime paths that read ``mode``.

    Returns ``config`` unchanged unless the harness carries an override, so the
    hot path and every un-overridden harness are byte-for-byte unaffected.
    """

    if harness_posture_override(config, harness) is None:
        return config
    posture = effective_harness_posture(config, harness)
    mode, security_level = dual_write_from_posture(posture, current_security_level=config.security_level)
    return replace(
        config,
        protection_posture=posture,
        protection_posture_explicit=True,
        mode=mode,
        security_level=security_level or config.security_level,
    )


def effective_harness_postures(config: GuardConfig) -> dict[str, str]:
    return {harness: effective_harness_posture(config, harness) for harness in known_harness_ids()}


def harness_watch_auto_revert_due(
    config: GuardConfig,
    *,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """Harnesses whose own Watch override outlived ``watch_auto_revert_hours``."""

    if config.watch_auto_revert_hours <= 0:
        return ()
    current = now or datetime.now(timezone.utc)
    due: list[str] = []
    for harness, posture in (config.harness_postures or {}).items():
        stamp = (config.harness_watch_entered_at or {}).get(harness)
        if posture != "watch" or stamp is None:
            continue
        entered = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if entered.tzinfo is None:
            entered = entered.replace(tzinfo=timezone.utc)
        if current - entered >= timedelta(hours=config.watch_auto_revert_hours):
            due.append(harness)
    return tuple(sorted(due))


def harness_extra_careful_actions(harnesses: Iterable[str]) -> dict[str, dict[str, GuardAction]]:
    """Strengthening overlay used for harnesses overridden to Extra careful."""

    actions = dict(POSTURE_RISK_ACTIONS["extra_careful"])
    return {harness: dict(actions) for harness in harnesses}


def stricter_risk_action(base: GuardAction | None, floor: GuardAction | None) -> GuardAction | None:
    if base is None:
        return floor
    if floor is None:
        return base
    return most_restrictive_guard_action(base, floor, unknown_action="block")


def harness_posture_summary(config: GuardConfig) -> dict[str, object]:
    """Compact per-harness fields merged into status/doctor payloads.

    ``harness_postures`` lists only harnesses with their own override;
    ``harnesses_in_watch`` lists every harness whose hooks currently only record.
    """

    overrides = dict(sorted((config.harness_postures or {}).items()))
    return {
        "harness_postures": overrides,
        "harnesses_in_watch": [h for h in known_harness_ids() if effective_harness_posture(config, h) == "watch"],
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
    for harness in known_harness_ids():
        override = overrides.get(harness)
        rows.append(
            {
                "harness": harness,
                "posture": effective_harness_posture(config, harness),
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
    "apply_harness_posture_patch",
    "canonical_harness_id",
    "coerce_harness_posture_patch",
    "coerce_loaded_harness_postures",
    "coerce_loaded_harness_watch_entered_at",
    "config_for_harness",
    "effective_harness_posture",
    "effective_harness_postures",
    "global_effective_posture",
    "harness_is_recording_only",
    "harness_posture_line",
    "harness_posture_override",
    "harness_posture_status",
    "harness_posture_summary",
    "harness_watch_auto_revert_due",
    "known_harness_ids",
    "managed_effective_harness_postures",
    "managed_locks_harness_postures",
    "protection_settings_payload",
    "reject_locked_harness_posture_patch",
    "runtime_harness_key",
]
