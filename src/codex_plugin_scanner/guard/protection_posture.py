"""Machine-wide protection posture and dual-write to legacy mode/level."""

from __future__ import annotations

from .models import GuardMode

VALID_PROTECTION_POSTURES = frozenset({"protected", "extra_careful", "watch"})
DEFAULT_PROTECTION_POSTURE = "protected"
DEFAULT_WATCH_AUTO_REVERT_HOURS = 24
MAX_WATCH_AUTO_REVERT_HOURS = 168
HIGH_CONFIDENCE_LABELS = frozenset({"strong"})

POSTURE_COPY: dict[str, dict[str, str]] = {
    "protected": {
        "label": "Protected",
        "help": (
            "Stops theft, wipes, and Guard bypass. Asks once about new tools or "
            "first-time secret access, then remembers."
        ),
    },
    "extra_careful": {
        "label": "Extra careful",
        "help": (
            "Same as Protected, and also asks the first time this project talks to a new site or installs a new tool."
        ),
    },
    "watch": {
        "label": "Watch",
        "help": ("Records what Guard would have stopped, but does not stop anything. Use only while debugging."),
    },
}


def normalize_protection_posture(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().replace("-", "_").lower()
    if normalized in VALID_PROTECTION_POSTURES:
        return normalized
    return None


def coerce_protection_posture(value: object) -> str:
    posture = normalize_protection_posture(value)
    if posture is None:
        raise ValueError("Invalid Guard protection posture.")
    return posture


def dual_write_from_posture(
    posture: str,
    *,
    current_security_level: str | None = None,
) -> tuple[GuardMode, str | None]:
    if posture == "watch":
        return "observe", current_security_level
    if posture == "extra_careful":
        return "enforce", "strict"
    return "enforce", "balanced"


def posture_label(posture: str) -> str:
    copy = POSTURE_COPY.get(posture)
    return copy["label"] if copy is not None else posture


def posture_help(posture: str) -> str:
    copy = POSTURE_COPY.get(posture)
    return copy["help"] if copy is not None else ""


def protection_is_off(*, posture: str, mode: str) -> bool:
    return posture == "watch" or mode == "observe"


def protection_status_fields(*, posture: str, mode: str) -> dict[str, object]:
    off = protection_is_off(posture=posture, mode=mode)
    return {
        "protection": posture,
        "protection_label": posture_label(posture),
        "protection_help": posture_help(posture),
        "protection_off": off,
    }
