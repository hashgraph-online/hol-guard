"""Presentation preference write validation shared by Guard settings surfaces."""

from __future__ import annotations

from dataclasses import dataclass

from .presentation_mode import (
    PRESENTATION_SCHEMA_VERSION,
    GuardPresentationMode,
    coerce_presentation_mode_write,
)

PRESENTATION_SETTING_INPUT_KEYS = frozenset(
    {"presentation_mode", "presentation_mode_explicit", "presentation_schema_version"}
)


@dataclass(frozen=True, slots=True)
class PresentationSettingsUpdate:
    requested: bool
    changed: bool
    mode: GuardPresentationMode
    explicit: bool


def resolve_presentation_settings_update(
    payload: dict[str, object],
    *,
    current_mode: GuardPresentationMode,
    current_explicit: bool,
    current_revision: int,
) -> PresentationSettingsUpdate:
    requested = bool({"presentation_mode", "presentation_mode_explicit"} & payload.keys())
    if "presentation_revision" in payload and not requested:
        raise ValueError("presentation_revision requires a presentation preference change.")
    if "presentation_schema_version" in payload:
        if not requested:
            raise ValueError("presentation_schema_version requires a presentation preference change.")
        if payload["presentation_schema_version"] != PRESENTATION_SCHEMA_VERSION:
            raise ValueError("Unsupported presentation schema version.")

    mode = current_mode
    if "presentation_mode" in payload:
        mode = coerce_presentation_mode_write(payload["presentation_mode"])
    explicit = current_explicit
    if "presentation_mode_explicit" in payload:
        value = payload["presentation_mode_explicit"]
        if not isinstance(value, bool):
            raise ValueError("presentation_mode_explicit must be a boolean.")
        explicit = value
    elif "presentation_mode" in payload:
        explicit = True

    if requested:
        expected_revision = payload.get("presentation_revision")
        if expected_revision is not None and expected_revision != current_revision:
            raise ValueError("Presentation preference changed on another surface. Reload settings and try again.")
    return PresentationSettingsUpdate(
        requested=requested,
        changed=requested and (mode != current_mode or explicit != current_explicit),
        mode=mode,
        explicit=explicit,
    )


def apply_presentation_settings_update(
    payload: dict[str, object],
    update: PresentationSettingsUpdate,
    *,
    current_revision: int,
) -> None:
    if not update.changed:
        return
    payload["presentation_mode"] = update.mode
    payload["presentation_mode_explicit"] = update.explicit
    payload["presentation_schema_version"] = PRESENTATION_SCHEMA_VERSION
    payload["presentation_revision"] = current_revision + 1
