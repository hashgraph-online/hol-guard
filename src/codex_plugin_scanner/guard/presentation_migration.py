"""One-time migration helpers for obsolete presentation preference values."""

from __future__ import annotations

from typing import Literal

MigratedPresentationMode = Literal["everyday", "technical"]
_LEGACY_PRESENTATION_MODE_MAP: dict[str, MigratedPresentationMode] = {
    "simple": "everyday",
    "advanced": "technical",
    "developer": "technical",
}


def migrate_legacy_presentation_mode(value: object) -> MigratedPresentationMode | None:
    if not isinstance(value, str):
        return None
    return _LEGACY_PRESENTATION_MODE_MAP.get(value)
