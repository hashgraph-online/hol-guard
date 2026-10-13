"""Authoritative, presentation-only mode resolution for Guard clients."""

from __future__ import annotations

from typing import Literal, cast

GuardPresentationMode = Literal["everyday", "technical"]

PRESENTATION_SCHEMA_VERSION = 1
PRESENTATION_MODE_VALUES = frozenset({"everyday", "technical"})


def coerce_presentation_mode_write(value: object) -> GuardPresentationMode:
    if isinstance(value, str) and value in PRESENTATION_MODE_VALUES:
        return cast(GuardPresentationMode, value)
    raise ValueError("Presentation mode must be everyday or technical.")
