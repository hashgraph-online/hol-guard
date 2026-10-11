"""Authoritative, presentation-only mode resolution for Guard clients."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

GuardPresentationMode = Literal["everyday", "technical"]
GuardPresentationSource = Literal[
    "default",
    "local-explicit",
    "migrated",
    "session-preview",
    "cloud-profile",
    "read-error",
]

PRESENTATION_SCHEMA_VERSION = 1
PRESENTATION_MODE_VALUES = frozenset({"everyday", "technical"})
LEGACY_PRESENTATION_MODE_MAP: dict[str, GuardPresentationMode] = {
    "simple": "everyday",
    "advanced": "technical",
    "developer": "technical",
}


@dataclass(frozen=True, slots=True)
class PersistedPresentationMode:
    value: GuardPresentationMode
    explicit: bool
    source: GuardPresentationSource
    schema_version: int
    diagnostic: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedPresentationMode:
    value: GuardPresentationMode
    source: GuardPresentationSource
    explicit: bool
    writable: bool
    schema_version: int = PRESENTATION_SCHEMA_VERSION
    revision: int = 0
    diagnostic: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "source": self.source,
            "explicit": self.explicit,
            "writable": self.writable,
            "schema_version": self.schema_version,
            "revision": self.revision,
            "diagnostic": self.diagnostic,
        }


def coerce_persisted_presentation_mode(
    value: object,
    *,
    explicit: object = False,
    schema_version: object = PRESENTATION_SCHEMA_VERSION,
) -> PersistedPresentationMode:
    is_explicit = explicit is True
    if schema_version != PRESENTATION_SCHEMA_VERSION:
        return PersistedPresentationMode(
            value="everyday",
            explicit=False,
            source="default",
            schema_version=PRESENTATION_SCHEMA_VERSION,
            diagnostic="unsupported_presentation_schema_fell_back_to_everyday",
        )
    if isinstance(value, str) and value in PRESENTATION_MODE_VALUES:
        return PersistedPresentationMode(
            value=cast(GuardPresentationMode, value),
            explicit=is_explicit,
            source="local-explicit" if is_explicit else "default",
            schema_version=PRESENTATION_SCHEMA_VERSION,
        )
    if isinstance(value, str) and value in LEGACY_PRESENTATION_MODE_MAP:
        return PersistedPresentationMode(
            value=LEGACY_PRESENTATION_MODE_MAP[value],
            explicit=True,
            source="migrated",
            schema_version=PRESENTATION_SCHEMA_VERSION,
            diagnostic=f"migrated_legacy_{value}_presentation_mode",
        )
    if value is None or value == "":
        return PersistedPresentationMode(
            value="everyday",
            explicit=False,
            source="default",
            schema_version=PRESENTATION_SCHEMA_VERSION,
        )
    return PersistedPresentationMode(
        value="everyday",
        explicit=False,
        source="default",
        schema_version=PRESENTATION_SCHEMA_VERSION,
        diagnostic="unknown_presentation_mode_fell_back_to_everyday",
    )


def coerce_presentation_mode_write(value: object) -> GuardPresentationMode:
    if isinstance(value, str) and value in PRESENTATION_MODE_VALUES:
        return cast(GuardPresentationMode, value)
    raise ValueError("Presentation mode must be everyday or technical.")
