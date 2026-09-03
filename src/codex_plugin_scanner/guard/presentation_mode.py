"""Authoritative, presentation-only mode resolution for Guard clients."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

GuardPresentationMode = Literal["everyday", "technical"]
GuardPresentationSource = Literal[
    "default",
    "local-explicit",
    "session-preview",
    "cloud-profile",
    "read-error",
]

PRESENTATION_SCHEMA_VERSION = 1
PRESENTATION_MODE_VALUES = frozenset({"everyday", "technical"})
UNSUPPORTED_PRESENTATION_SCHEMA_DIAGNOSTIC = "unsupported_presentation_schema_fell_back_to_everyday"


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
            diagnostic=UNSUPPORTED_PRESENTATION_SCHEMA_DIAGNOSTIC,
        )
    if isinstance(value, str) and value in PRESENTATION_MODE_VALUES:
        return PersistedPresentationMode(
            value=cast(GuardPresentationMode, value),
            explicit=is_explicit,
            source="local-explicit" if is_explicit else "default",
            schema_version=PRESENTATION_SCHEMA_VERSION,
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


def resolve_presentation_mode(
    *,
    local_value: object = None,
    local_explicit: object = False,
    local_schema_version: object = PRESENTATION_SCHEMA_VERSION,
    revision: object = 0,
    session_preview: object = None,
    cloud_profile: object = None,
    writable: bool = True,
    read_error: bool = False,
) -> ResolvedPresentationMode:
    """Resolve display preference without policy, entitlement, or decision inputs."""

    safe_revision = revision if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 0 else 0
    if read_error:
        return ResolvedPresentationMode(
            value="everyday",
            source="read-error",
            explicit=False,
            writable=writable,
            revision=safe_revision,
            diagnostic="presentation_settings_unavailable",
        )
    if isinstance(session_preview, str) and session_preview in PRESENTATION_MODE_VALUES:
        return ResolvedPresentationMode(
            value=cast(GuardPresentationMode, session_preview),
            source="session-preview",
            explicit=True,
            writable=writable,
            revision=safe_revision,
        )
    local = coerce_persisted_presentation_mode(
        local_value,
        explicit=local_explicit,
        schema_version=local_schema_version,
    )
    if local.explicit:
        return ResolvedPresentationMode(
            value=local.value,
            source=local.source,
            explicit=local.explicit,
            writable=writable,
            revision=safe_revision,
            diagnostic=local.diagnostic,
        )
    if isinstance(cloud_profile, str) and cloud_profile in PRESENTATION_MODE_VALUES:
        return ResolvedPresentationMode(
            value=cast(GuardPresentationMode, cloud_profile),
            source="cloud-profile",
            explicit=False,
            writable=writable,
            revision=safe_revision,
            diagnostic=local.diagnostic,
        )
    return ResolvedPresentationMode(
        value=local.value,
        source=local.source,
        explicit=local.explicit,
        writable=writable,
        revision=safe_revision,
        diagnostic=local.diagnostic,
    )


def coerce_presentation_mode_write(value: object) -> GuardPresentationMode:
    if isinstance(value, str) and value in PRESENTATION_MODE_VALUES:
        return cast(GuardPresentationMode, value)
    raise ValueError("Presentation mode must be everyday or technical.")
