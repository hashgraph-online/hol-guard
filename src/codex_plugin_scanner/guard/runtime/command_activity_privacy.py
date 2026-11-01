"""Local correlation handles for command activity evidence."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Final, cast, final

from typing_extensions import override

from .command_activity_contract import (
    COMMAND_ACTIVITY_HARNESSES,
    COMMAND_ACTIVITY_SCHEMA_VERSION,
    CorrelationHandle,
    CorrelationKind,
)

COMMAND_ACTIVITY_CORRELATION_VERSION: Final = "guard.command-activity-correlation.v1"
_STABLE_ID: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_WEAK_IDENTIFIER: Final[re.Pattern[str]] = re.compile(
    r"(?:[0-9]+|(?:request|req|session|sess|run|event)[._:-]?[0-9]+)",
    re.IGNORECASE,
)
_OPAQUE_STRONG_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{15,511}")
_ISO_TIMESTAMP: Final[re.Pattern[str]] = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})"
)


@final
class InstallationCorrelationKey:
    """Independent per-install HMAC material with a non-secret rotation ID."""

    __slots__: tuple[str, ...] = ("_material", "key_id")
    key_id: str
    _material: bytes

    def __init__(self, *, key_id: str, material: bytes) -> None:
        _require_stable_id(key_id, "key_id")
        if type(material) is not bytes or len(material) < 32:
            raise ValueError("correlation key material must contain at least 32 random bytes")
        self.key_id = key_id
        self._material = bytes(material)

    @override
    def __repr__(self) -> str:
        return f"InstallationCorrelationKey(key_id={self.key_id!r}, material=<hidden>)"

    def derive(self, framed: bytes) -> str:
        return hmac.new(self._material, framed, hashlib.sha256).hexdigest()


@final
class StrongHarnessIdentifier:
    """A native unpredictable identifier attested by a harness adapter."""

    __slots__: tuple[str, ...] = ("_value", "harness", "kind")
    harness: str
    kind: CorrelationKind
    _value: str

    def __init__(self, *, harness: str, kind: CorrelationKind, value: str) -> None:
        _require_harness(harness)
        if not isinstance(cast(object, kind), CorrelationKind):
            raise ValueError("kind must be an exact CorrelationKind value")
        if not isinstance(cast(object, value), str) or _OPAQUE_STRONG_IDENTIFIER.fullmatch(value) is None:
            raise ValueError("strong harness identifier must be a bounded opaque native identifier")
        identifier_alphabet = {character.lower() for character in value if character.isalnum()}
        if (
            _WEAK_IDENTIFIER.fullmatch(value) is not None
            or _ISO_TIMESTAMP.fullmatch(value) is not None
            or len(identifier_alphabet) < 6
        ):
            raise ValueError("predictable counters and timestamps are not strong harness identifiers")
        self.harness = harness
        self.kind = kind
        self._value = value

    @override
    def __repr__(self) -> str:
        return f"StrongHarnessIdentifier(harness={self.harness!r}, kind={self.kind!r}, value=<hidden>)"

    def derive(self, key: InstallationCorrelationKey) -> CorrelationHandle:
        framed = b"".join(
            _frame(value)
            for value in (
                COMMAND_ACTIVITY_CORRELATION_VERSION.encode("ascii"),
                COMMAND_ACTIVITY_SCHEMA_VERSION.encode("ascii"),
                key.key_id.encode("ascii"),
                self.harness.encode("utf-8"),
                self.kind.value.encode("ascii"),
                self._value.encode("utf-8"),
            )
        )
        return CorrelationHandle(self.kind, self.harness, key.key_id, key.derive(framed))


def derive_correlation_handle(
    identifier: StrongHarnessIdentifier,
    key: InstallationCorrelationKey,
) -> CorrelationHandle:
    """Derive a local-only, domain-separated handle without retaining the raw ID."""

    if not isinstance(cast(object, identifier), StrongHarnessIdentifier):
        raise ValueError("identifier must be an exact StrongHarnessIdentifier")
    if not isinstance(cast(object, key), InstallationCorrelationKey):
        raise ValueError("key must be an exact InstallationCorrelationKey")
    return identifier.derive(key)


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _require_stable_id(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable lowercase identifier")


def _require_harness(value: object) -> None:
    if not isinstance(value, str) or value not in COMMAND_ACTIVITY_HARNESSES:
        raise ValueError("harness must identify a supported Guard harness")
