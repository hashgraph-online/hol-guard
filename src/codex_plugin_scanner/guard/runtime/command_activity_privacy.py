"""Privacy and egress contracts for command activity evidence."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Final, cast, final

from typing_extensions import override

from codex_plugin_scanner.guard.action_lattice import GUARD_ACTION_LATTICE

from .command_activity_contract import (
    COMMAND_ACTIVITY_FIELDS,
    COMMAND_ACTIVITY_HARNESSES,
    COMMAND_ACTIVITY_MATCH_FIELDS,
    COMMAND_ACTIVITY_SCHEMA_VERSION,
    ActivityLatencyBucket,
    CommandExecutionStatus,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
)
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

COMMAND_ACTIVITY_CORRELATION_VERSION: Final = "guard.command-activity-correlation.v1"
COMMAND_ACTIVITY_CLOUD_SCHEMA_VERSION: Final = "guard.command-activity-aggregate.v1"
MIN_CLOUD_AGGREGATE_COUNT: Final = 10
_STABLE_ID: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_WEAK_IDENTIFIER: Final[re.Pattern[str]] = re.compile(
    r"(?:[0-9]+|(?:request|req|session|sess|run|event)[._:-]?[0-9]+)",
    re.IGNORECASE,
)
_OPAQUE_STRONG_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{15,511}")
_ISO_TIMESTAMP: Final[re.Pattern[str]] = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})"
)
_CLOUD_EXTENSION_IDS: Final = frozenset(
    extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
)
_CLOUD_RULE_IDS: Final = frozenset(
    rule.rule_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions for rule in extension.rules
)

FORBIDDEN_ACTIVITY_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "arguments",
        "args",
        "artifact_hash",
        "clipboard",
        "command",
        "command_hash",
        "command_security_identity",
        "command_text",
        "credential",
        "credentials",
        "cwd",
        "environment",
        "environment_names",
        "environment_values",
        "exception_message",
        "hostname",
        "installation_id",
        "matcher_evidence",
        "metadata",
        "normalized_command",
        "package_name",
        "package_source",
        "path",
        "raw_arguments",
        "raw_command",
        "raw_request_id",
        "raw_session_id",
        "reason_text",
        "repository_name",
        "secret",
        "secrets",
        "security_identity",
        "shell_fragment",
        "token",
        "tokens",
        "url",
        "workspace_name",
    }
)


class ActivityEgressMode(str, Enum):
    LOCAL_ONLY = "local_only"
    AGGREGATE_ONLY = "aggregate_only"


class CloudAggregateDimension(str, Enum):
    TOTAL = "total"
    HARNESS = "harness"
    EXTENSION = "extension"
    RULE = "rule"
    DISPOSITION = "disposition"
    EXECUTION_STATUS = "execution_status"
    PROMPT_STATUS = "prompt_status"
    PROOF_LEVEL = "proof_level"
    LATENCY = "latency"


@dataclass(frozen=True, slots=True)
class CommandActivityPrivacyPolicy:
    egress_mode: ActivityEgressMode = ActivityEgressMode.LOCAL_ONLY

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.egress_mode), ActivityEgressMode):
            raise ValueError("egress_mode must be an exact ActivityEgressMode value")


DEFAULT_COMMAND_ACTIVITY_PRIVACY_POLICY: Final = CommandActivityPrivacyPolicy()


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


@dataclass(frozen=True, slots=True)
class CloudCommandActivityAggregate:
    """One rare-cell-suppressed daily count with exactly one bounded dimension."""

    day: date
    dimension: CloudAggregateDimension
    dimension_value: str
    count: int
    schema_version: str = COMMAND_ACTIVITY_CLOUD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(cast(object, self.day)) is not date:
            raise ValueError("day must be a UTC calendar date")
        if not isinstance(cast(object, self.dimension), CloudAggregateDimension):
            raise ValueError("dimension must be an exact CloudAggregateDimension value")
        _require_stable_id(self.dimension_value, "dimension_value")
        _require_cloud_dimension_value(self.dimension, self.dimension_value)
        if type(self.count) is not int or self.count < MIN_CLOUD_AGGREGATE_COUNT:
            raise ValueError("rare cloud aggregate cells must be suppressed")
        if self.schema_version != COMMAND_ACTIVITY_CLOUD_SCHEMA_VERSION:
            raise ValueError("unsupported cloud command activity aggregate schema version")

    def to_cloud_payload(self, policy: CommandActivityPrivacyPolicy) -> dict[str, object]:
        if not isinstance(cast(object, policy), CommandActivityPrivacyPolicy):
            raise ValueError("policy must be a CommandActivityPrivacyPolicy")
        if policy.egress_mode is not ActivityEgressMode.AGGREGATE_ONLY:
            raise ValueError("command activity egress is local-only unless aggregate mode is explicitly enabled")
        return {
            "day": self.day.isoformat(),
            "dimension": self.dimension.value,
            "dimension_value": self.dimension_value,
            "count": self.count,
            "schema_version": self.schema_version,
        }


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


def validate_activity_schema_privacy() -> None:
    """Prove the frozen activity schemas contain no forbidden storage fields."""

    names = frozenset((*COMMAND_ACTIVITY_FIELDS, *COMMAND_ACTIVITY_MATCH_FIELDS))
    overlap = names & FORBIDDEN_ACTIVITY_FIELD_NAMES
    if overlap:
        raise ValueError(f"command activity schema contains forbidden fields: {sorted(overlap)!r}")
    if any(name in names for name in ("raw_request_id", "raw_session_id", "installation_id")):
        raise ValueError("raw or installation identifiers cannot enter command activity schemas")


def validate_cloud_payload(payload: object) -> None:
    """Reject non-aggregate, nested, or unexpected cloud payload shapes."""

    if not isinstance(payload, dict):
        raise ValueError("cloud command activity payload must be a dictionary")
    typed_payload = cast(dict[object, object], payload)
    expected = {"day", "dimension", "dimension_value", "count", "schema_version"}
    if set(typed_payload) != expected or any(
        isinstance(value, (dict, list, tuple, set)) for value in typed_payload.values()
    ):
        raise ValueError("cloud command activity payload must use the exact flat aggregate allowlist")
    forbidden = set(typed_payload) & FORBIDDEN_ACTIVITY_FIELD_NAMES
    if forbidden:
        raise ValueError("cloud command activity payload contains forbidden fields")
    day_value = typed_payload["day"]
    dimension_value = typed_payload["dimension"]
    bounded_value = typed_payload["dimension_value"]
    count = typed_payload["count"]
    schema_version = typed_payload["schema_version"]
    if (
        type(day_value) is not str
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day_value) is None
        or type(dimension_value) is not str
        or type(bounded_value) is not str
        or type(count) is not int
        or type(schema_version) is not str
    ):
        raise ValueError("cloud command activity payload contains invalid scalar types")
    try:
        parsed_day = date.fromisoformat(day_value)
        parsed_dimension = CloudAggregateDimension(dimension_value)
    except ValueError as error:
        raise ValueError("cloud command activity payload contains invalid bounded values") from error
    _ = CloudCommandActivityAggregate(
        day=parsed_day,
        dimension=parsed_dimension,
        dimension_value=bounded_value,
        count=count,
        schema_version=schema_version,
    )


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _require_stable_id(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) > 128 or _STABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable lowercase identifier")


def _require_harness(value: object) -> None:
    if not isinstance(value, str) or value not in COMMAND_ACTIVITY_HARNESSES:
        raise ValueError("harness must identify a supported Guard harness")


def _require_cloud_dimension_value(dimension: CloudAggregateDimension, value: str) -> None:
    allowed: dict[CloudAggregateDimension, frozenset[str]] = {
        CloudAggregateDimension.TOTAL: frozenset({"all"}),
        CloudAggregateDimension.HARNESS: COMMAND_ACTIVITY_HARNESSES,
        CloudAggregateDimension.EXTENSION: _CLOUD_EXTENSION_IDS,
        CloudAggregateDimension.RULE: _CLOUD_RULE_IDS,
        CloudAggregateDimension.DISPOSITION: frozenset(GUARD_ACTION_LATTICE),
        CloudAggregateDimension.EXECUTION_STATUS: frozenset(item.value for item in CommandExecutionStatus),
        CloudAggregateDimension.PROMPT_STATUS: frozenset({"prompted", "not_prompted"}),
        CloudAggregateDimension.PROOF_LEVEL: frozenset(item.value for item in CommandProofLevel),
        CloudAggregateDimension.LATENCY: frozenset(item.value for item in ActivityLatencyBucket),
    }
    if value not in allowed[dimension]:
        raise ValueError("dimension_value must belong to the selected bounded aggregate dimension")


validate_activity_schema_privacy()
