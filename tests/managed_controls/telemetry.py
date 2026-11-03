"""Allowlisted, privacy-safe Managed Controls telemetry."""

from __future__ import annotations

from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {
        "event",
        "result",
        "authority_mode",
        "compatibility_state",
        "drift_state",
        "control_count_bucket",
        "latency_bucket",
    }
)
_FORBIDDEN_FRAGMENTS = ("command", "path", "secret", "token", "proof", "nonce")
_ENUM_VALUES = {
    "event": frozenset(
        {
            "apply",
            "catalog_sync",
            "compatibility_check",
            "drift_check",
            "migration",
            "rollback",
        }
    ),
    "result": frozenset({"blocked", "failure", "skipped", "success", "unsupported"}),
    "authority_mode": frozenset({"personal-shared", "workspace-shared", "managed-restrictive"}),
    "compatibility_state": frozenset({"compatible", "missing_capability", "catalog_mismatch", "schema_unsupported"}),
    "drift_state": frozenset({"current", "pending", "catalog_mismatch", "effective_mismatch", "unsupported"}),
    "control_count_bucket": frozenset({"0", "1", "2-10", "11-50", "51-100", "101-plus"}),
    "latency_bucket": frozenset({"lt-10ms", "10-49ms", "50-249ms", "250-999ms", "gte-1s"}),
}


class TelemetryPrivacyError(ValueError):
    """Raised when telemetry contains sensitive or arbitrary data."""


def managed_controls_telemetry_event(
    values: Mapping[str, object],
) -> dict[str, str]:
    unknown = set(values) - _ALLOWED_FIELDS
    if unknown:
        raise TelemetryPrivacyError("telemetry contains non-allowlisted fields")
    event: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise TelemetryPrivacyError("telemetry value has an unsupported type")
        text = str(value)
        lowered = f"{key}:{text}".lower()
        if any(fragment in lowered for fragment in _FORBIDDEN_FRAGMENTS):
            raise TelemetryPrivacyError("telemetry contains sensitive material")
        allowed_values = _ENUM_VALUES[key]
        if text not in allowed_values:
            raise TelemetryPrivacyError("telemetry contains an unsupported value")
        event[key] = text
    return event
