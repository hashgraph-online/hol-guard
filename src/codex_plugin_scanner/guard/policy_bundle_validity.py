"""Shared UTC comparison time for v1 and v2 policy-bundle validity."""

from __future__ import annotations

from datetime import datetime, timezone

POLICY_BUNDLE_CLOCK_SKEW_SECONDS = 300


def _parse_policy_bundle_timestamp(value: str) -> float | None:
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).timestamp()


def comparison_unix_seconds(now: datetime | float | None, *, default: float) -> float:
    """Normalize an injected clock to unix seconds without replacing caller defaults."""

    if now is None:
        return default
    if isinstance(now, datetime):
        aware = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).timestamp()
    return float(now)


def comparison_utc_datetime(now: datetime | float | None, *, default: datetime) -> datetime:
    """Normalize an injected clock to UTC datetime without replacing caller defaults."""

    if now is None:
        return default.astimezone(timezone.utc) if default.tzinfo is not None else default.replace(tzinfo=timezone.utc)
    if isinstance(now, datetime):
        aware = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc)
    return datetime.fromtimestamp(float(now), tz=timezone.utc)


def issued_at_validity_error(issued_at: float, *, current_time: float) -> str | None:
    """Reject future-dated envelopes using the v1 clock-skew contract."""

    if issued_at > current_time + POLICY_BUNDLE_CLOCK_SKEW_SECONDS:
        return "bundle_not_yet_valid"
    return None


def expires_at_validity_error(expires_at: float | None, *, current_time: float) -> str | None:
    """Expire only after the exclusive expiry instant, matching v1."""

    if expires_at is not None and current_time > expires_at:
        return "bundle_expired"
    return None
