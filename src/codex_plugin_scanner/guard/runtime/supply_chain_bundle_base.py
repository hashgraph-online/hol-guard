"""Shared parsing primitives for supply-chain bundle handling."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Final

_BUNDLE_MAX_AGE_SECONDS: Final[int] = 86_400 * 7
_BUNDLE_CLOCK_SKEW_SECONDS: Final[int] = 300
_PACKAGE_ACTION_VALUES = frozenset({"allow", "monitor", "warn", "ask", "block"})
_SEVERITY_VALUES = frozenset({"unknown", "low", "medium", "high", "critical"})
_EXPLOIT_LEVEL_VALUES = frozenset({"none", "elevated", "active"})
_MALWARE_STATE_VALUES = frozenset({"none", "suspected", "known"})
_STALE_STATUS_VALUES = frozenset({"fresh", "stale", "unknown"})
_VERIFICATION_KEY_STATE_VALUES = frozenset({"active", "grace"})


class SupplyChainBundleError(Exception):
    """Base error for supply-chain bundle failures."""


class SupplyChainBundleSignatureError(SupplyChainBundleError):
    """Bundle signature did not verify."""


class SupplyChainBundleExpiredError(SupplyChainBundleError):
    """Bundle freshness window has elapsed."""


class SupplyChainBundleRollbackError(SupplyChainBundleError):
    """Bundle version is older than the cached version."""


class SupplyChainBundleMalformedError(SupplyChainBundleError):
    """Bundle response is missing required fields or invalid values."""


class SupplyChainBundlePayloadHashError(SupplyChainBundleError):
    """Bundle payload hash does not match the canonical payload."""


class SupplyChainBundleKeyringError(SupplyChainBundleError):
    """Bundle key rotation is not anchored to the trusted keyring."""


def _require_string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SupplyChainBundleMalformedError(f"Missing required string field: {key!r}")
    return value.strip()


def _optional_string(data: dict[str, object], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise SupplyChainBundleMalformedError(f"Field must be a string when present: {key!r}")
    normalized = value.strip()
    return normalized or None


def _require_int(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int):
        raise SupplyChainBundleMalformedError(f"Missing required int field: {key!r}")
    return value


def _require_bool(data: dict[str, object], key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise SupplyChainBundleMalformedError(f"Missing required boolean field: {key!r}")
    return value


def _require_string_array(data: dict[str, object], key: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list):
        raise SupplyChainBundleMalformedError(f"Missing required list field: {key!r}")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SupplyChainBundleMalformedError(f"Field contains invalid string item: {key!r}")
        items.append(item.strip())
    return tuple(items)


def _parse_iso_timestamp(value: str, *, field_name: str) -> float:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SupplyChainBundleMalformedError(f"Invalid ISO timestamp for {field_name!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).timestamp()


def _bundle_version_timestamp(bundle_version: str) -> int:
    try:
        prefix = bundle_version.split("-", 1)[0]
        return int(prefix)
    except (TypeError, ValueError) as exc:
        raise SupplyChainBundleMalformedError(
            "bundleVersion must start with a unix-ms timestamp prefix"
        ) from exc
