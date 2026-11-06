"""Shared parsing primitives for supply-chain bundle handling."""

from __future__ import annotations

from datetime import datetime, timezone

_VERIFICATION_KEY_STATE_VALUES = frozenset({"active", "grace", "revoked"})


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


def _parse_iso_timestamp(value: str, *, field_name: str) -> float:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SupplyChainBundleMalformedError(f"Invalid ISO timestamp for {field_name!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).timestamp()
