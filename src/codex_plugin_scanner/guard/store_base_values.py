"""Implementation definitions reexported by the StoreBase facade."""

from __future__ import annotations

import hmac

from .store_base_definition import preserve_store_base_module as _preserve_module


@_preserve_module
def _is_approval_gate_one_shot_policy(row: sqlite3.Row) -> bool:
    return str(row["source"]) == _base._APPROVAL_GATE_POLICY_SOURCE and row["expires_at"] is not None


@_preserve_module
def _normalize_source_name(source: str | None) -> str:
    """Normalize a connection source name.

    The default source is 'default'. Source names are used to namespace
    OAuth credentials in the local store, allowing multiple simultaneous
    connections (e.g. production + staging).
    """
    if source is None:
        return "default"
    normalized = source.strip().lower()
    if not normalized:
        return "default"
    if not _base._SOURCE_NAME_PATTERN.match(normalized):
        raise ValueError(f"Invalid source name: {source!r}. Source names must match [a-zA-Z0-9][a-zA-Z0-9_-]*")
    if len(normalized) > 64:
        raise ValueError(f"Invalid source name: {source!r}. Source names must be 64 characters or fewer.")
    return normalized


@_preserve_module
def _oauth_sync_url_from_issuer(issuer: str) -> str:
    oauth_client = _base.resolve_guard_oauth_client_config(issuer)
    return f"{oauth_client.issuer}/api/guard/receipts/sync"


@_preserve_module
def _allowed_origin_from_sync_url(sync_url: str) -> str | None:
    parsed = _base.urlparse(sync_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


@_preserve_module
def _secret_fingerprint(value: str) -> str:
    digest = _base.scrypt(
        value.encode("utf-8"),
        salt=_base._SECRET_FINGERPRINT_SALT,
        n=_base._SECRET_FINGERPRINT_N,
        r=_base._SECRET_FINGERPRINT_R,
        p=_base._SECRET_FINGERPRINT_P,
        dklen=_base._SECRET_FINGERPRINT_DKLEN,
    ).hex()
    return f"{_base._SECRET_FINGERPRINT_PREFIX}{digest}"


@_preserve_module
def _secret_matches_hash(value: str, expected_hash: str) -> bool:
    prefix = _base._SECRET_FINGERPRINT_PREFIX
    if (
        not expected_hash.startswith(prefix)
        or len(expected_hash) != len(prefix) + 2 * _base._SECRET_FINGERPRINT_DKLEN
        or any(character not in "0123456789abcdef" for character in expected_hash[len(prefix) :])
    ):
        return False
    return hmac.compare_digest(_base._secret_fingerprint(value), expected_hash)


@_preserve_module
def _should_warn_on_slow_store_transactions() -> bool:
    value = _base.os.environ.get(_base._SLOW_STORE_WARNING_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


@_preserve_module
def receipt_index_statements() -> list[str]:
    return [
        ("create index if not exists idx_receipts_harness_artifact on runtime_receipts(harness, artifact_id)"),
        ("create index if not exists idx_receipts_timestamp_harness on runtime_receipts(timestamp, harness)"),
        ("create index if not exists idx_receipts_timestamp_desc on runtime_receipts(timestamp desc)"),
        ("create index if not exists idx_receipts_harness_timestamp_desc on runtime_receipts(harness, timestamp desc)"),
        (
            "create index if not exists idx_receipts_harness_artifact_timestamp_desc "
            "on runtime_receipts(harness, artifact_id, timestamp desc)"
        ),
        (
            "create index if not exists idx_receipts_approval_request_decision "
            "on runtime_receipts(approval_request_id, policy_decision)"
        ),
    ]


@_preserve_module
def _row_mapping(row: sqlite3.Row) -> dict[str, object]:
    keys = row.keys()
    return {key: row[key] for key in keys}


@_preserve_module
def _string_value(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


@_preserve_module
def _int_value(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


@_preserve_module
def _mapping_int(payload: Mapping[str, object], key: str) -> int | None:
    return _base._int_value(payload.get(key))


@_preserve_module
def _parse_utc_timestamp(value: str) -> datetime:
    candidate = value.strip()
    if not candidate:
        raise ValueError("timestamp must not be empty")
    parsed = _base.datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_base.timezone.utc)
    return parsed.astimezone(_base.timezone.utc)


@_preserve_module
def _canonical_utc_timestamp(value: str) -> str:
    """Normalize an ISO-8601 timestamp for safe storage and comparison."""

    return _base._parse_utc_timestamp(value).isoformat(timespec="microseconds")


@_preserve_module
def _timestamp_has_expired(expires_at: str, *, now: str) -> bool:
    """Return true at the expiry boundary and for malformed legacy values."""

    try:
        return _base._parse_utc_timestamp(expires_at) <= _base._parse_utc_timestamp(now)
    except (TypeError, ValueError):
        return True


@_preserve_module
def _now() -> str:
    return _base._canonical_utc_timestamp(_base.datetime.now(_base.timezone.utc).isoformat())


@_preserve_module
def _lease_expiry(now: str, lease_seconds: int) -> str:
    return (_base.datetime.fromisoformat(now) + _base.timedelta(seconds=max(lease_seconds, 1))).isoformat()


@_preserve_module
def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


@_preserve_module
def _transport_value(value: object) -> TransportKind:
    if value == "local":
        return "local"
    if value == "remote":
        return "remote"
    if value == "hybrid":
        return "hybrid"
    return "local"


# Bind dependencies after declarations so each owner can be imported first.
from . import store_base as _base  # noqa: E402
from .store_base import Mapping, TransportKind, datetime, sqlite3  # noqa: E402
