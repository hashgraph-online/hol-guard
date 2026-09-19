"""Values helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _dict_payload(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _dict_items(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _int_value(value: object) -> int | None:
    if isinstance(value, int):
        return value
    return None


def _parse_timestamp(value: str | None) -> _api.datetime | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = _api.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=_api.timezone.utc)
    return parsed.astimezone(_api.timezone.utc)


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
