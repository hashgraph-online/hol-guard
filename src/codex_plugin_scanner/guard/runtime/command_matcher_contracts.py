"""Dependency-neutral contracts shared by command matchers and rules."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, is_dataclass
from enum import Enum
from functools import lru_cache
from typing import Protocol

from .command_model import CanonicalCommand

MATCHER_CONTRACT_SCHEMA_VERSION = 1


class MatcherContractError(TypeError):
    """Raised when a matcher contains configuration outside the catalog contract."""


@dataclass(frozen=True, slots=True)
class MatcherEvidence:
    """Redaction-safe location emitted by one structured matcher."""

    segment_index: int
    executable: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "segment_index": self.segment_index,
            "executable": self.executable,
            "detail": self.detail,
        }


class CommandMatcher(Protocol):
    """Side-effect-free structured command matcher."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]: ...


@lru_cache(maxsize=512)
def _encoded_short_string(value: str) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _set_sort_key(value: object) -> str:
    # Catalogs repeat many immutable flag names across matcher sets. Keep the
    # exact JSON ordering, with a bounded cache only for short plain strings.
    # Mutable values and unusual scalar subclasses retain ordinary encoding.
    if type(value) is str and len(value) <= 256:
        return _encoded_short_string(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def canonical_contract_value(value: object) -> object:
    """Serialize matcher configuration without relying on object repr output.

    Catalog matchers must use explicit dataclass configuration (built-in
    matchers are frozen); unsupported values fail closed instead of being
    reduced to ``repr`` output.
    """

    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        dataclass_fields = getattr(value, "__dataclass_fields__", {})
        return {
            "type": type(value).__qualname__,
            "fields": {
                field_name: canonical_contract_value(getattr(value, field_name)) for field_name in dataclass_fields
            },
        }
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise MatcherContractError("catalog contract mappings require string keys")
        return {key: canonical_contract_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (set, frozenset)):
        normalized = [canonical_contract_value(item) for item in value]
        return sorted(normalized, key=_set_sort_key)
    if isinstance(value, (tuple, list)):
        return [canonical_contract_value(item) for item in value]
    raise MatcherContractError(f"unsupported catalog contract value: {type(value).__qualname__}")


def canonical_contract_digest(value: object) -> str:
    """Return a versioned digest over the complete matcher contract."""

    canonical = json.dumps(
        canonical_contract_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(
        f"hol-guard.command-matcher-contract.v{MATCHER_CONTRACT_SCHEMA_VERSION}\0".encode("ascii") + canonical
    ).hexdigest()
