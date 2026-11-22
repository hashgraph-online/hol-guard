"""Native store snapshot of the Cloud Review policy-memory cursor."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


class ReviewPolicyMemoryRowUnreadableError(ValueError):
    """A policy-memory row holds text that is not JSON, so no bundle may be planned on it."""


@dataclass(frozen=True)
class ReviewPolicyMemoryRows:
    """The stored memory policy version and rule registry, from one snapshot.

    ``registry`` is ``None`` when the row is missing or is neither an object
    nor an array, as ``get_sync_payload`` answers for it. ``policy_version`` is
    the stored ``policyVersion`` without surrounding whitespace, or ``None``.
    """

    registry: dict[str, object] | list[object] | None
    policy_version: str | None

    @classmethod
    def from_native(cls, answer: object) -> ReviewPolicyMemoryRows:
        if not isinstance(answer, dict):
            raise RuntimeError("native review_policy_memory_rows returned no answer")
        unreadable = answer.get("unreadable")
        if unreadable:
            roles = ",".join(str(role) for role in unreadable) if isinstance(unreadable, list) else "rows"
            raise ReviewPolicyMemoryRowUnreadableError(f"review_policy_memory_unreadable:{roles}")
        registry = answer.get("registry")
        policy_version = answer.get("policy_version")
        if registry is not None and not isinstance(registry, (dict, list)):
            raise RuntimeError("native review_policy_memory_rows returned no answer")
        if policy_version is not None and (not isinstance(policy_version, str) or not policy_version):
            raise RuntimeError("native review_policy_memory_rows returned no answer")
        return cls(registry=registry, policy_version=policy_version)


class StoreReviewPolicyMemoryRowsMixin:
    """The policy-memory cursor, read by the native store in one snapshot."""

    def review_policy_memory_rows(self: _NativeStore) -> ReviewPolicyMemoryRows:
        return ReviewPolicyMemoryRows.from_native(self._native_store_call("review_policy_memory_rows", {}))


__all__ = [
    "ReviewPolicyMemoryRowUnreadableError",
    "ReviewPolicyMemoryRows",
    "StoreReviewPolicyMemoryRowsMixin",
]
