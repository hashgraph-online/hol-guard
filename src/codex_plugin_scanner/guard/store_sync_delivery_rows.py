"""Native store methods for the rows the receipts sync reads and records."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


class StoreSyncDeliveryRowsMixin:
    """The workspace assessment delivery and the policy bundle failed acknowledgement."""

    def workspace_assessment_delivery(self: _NativeStore) -> dict[str, Any] | None:
        """The digest and send time of the summary Guard Cloud last accepted, if any."""

        answer = self._native_store_call("workspace_assessment_delivery", {})
        return answer if isinstance(answer, dict) else None

    def commit_workspace_assessment_sent(self: _NativeStore, *, digest: str, sent_at: str) -> None:
        """Record the digest of the summary Guard Cloud accepted, stamped ``sent_at``."""

        self._native_store_call("commit_workspace_assessment_sent", {"digest": digest, "sent_at": sent_at})

    def cached_policy_bundle(self: _NativeStore) -> dict[str, Any] | None:
        """The cached policy bundle the sync validates, possibly empty, or ``None``."""

        answer = self._native_store_call("cached_policy_bundle", {})
        return answer if isinstance(answer, dict) else None

    def record_policy_bundle_failure_ack(self: _NativeStore, *, acknowledgement: object, now: str) -> None:
        """Persist a failed acknowledgement so the next request resends the same one."""

        self._native_store_call("record_policy_bundle_failure_ack", {"acknowledgement": acknowledgement, "now": now})
