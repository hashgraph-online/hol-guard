"""Native-owned continuation claims and atomic durable finalization."""

from __future__ import annotations

import sqlite3
from typing import Any, cast
from uuid import uuid4

from .native_continuation_authority import continuation_authority
from .review_event_wake import review_event_wake_signal_for_key
from .store_base import sqlite_connect_timeout_seconds


def continuation_store_call(store: Any, call: str, **args: Any) -> dict[str, Any]:
    """Hold the store admission gate across one bound native transaction."""
    timeout_seconds = sqlite_connect_timeout_seconds()
    if timeout_seconds <= 0:
        raise TimeoutError("Guard storage operation deadline expired.")
    failure: sqlite3.DatabaseError | None = None
    result: dict[str, Any] = {}
    with store._hold_storage_gate(exclusive=False):
        try:
            result = continuation_authority(
                call,
                guard_home=store.guard_home,
                store_path=str(store.path),
                busy_timeout_ms=max(1, min(10_000, int(timeout_seconds * 1000))),
                **args,
            )
        except sqlite3.DatabaseError as error:
            failure = error
        finally:
            store._repair_store_permissions()
    if failure is not None:
        # The transaction already ran against the failed store: recover it for
        # the next call, then surface this failure.
        try:
            store._recover_fatal_sqlite_store(failure)
        except Exception as recovery_error:
            raise recovery_error from failure
        raise failure
    if result.get("outbox_generation") is not None:
        review_event_wake_signal_for_key(result["database_key"]).notify_if_outbox_changed(result["outbox_generation"])
    return result


class StoreContinuationMixin:
    def claim_continuation_attempt(
        self, *, request_id: str, offer_hash: str, action: str, now: str, lease_seconds: float
    ) -> str | None:
        result = continuation_store_call(
            self,
            "store_claim",
            request_id=request_id,
            offer_hash=offer_hash,
            action=action,
            now=now,
            lease_seconds=lease_seconds,
            new_claim_id=f"claim-{uuid4().hex}",
        )
        return cast(str | None, result["claim_id"])
