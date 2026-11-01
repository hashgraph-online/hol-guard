"""Bounded local lookup of the legacy Codex writer's correlated Rust receipt.

This is evidence lookup only. It neither grants protection admission nor
replaces configured launch, authenticated daemon and artifact verification.
The native store op ``read_legacy_codex_probe_receipt`` matches the request
and validates its receipt; this module keeps the admission deadline.
"""

from __future__ import annotations

import math
import sqlite3
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from .runtime.command_activity_contract import CorrelationHandle, CorrelationKind
from .runtime_transition import TransitionError
from .sqlite_tuning import sqlite_connect_timeout_override

if TYPE_CHECKING:
    from .store import GuardStore

_LOOKUP_FAILURES = frozenset(
    {
        "admission_deadline_expired",
        "legacy_probe_identity_invalid",
        "legacy_probe_receipt_ambiguous",
        "legacy_probe_receipt_capacity",
        "legacy_probe_receipt_invalid",
    }
)

_MAX_BUDGET_MS = 60_000


def read_legacy_codex_probe_receipt(
    store: GuardStore,
    *,
    correlation: CorrelationHandle,
    since: datetime,
    deadline_monotonic: float,
) -> dict[str, object] | None:
    """Match a fresh request and its receipt before ``deadline_monotonic``."""
    if (
        correlation.kind is not CorrelationKind.REQUEST
        or correlation.harness != "codex"
        or since.tzinfo is None
        or not math.isfinite(deadline_monotonic)
    ):
        raise TransitionError("legacy_probe_identity_invalid")
    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0:
        raise TransitionError("admission_deadline_expired")
    args = {
        "key_id": correlation.key_id,
        "digest": correlation.digest,
        "since": since.astimezone(timezone.utc).isoformat(),
        # The native lookup interrupts its statement when this runs out.
        "budget_ms": min(_MAX_BUDGET_MS, max(1, math.ceil(remaining * 1000))),
    }
    try:
        # Lock-wait floor 0.5s: 100ms trips on real contention under coverage
        # shards; the operation deadline still bounds the whole call.
        with sqlite_connect_timeout_override(min(0.5, remaining), operation_seconds=remaining):
            receipt: object = store._native_store_call("read_legacy_codex_probe_receipt", args)
    except ValueError as error:
        if str(error) in _LOOKUP_FAILURES:
            raise TransitionError(str(error)) from error
        raise
    except (TimeoutError, sqlite3.OperationalError) as error:
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("admission_deadline_expired") from error
        raise
    if time.monotonic() >= deadline_monotonic:
        raise TransitionError("admission_deadline_expired")
    return cast("dict[str, object] | None", receipt)
