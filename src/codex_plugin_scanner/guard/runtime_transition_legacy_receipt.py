"""Bounded local lookup of the legacy Codex writer's correlated Rust receipt.

This is evidence lookup only. It neither grants protection admission nor
replaces configured launch, authenticated daemon and artifact verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime, timezone
from typing import Protocol

from .runtime.command_activity_contract import CorrelationHandle, CorrelationKind
from .runtime_transition import TransitionError
from .sqlite_tuning import sqlite_connect_timeout_override
from .store_native_decision_receipts import validate_stored_native_decision_receipt

MAX_LEGACY_PROBE_ROWS = 128


class _ReceiptStore(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


@contextmanager
def _deadline_connection(store: _ReceiptStore, deadline: float) -> Iterator[sqlite3.Connection]:
    """Preserve the admission deadline across connection setup and teardown."""
    try:
        with store._connect() as connection:
            yield connection
    except (TimeoutError, sqlite3.OperationalError) as error:
        if time.monotonic() >= deadline:
            raise TransitionError("admission_deadline_expired") from error
        raise


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo is not None else None


def read_legacy_codex_probe_receipt(
    store: _ReceiptStore,
    *,
    correlation: CorrelationHandle,
    since: datetime,
    deadline_monotonic: float,
) -> dict[str, object] | None:
    """Match a fresh request and its receipt in one capped SQLite statement.

    Legacy denied attempts salt their HMAC handle with receipt/action metadata.
    Both activity and native receipt timestamps must follow the caller's launch
    boundary. A nonce's matching results must be unique. No shared last-receipt
    slot, command text or uncorrelated newest-row heuristic is consulted.
    """
    if (
        correlation.kind is not CorrelationKind.REQUEST
        or correlation.harness != "codex"
        or since.tzinfo is None
        or not math.isfinite(deadline_monotonic)
    ):
        raise TransitionError("legacy_probe_identity_invalid")
    since = since.astimezone(timezone.utc)

    def check() -> None:
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("admission_deadline_expired")

    check()
    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0:
        raise TransitionError("admission_deadline_expired")
    with (
        # Keep lock waits short without shrinking the entire receipt query
        # and connection initialization to the same 100 ms budget.
        sqlite_connect_timeout_override(min(0.1, remaining), operation_seconds=remaining),
        _deadline_connection(store, deadline_monotonic) as connection,
    ):
        check()
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline_monotonic), 100)
        try:
            rows = connection.execute(
                "select r.*, a.occurred_at as activity_occurred_at, "
                "a.policy_action as activity_policy_action, a.prompted as activity_prompted, "
                "a.approval_reuse_status as activity_approval_reuse_status, "
                "a.execution_status as activity_execution_status, c.digest as correlation_digest "
                "from command_activity a join command_activity_correlations c "
                "on c.activity_id = a.activity_id join native_hook_decision_receipts r "
                "on r.decision_id = a.receipt_id "
                "where a.harness = 'codex' and c.harness = 'codex' and c.kind = 'request' "
                "and c.key_id = ? and a.hook_phase = 'pre' and a.proof_level = 'pre_hook' "
                "and a.receipt_link_status = 'linked' and a.occurred_at >= ? "
                "order by a.occurred_at desc, a.activity_id limit ?",
                (correlation.key_id, since.isoformat(), MAX_LEGACY_PROBE_ROWS + 1),
            ).fetchall()
        except sqlite3.OperationalError:
            check()
            raise
        finally:
            connection.set_progress_handler(None, 0)
    check()
    if len(rows) > MAX_LEGACY_PROBE_ROWS:
        raise TransitionError("legacy_probe_receipt_capacity")
    matched: list[dict[str, object]] = []
    for row in rows:
        check()
        raw: dict[str, object] = dict(row)
        activity = {key.removeprefix("activity_"): raw.pop(key) for key in tuple(raw) if key.startswith("activity_")}
        digest = raw.pop("correlation_digest")
        action = activity["policy_action"]
        expected = correlation.digest
        if action not in {"allow", "warn"}:
            # Exact shipped native-prevented-attempt-v1 wire formula, including
            # JSON's default separators. It is not a new correlation scheme.
            expected = hashlib.sha256(
                json.dumps(
                    [
                        "native-prevented-attempt-v1",
                        correlation.digest,
                        action,
                        raw["decision_id"],
                        bool(activity["prompted"]),
                        activity["approval_reuse_status"],
                    ]
                ).encode()
            ).hexdigest()
        if not isinstance(digest, str) or not hmac.compare_digest(digest, expected):
            continue
        occurred, recorded = _timestamp(activity["occurred_at"]), _timestamp(raw["recorded_at"])
        receipt = validate_stored_native_decision_receipt(raw)
        if (
            receipt is None
            or occurred is None
            or recorded is None
            or occurred < since
            or recorded < since
            or occurred > datetime.now(timezone.utc)
            or recorded > datetime.now(timezone.utc)
            or activity["prompted"] != 0
            or activity["approval_reuse_status"] != "not-applicable"
            or receipt["harness"] != "codex"
            or receipt["event_name"] != "PreToolUse"
            or receipt["payload_kind"] != "inline"
            or receipt["observe_mode"] is not False
            or receipt["policy_action"] != action
            or activity["execution_status"] != ("allowed_unconfirmed" if action in {"allow", "warn"} else "prevented")
        ):
            raise TransitionError("legacy_probe_receipt_invalid")
        matched.append(receipt)
    check()
    if len(matched) > 1:
        raise TransitionError("legacy_probe_receipt_ambiguous")
    return matched[0] if matched else None
