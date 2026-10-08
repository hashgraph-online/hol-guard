"""SQLite ledger and discovery for opted-in native activity projection."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .native_activity_projection import NativeActivityEligibility, NativeActivityStore

_RECEIPT_KIND = "native_policy_decision"
_LEDGER = "native_activity_projection_ledger"
_BACKFILL_KEY = "native_activity_backfill_authorization"
_COLUMNS = (
    "decision_id, harness, event_name, policy_generation, policy_digest, "
    "rule_digest, decision, model_output_action, policy_action, "
    "observed_policy_action, reason_code, observe_mode, recorded_at"
)


def _ensure_ledger(connection: sqlite3.Connection) -> None:
    connection.execute(
        f"""
        create table if not exists {_LEDGER} (
          source_kind text not null check (source_kind in ('hook', 'prompt')),
          decision_id text not null check (length(decision_id) = 64),
          workspace_id text not null,
          installation_id text not null,
          idempotency_key text not null unique,
          state text not null check (state in ('projected', 'dropped', 'withheld', 'quarantined')),
          recorded_at text not null,
          updated_at text not null,
          primary key (source_kind, decision_id)
        )
        """
    )


def _native_tables_ready(connection: sqlite3.Connection) -> bool:
    rows = connection.execute(
        """
        select name from sqlite_master
        where type = 'table'
          and name in ('native_hook_decision_receipts', 'native_prompt_decision_receipts')
        """
    ).fetchall()
    return len(rows) == 2


def _discover(connection: sqlite3.Connection, limit: int) -> list[tuple[str, sqlite3.Row]]:
    discovered: list[tuple[str, sqlite3.Row]] = []
    for source_kind, table in (
        ("hook", "native_hook_decision_receipts"),
        ("prompt", "native_prompt_decision_receipts"),
    ):
        rows = connection.execute(
            f"""
            select {_COLUMNS}
            from {table} as receipt
            where not exists (
              select 1 from {_LEDGER} as ledger
              where ledger.source_kind = ? and ledger.decision_id = receipt.decision_id
            )
            order by receipt.recorded_at asc, receipt.decision_id asc
            limit ?
            """,
            (source_kind, limit),
        ).fetchall()
        discovered.extend((source_kind, row) for row in rows)
    discovered.sort(key=lambda item: (str(item[1]["recorded_at"]), str(item[1]["decision_id"])))
    return discovered[:limit]


def _quarantine_other_bindings(
    connection: sqlite3.Connection,
    eligibility: NativeActivityEligibility,
    now: str,
) -> int:
    # Quarantined rows are not deletable here — the row itself must remain in
    # the ledger so the queue can still track and report them (the ledger is
    # the authority for "this request was quarantined"). Dead queue weight is
    # handled by `_prune_ledger` once the per-(workspace, installation) cap
    # is exceeded.
    cursor = connection.execute(
        f"""
        update {_LEDGER}
        set state = 'quarantined', updated_at = ?
        where state = 'projected'
          and (workspace_id != ? or installation_id != ?)
        """,
        (now, eligibility.workspace_id, eligibility.installation_id),
    )
    return int(cursor.rowcount or 0)


_LEDGER_RETENTION_CAP = 500


def _prune_ledger(
    connection: sqlite3.Connection,
    eligibility: NativeActivityEligibility,
) -> int:
    """Bound the projection ledger per (workspace, installation) pair.

    Receipts written to ``projected``/``withheld``/``dropped`` are terminal — the
    only live read path is ``_sendable_keys`` (``state = 'projected'``), so a
    projected row stays pinned until its matching event has been uploaded.
    Pruning is by retention cap: keep the newest ``_LEDGER_RETENTION_CAP`` rows
    per (workspace, installation); older terminal rows are dead weight.
    Quarantined rows are dropped along with their unuploaded
    ``guard_cloud_events`` row so the queue cannot accumulate dead weight
    across binding changes.
    """
    connection.execute(
        f"""
        delete from guard_cloud_events
        where uploaded_at is null
          and idempotency_key in (
            select idempotency_key from {_LEDGER}
            where workspace_id = ? and installation_id = ?
              and state = 'quarantined'
              and (source_kind, decision_id) in (
                select source_kind, decision_id from {_LEDGER}
                where workspace_id = ? and installation_id = ?
                order by recorded_at desc
                limit -1 offset ?
              )
          )
        """,
        (
            eligibility.workspace_id,
            eligibility.installation_id,
            eligibility.workspace_id,
            eligibility.installation_id,
            _LEDGER_RETENTION_CAP,
        ),
    )
    cursor = connection.execute(
        f"""
        delete from {_LEDGER}
        where (source_kind, decision_id) in (
            select source_kind, decision_id from {_LEDGER}
            where workspace_id = ? and installation_id = ?
            order by recorded_at desc
            limit -1 offset ?
        )
        """,
        (
            eligibility.workspace_id,
            eligibility.installation_id,
            _LEDGER_RETENTION_CAP,
        ),
    )
    return int(cursor.rowcount or 0)


def _capture_watermark(
    store: NativeActivityStore,
    eligibility: NativeActivityEligibility,
    now: str,
) -> str:
    key = _watermark_key(eligibility)
    current = store.get_sync_payload(key)
    if isinstance(current, dict):
        floor = current.get("recordedAtFloor")
        if (
            isinstance(floor, str)
            and current.get("workspaceId") == eligibility.workspace_id
            and current.get("installationId") == eligibility.installation_id
        ):
            return floor
    store.set_sync_payload(
        key,
        {
            "installationId": eligibility.installation_id,
            "recordedAtFloor": now,
            "workspaceId": eligibility.workspace_id,
        },
        now,
    )
    return now


def _watermark_key(eligibility: NativeActivityEligibility) -> str:
    return f"native_activity_opt_in_watermark:{eligibility.workspace_id}:{eligibility.installation_id}"


def _reduce_backfill(
    store: NativeActivityStore,
    eligibility: NativeActivityEligibility,
    *,
    used: int,
    now: str,
) -> None:
    payload = store.get_sync_payload(_BACKFILL_KEY)
    if not isinstance(payload, dict) or used <= 0:
        return
    updated = dict(payload)
    raw_limit = updated.get("limit")
    if isinstance(raw_limit, bool) or not isinstance(raw_limit, int):
        return
    updated["limit"] = max(0, raw_limit - used)
    updated["workspaceId"] = eligibility.workspace_id
    updated["installationId"] = eligibility.installation_id
    store.set_sync_payload(_BACKFILL_KEY, updated, now)


def _backfill_remaining(store: NativeActivityStore, eligibility: NativeActivityEligibility) -> int:
    payload = store.get_sync_payload(_BACKFILL_KEY)
    if not isinstance(payload, dict):
        return 0
    if payload.get("workspaceId") != eligibility.workspace_id:
        return 0
    if payload.get("installationId") != eligibility.installation_id:
        return 0
    raw_limit = payload.get("limit")
    if isinstance(raw_limit, bool) or not isinstance(raw_limit, int):
        return 0
    return raw_limit if 0 < raw_limit <= 50 else 0


def _unledgered_receipts(connection: sqlite3.Connection) -> int:
    if not _native_tables_ready(connection):
        return 0
    pending = 0
    for source_kind, table in (
        ("hook", "native_hook_decision_receipts"),
        ("prompt", "native_prompt_decision_receipts"),
    ):
        row = connection.execute(
            f"""
            select count(*) as count from {table} as receipt
            where not exists (
              select 1 from {_LEDGER} as ledger
              where ledger.source_kind = ? and ledger.decision_id = receipt.decision_id
            )
            """,
            (source_kind,),
        ).fetchone()
        pending += int(row["count"]) if row is not None else 0
    return pending


def _sendable_keys(
    store: NativeActivityStore,
    eligibility: NativeActivityEligibility | None,
) -> set[str]:
    if eligibility is None or not eligibility.sync_enabled:
        return set()
    with store._connect() as connection:
        _ensure_ledger(connection)
        rows = connection.execute(
            f"""
            select idempotency_key from {_LEDGER}
            where state = 'projected' and workspace_id = ? and installation_id = ?
            """,
            (eligibility.workspace_id, eligibility.installation_id),
        ).fetchall()
    return {str(row["idempotency_key"]) for row in rows}


def _is_native_activity_event(event: Mapping[str, object]) -> bool:
    body = event.get("payload")
    if not isinstance(body, dict):
        return False
    payload = cast(dict[str, object], body)
    inner = payload.get("payload")
    candidate = inner if isinstance(inner, dict) else payload
    return candidate.get("receiptKind") == _RECEIPT_KIND


def _at_or_after(recorded_at: str, floor: str) -> bool:
    recorded = _parse_time(recorded_at)
    start = _parse_time(floor)
    if recorded is None or start is None:
        return False
    return recorded >= start


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)
