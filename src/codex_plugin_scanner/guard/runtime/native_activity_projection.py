"""Project opted-in native policy receipts into the existing cloud event queue.

Hooks do not call this module. Sync discovers durable native receipts, writes
the locked activity payload, and leaves HTTP delivery to the existing event
uploader. A terminal allow or deny stays activity evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from ..mdm.contracts import ManagedPolicyState
from ..schemas.guard_event_v1 import GuardEventV1
from .native_activity_projection_ledger import (
    _LEDGER,
    _RECEIPT_KIND,
    _at_or_after,
    _backfill_remaining,
    _capture_watermark,
    _discover,
    _ensure_ledger,
    _is_native_activity_event,
    _native_tables_ready,
    _prune_ledger,
    _quarantine_other_bindings,
    _reduce_backfill,
    _sendable_keys,
    _unledgered_receipts,
)

_ACTIVITY_SCHEMA = "guard-native-cloud-activity.v1"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DISCOVERY_LIMIT = 25


class NativeActivityStore(Protocol):
    @property
    def guard_home(self) -> object: ...

    _guard_event_queue_limit: int

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _count_guard_event_upload_capacity(self, connection: sqlite3.Connection) -> int: ...

    def get_review_event_oauth_binding(self) -> Mapping[str, str] | None: ...

    def get_sync_payload(self, state_key: str) -> object: ...

    def set_sync_payload(
        self,
        state_key: str,
        payload: Mapping[str, object],
        now: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class NativeActivityEligibility:
    sync_enabled: bool
    workspace_id: str
    installation_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class NativeActivityProjection:
    eligibility: NativeActivityEligibility
    projected: int
    dropped: int
    withheld: int
    quarantined: int


def resolve_native_activity_eligibility(
    binding: Mapping[str, str] | None,
    *,
    sync_enabled: bool,
) -> NativeActivityEligibility:
    """Data-sync consent is the profile, sync setting, and installation binding."""

    if binding is None:
        return NativeActivityEligibility(False, "", "", "no_profile")
    workspace_id = str(binding.get("workspace_id", "")).strip().lower()
    installation_id = str(binding.get("machine_installation_id", "")).strip().lower()
    if _UUID.fullmatch(workspace_id) is None or _UUID.fullmatch(installation_id) is None:
        return NativeActivityEligibility(False, workspace_id, installation_id, "binding_invalid")
    if not sync_enabled:
        return NativeActivityEligibility(False, workspace_id, installation_id, "sync_disabled")
    return NativeActivityEligibility(True, workspace_id, installation_id, "eligible")


def eligibility_from_store(
    store: NativeActivityStore,
    *,
    managed_policy_state: ManagedPolicyState | None = None,
) -> NativeActivityEligibility:
    from pathlib import Path

    from ..config import load_guard_config

    binding = store.get_review_event_oauth_binding()
    home = store.guard_home if isinstance(store.guard_home, Path) else Path(str(store.guard_home))
    config = load_guard_config(
        home,
        create_home=False,
        managed_policy_state=managed_policy_state,
    )
    return resolve_native_activity_eligibility(binding, sync_enabled=bool(config.sync))


def native_activity_coverage(store: NativeActivityStore) -> dict[str, object]:
    """A lost, dropped, withheld, or unaccepted observation is not complete history."""

    with store._connect() as connection:
        _ensure_ledger(connection)
        counts = {
            str(row["state"]): int(row["count"])
            for row in connection.execute(f"select state, count(*) as count from {_LEDGER} group by state")
        }
        uploaded = connection.execute(
            f"""
            select count(*) as count
            from {_LEDGER} as ledger
            join guard_cloud_events as event
              on event.idempotency_key = ledger.idempotency_key
            where ledger.state = 'projected' and event.uploaded_at is not null
            """
        ).fetchone()
        unprojected = _unledgered_receipts(connection)
    projected = counts.get("projected", 0)
    dropped = counts.get("dropped", 0)
    withheld = counts.get("withheld", 0)
    quarantined = counts.get("quarantined", 0)
    accepted = int(uploaded["count"]) if uploaded is not None else 0
    complete = dropped == 0 and withheld == 0 and quarantined == 0 and unprojected == 0 and accepted == projected
    return {
        "accepted": accepted,
        "complete": complete,
        "dropped": dropped,
        "projected": projected,
        "quarantined": quarantined,
        "unprojected": unprojected,
        "withheld": withheld,
    }


def project_native_policy_activity(
    store: NativeActivityStore,
    *,
    eligibility: NativeActivityEligibility | None = None,
    limit: int = _DISCOVERY_LIMIT,
    managed_policy_state: ManagedPolicyState | None = None,
    now: str | None = None,
) -> NativeActivityProjection:
    """Queue bounded native activity for the current opt-in cohort."""

    resolved = eligibility or eligibility_from_store(store, managed_policy_state=managed_policy_state)
    recorded_now = now or datetime.now(timezone.utc).isoformat()
    if not resolved.sync_enabled:
        return NativeActivityProjection(resolved, 0, 0, 0, 0)
    floor = _capture_watermark(store, resolved, recorded_now)
    initial_backfill = _backfill_remaining(store, resolved)
    backfill_remaining = initial_backfill
    projected = dropped = withheld = 0
    with store._connect() as connection:
        _ensure_ledger(connection)
        if not _native_tables_ready(connection):
            return NativeActivityProjection(resolved, 0, 0, 0, 0)
        quarantined = _quarantine_other_bindings(connection, resolved, recorded_now)
        rows = [(source_kind, _copy_row(row)) for source_kind, row in _discover(connection, limit)]
    for source_kind, row in rows:
        outcome = _project_row(
            store,
            source_kind=source_kind,
            row=row,
            eligibility=resolved,
            floor=floor,
            backfill_remaining=backfill_remaining,
            now=recorded_now,
        )
        if outcome == "backfilled":
            backfill_remaining -= 1
            projected += 1
        elif outcome == "projected":
            projected += 1
        elif outcome == "dropped":
            dropped += 1
        elif outcome == "withheld":
            withheld += 1
    consumed_backfill = initial_backfill - backfill_remaining
    if consumed_backfill > 0:
        _reduce_backfill(
            store,
            resolved,
            used=consumed_backfill,
            now=recorded_now,
        )
    return NativeActivityProjection(resolved, projected, dropped, withheld, quarantined)


def sendable_guard_cloud_events(
    store: NativeActivityStore,
    events: list[dict[str, object]],
    *,
    eligibility: NativeActivityEligibility | None,
) -> list[dict[str, object]]:
    """Hold native activity that is no longer eligible. Leave every other event alone."""

    keys = _sendable_keys(store, eligibility)
    ready: list[dict[str, object]] = []
    for event in events:
        if not _is_native_activity_event(event):
            ready.append(event)
            continue
        key = event.get("idempotency_key")
        if isinstance(key, str) and key in keys:
            ready.append(event)
    return ready


def _project_row(
    store: NativeActivityStore,
    *,
    source_kind: str,
    row: Mapping[str, object],
    eligibility: NativeActivityEligibility,
    floor: str,
    backfill_remaining: int,
    now: str,
) -> str:
    recorded_at = str(row["recorded_at"])
    in_cohort = _at_or_after(recorded_at, floor)
    if not in_cohort and backfill_remaining <= 0:
        stored = _commit(
            store,
            source_kind=source_kind,
            row=row,
            eligibility=eligibility,
            state="withheld",
            event=None,
            now=now,
        )
        return "withheld" if stored == "withheld" else "duplicate"
    event = _activity_event(source_kind, row, eligibility)
    stored = _commit(
        store,
        source_kind=source_kind,
        row=row,
        eligibility=eligibility,
        state="projected",
        event=event,
        now=now,
    )
    if stored == "dropped":
        return "dropped"
    if stored != "projected":
        return "duplicate"
    if not in_cohort:
        return "backfilled"
    return "projected"


def _copy_row(row: sqlite3.Row) -> dict[str, object]:
    names = row.keys()
    return {str(name): row[name] for name in names}


def _activity_event(
    source_kind: str,
    row: Mapping[str, object],
    eligibility: NativeActivityEligibility,
) -> GuardEventV1:
    decision_id = str(row["decision_id"])
    observed = row["observe_mode"] in (1, True)
    activity: dict[str, object] = {
        "activitySchema": _ACTIVITY_SCHEMA,
        "decision": "observed" if observed else str(row["decision"]),
        "decisionId": decision_id,
        "eventName": str(row["event_name"]),
        "harnessId": str(row["harness"]),
        "observedAt": str(row["recorded_at"]),
        "observeMode": "1" if observed else "0",
        "policyGeneration": str(row["policy_generation"]),
        "reasonCode": str(row["reason_code"]),
        "sourceKind": source_kind,
    }
    for column, field in (
        ("model_output_action", "modelOutputAction"),
        ("policy_action", "policyAction"),
        ("observed_policy_action", "observedPolicyAction"),
        ("policy_digest", "policyDigest"),
        ("rule_digest", "ruleDigest"),
    ):
        value = row[column]
        if isinstance(value, str) and value.strip():
            activity[field] = value.strip()
    key = f"native-activity:{eligibility.workspace_id}:{eligibility.installation_id}:{source_kind}:{decision_id}"
    return GuardEventV1(
        event_id=f"guard-event-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:32]}",
        idempotency_key=key,
        event_type="receipt.created",
        source="edge",
        occurred_at=str(row["recorded_at"]),
        workspace_id=eligibility.workspace_id,
        device_id=eligibility.installation_id,
        payload={
            "receiptKind": _RECEIPT_KIND,
            "installationId": eligibility.installation_id,
            "activity": activity,
        },
    )


def _commit(
    store: NativeActivityStore,
    *,
    source_kind: str,
    row: Mapping[str, object],
    eligibility: NativeActivityEligibility,
    state: str,
    event: GuardEventV1 | None,
    now: str,
) -> str:
    decision_id = str(row["decision_id"])
    key = (
        event.idempotency_key
        if event is not None
        else (f"native-activity:{eligibility.workspace_id}:{eligibility.installation_id}:{source_kind}:{decision_id}")
    )
    with store._connect() as connection:
        _ensure_ledger(connection)
        existing = connection.execute(
            f"select state from {_LEDGER} where source_kind = ? and decision_id = ?",
            (source_kind, decision_id),
        ).fetchone()
        if existing is not None:
            return str(existing["state"])
        stored_state = state
        if event is not None:
            already = connection.execute(
                "select event_id from guard_cloud_events where idempotency_key = ?",
                (key,),
            ).fetchone()
            if already is None:
                pending_count = store._count_guard_event_upload_capacity(connection)
                if pending_count >= store._guard_event_queue_limit:
                    stored_state = "dropped"
                else:
                    payload = event.to_dict()
                    connection.execute(
                        """
                        insert or ignore into guard_cloud_events (
                          event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
                        ) values (?, ?, ?, ?, ?, null)
                        """,
                        (
                            event.event_id,
                            event.idempotency_key,
                            event.event_type,
                            json.dumps(payload, sort_keys=True),
                            event.occurred_at,
                        ),
                    )
        connection.execute(
            f"""
            insert into {_LEDGER} (
              source_kind, decision_id, workspace_id, installation_id,
              idempotency_key, state, recorded_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_kind,
                decision_id,
                eligibility.workspace_id,
                eligibility.installation_id,
                key,
                stored_state,
                str(row["recorded_at"]),
                now,
            ),
        )
        _prune_ledger(connection, eligibility)
        return stored_state
