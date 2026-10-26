"""GuardStore receipt facade: the resident owns every receipt fact.

Python supplies instants and the receipt fields; the resident canonicalizes the
decision, redacts the envelope, writes rows, rollups and the pending cloud
event, and returns raw rows that are only shaped here.
"""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

import json
from contextlib import closing
from datetime import datetime, timezone
from uuid import uuid4

from .models import GuardRuntimeRegistration

# ruff: noqa: F403,F405
from .store_base import *
from .store_base import _canonical_utc_timestamp
from .store_inventory import inventory_artifact_wire


def _receipt_wire(receipt: GuardReceipt) -> dict[str, object]:
    return {
        "receipt_id": receipt.receipt_id,
        "timestamp": receipt.timestamp,
        "harness": receipt.harness,
        "artifact_id": receipt.artifact_id,
        "artifact_hash": receipt.artifact_hash,
        "policy_decision": receipt.policy_decision,
        "capabilities_summary": receipt.capabilities_summary,
        "changed_capabilities": list(receipt.changed_capabilities),
        "provenance_summary": receipt.provenance_summary,
        "user_override": receipt.user_override,
        "artifact_name": receipt.artifact_name,
        "source_scope": receipt.source_scope,
        "diff_summary": receipt.diff_summary,
        "approval_source": receipt.approval_source,
        "approval_request_id": receipt.approval_request_id,
        "scanner_evidence": [dict(item) for item in receipt.scanner_evidence],
        "raw_command_text": receipt.raw_command_text,
    }


def _now_iso() -> str:
    return _canonical_utc_timestamp(datetime.now(timezone.utc).isoformat())


class StoreReceiptsRuntimeMixin:
    def add_receipt(
        self,
        receipt: GuardReceipt,
        *,
        action_envelope: GuardActionEnvelope | None = None,
    ) -> None:
        self._native_store_call(
            "add_receipt",
            {
                "receipt": _receipt_wire(receipt),
                "action_envelope": action_envelope.to_dict() if action_envelope is not None else None,
                "now": _now_iso(),
                "new_device_id": uuid4().hex,
                "event_queue_limit": self._guard_event_queue_limit,
            },
        )

    def record_tool_call_evidence(
        self,
        *,
        artifact: GuardArtifact,
        artifact_hash: str,
        policy_action: GuardAction,
        approved: bool,
        receipt: GuardReceipt,
        event_name: str,
        event_payload: dict[str, object],
        now: str,
    ) -> None:
        """Write the inventory row, receipt and runtime event in one resident transaction."""
        self._native_store_call(
            "record_tool_call_evidence",
            {
                "inventory": inventory_artifact_wire(
                    artifact=artifact,
                    artifact_hash=artifact_hash,
                    policy_action=policy_action,
                    changed=False,
                    now=now,
                    approved=approved,
                ),
                "receipt": _receipt_wire(receipt),
                "action_envelope": None,
                "now": _now_iso(),
                "new_device_id": uuid4().hex,
                "event_queue_limit": self._guard_event_queue_limit,
                "event_name": event_name,
                "event_payload_json": json.dumps(event_payload),
                "event_occurred_at": now,
            },
        )

    def set_receipt_action_envelope(self, receipt_id: str, action_envelope: dict[str, object]) -> None:
        self._native_store_call(
            "set_receipt_action_envelope",
            {"receipt_id": receipt_id, "action_envelope": action_envelope},
        )

    def update_receipt_policy_decision(self, receipt_id: str, policy_decision: str) -> None:
        self._native_store_call(
            "update_receipt_policy_decision",
            {"receipt_id": receipt_id, "policy_decision": policy_decision},
        )

    def update_receipt_approval_context(
        self,
        receipt_id: str,
        *,
        approval_source: str | None,
        approval_request_id: str | None,
    ) -> None:
        self._native_store_call(
            "update_receipt_approval_context",
            {
                "receipt_id": receipt_id,
                "approval_source": approval_source,
                "approval_request_id": approval_request_id,
            },
        )

    def reconcile_receipt_events(self) -> None:
        self._native_store_call("reconcile_receipt_events", {})

    def list_receipts(self, limit: int = 50, harness: str | None = None) -> list[dict[str, object]]:
        return list(self._native_store_call("list_receipts", {"limit": limit, "harness": harness}))

    def list_receipts_since_rowid(
        self,
        *,
        after_rowid: int | None,
        limit: int = 200,
        harness: str | None = None,
    ) -> list[dict[str, object]]:
        return list(
            self._native_store_call(
                "list_receipts_since_rowid",
                {"after_rowid": after_rowid, "limit": limit, "harness": harness},
            )
        )

    def list_receipts_for_command_detail_backfill(
        self,
        *,
        limit: int = 2000,
        days: int = 7,
        before_rowid: int | None = None,
    ) -> list[dict[str, object]]:
        return list(
            self._native_store_call(
                "list_receipts_for_command_detail_backfill",
                {"limit": limit, "days": days, "before_rowid": before_rowid, "now": _now_iso()},
            )
        )

    def latest_receipt_rowid(self, *, harness: str | None = None) -> int | None:
        value = self._native_store_call("latest_receipt_rowid", {"harness": harness})
        return value if isinstance(value, int) else None

    def get_receipt(self, receipt_id: str) -> dict[str, object] | None:
        return self._native_store_call("get_receipt", {"receipt_id": receipt_id})

    def get_receipt_for_approval_request(
        self,
        request_id: str,
        *,
        policy_decision: str,
    ) -> dict[str, object] | None:
        return self._native_store_call(
            "get_receipt_for_approval_request",
            {"request_id": request_id, "policy_decision": policy_decision},
        )

    def get_latest_receipt(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        return self._native_store_call("get_latest_receipt", {"harness": harness, "artifact_id": artifact_id})

    def count_receipts(self, harness: str | None = None) -> int:
        return int(self._native_store_call("count_receipts", {"harness": harness}))

    def receipt_summary_between(self, *, start_at: str, before_at: str) -> dict[str, object]:
        return dict(self._native_store_call("receipt_summary_between", {"start_at": start_at, "before_at": before_at}))

    def receipt_analytics(
        self,
        *,
        activity_days: int = 90,
        trend_days: int = 7,
        top_limit: int = 10,
    ) -> dict[str, object]:
        return dict(
            self._native_store_call(
                "receipt_analytics",
                {
                    "activity_days": activity_days,
                    "trend_days": trend_days,
                    "top_limit": top_limit,
                    "now": _now_iso(),
                },
            )
        )

    def receipt_decision_counts(self, harness: str, artifact_id: str) -> dict[str, int]:
        return dict(
            self._native_store_call("receipt_decision_counts", {"harness": harness, "artifact_id": artifact_id})
        )

    def upsert_runtime_state(
        self,
        *,
        session_id: str,
        daemon_host: str,
        daemon_port: int,
        started_at: str,
        last_heartbeat_at: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into guard_runtime_state (
                  state_key, session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                )
                values ('runtime', ?, ?, ?, ?, ?)
                on conflict(state_key) do update set
                  session_id = excluded.session_id,
                  daemon_host = excluded.daemon_host,
                  daemon_port = excluded.daemon_port,
                  started_at = excluded.started_at,
                  last_heartbeat_at = excluded.last_heartbeat_at
                """,
                (session_id, daemon_host, daemon_port, started_at, last_heartbeat_at),
            )

    def try_touch_runtime_state(
        self,
        *,
        session_id: str,
        last_heartbeat_at: str,
        timeout_seconds: float,
        registration: GuardRuntimeRegistration | None = None,
    ) -> bool:
        """Persist a heartbeat without inheriting the store's long busy timeout.

        When the runtime row is gone (for example after the store was
        quarantined and re-initialized during uptime), a serving daemon can
        recreate it by passing its registration identity. The insert never
        steals a row owned by another session.

        The connection is held under the shared storage gate; while the
        exclusive gate holds the store for quarantine recovery this returns
        False without touching the database, and the heartbeat writer retries
        on its own cadence rather than blocking on the lock.
        """

        bounded_timeout = min(max(timeout_seconds, 0.0), 1.0)
        try:
            with self._try_hold_storage_gate(exclusive=False) as gate_held:
                if not gate_held:
                    return False
                with closing(sqlite3.connect(self.path, timeout=bounded_timeout)) as connection:
                    connection.execute(f"pragma busy_timeout={int(bounded_timeout * 1000)}")
                    cursor = connection.execute(
                        """
                        update guard_runtime_state
                        set last_heartbeat_at = ?
                        where state_key = 'runtime'
                          and session_id = ?
                        """,
                        (last_heartbeat_at, session_id),
                    )
                    if cursor.rowcount == 0 and registration is not None:
                        connection.execute(
                            """
                            insert into guard_runtime_state (
                              state_key, session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                            )
                            values ('runtime', ?, ?, ?, ?, ?)
                            on conflict(state_key) do nothing
                            """,
                            (
                                session_id,
                                registration.daemon_host,
                                registration.daemon_port,
                                registration.started_at,
                                last_heartbeat_at,
                            ),
                        )
                    connection.commit()
        except (OSError, sqlite3.Error):
            return False
        return True

    def get_runtime_state(self) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select session_id, daemon_host, daemon_port, started_at, last_heartbeat_at
                from guard_runtime_state
                where state_key = 'runtime'
                """
            ).fetchone()
        if row is None:
            return None
        return GuardRuntimeState(
            session_id=str(row["session_id"]),
            daemon_host=str(row["daemon_host"]),
            daemon_port=int(row["daemon_port"]),
            started_at=str(row["started_at"]),
            last_heartbeat_at=str(row["last_heartbeat_at"]),
        ).to_dict()

    def clear_runtime_state(self, *, session_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                delete from guard_runtime_state
                where state_key = 'runtime'
                  and session_id = ?
                """,
                (session_id,),
            )
