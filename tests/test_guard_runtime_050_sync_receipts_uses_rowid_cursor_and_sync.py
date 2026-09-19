"""Runtime regression tests: sync receipts uses rowid cursor and sync."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardReceipt,
    GuardStore,
    guard_runner_module,
    json,
    stub_authenticated_urlopen,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_runtime_test_support import (
    _seed_guard_cloud,
)


def test_sync_receipts_uses_rowid_cursor_and_sync_context(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store)
    for index in range(3):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"receipt-{index}",
                timestamp="2026-04-19T00:00:00+00:00",
                harness="codex",
                artifact_id=f"artifact-{index}",
                artifact_hash=f"sha256:{index:064x}",
                policy_decision="review",
                capabilities_summary="requests file write",
                changed_capabilities=("fs_write",),
                provenance_summary="local codex workspace",
                artifact_name=f"artifact-{index}",
                source_scope="workspace",
            )
        )

    sync_payloads: list[dict[str, object]] = []

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        payload = json.loads(request.data.decode("utf-8"))
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"statuses": []})
        sync_payloads.append(payload)
        return _Response(
            {
                "syncedAt": "2026-04-19T00:00:10+00:00",
                "receiptsStored": len(payload["receipts"]),
                "advisories": [],
                "policy": {},
                "alertPreferences": {},
                "teamPolicyPack": {},
                "exceptions": [],
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    first_summary = guard_runner_module.sync_receipts(store)
    cursor_payload = store.get_sync_payload("receipt_sync_cursor")
    assert isinstance(cursor_payload, dict)
    first_cursor_rowid = cursor_payload["last_rowid"]
    assert isinstance(first_cursor_rowid, int)
    assert first_summary["receipts"] == 3
    assert "syncContext" in sync_payloads[0]
    assert sync_payloads[0]["syncContext"]["localGuardOnlineAt"]

    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-late",
            timestamp="2026-04-18T23:59:00+00:00",
            harness="codex",
            artifact_id="artifact-late",
            artifact_hash="sha256:late",
            policy_decision="review",
            capabilities_summary="late insert",
            changed_capabilities=("fs_write",),
            provenance_summary="local codex workspace",
            artifact_name="artifact-late",
            source_scope="workspace",
        )
    )

    second_summary = guard_runner_module.sync_receipts(store)
    assert second_summary["receipts"] == 1
    assert len(sync_payloads) == 2
    assert sync_payloads[1]["receipts"][0]["receiptId"] == "receipt-late"
    assert "lastReceiptSyncAt" not in sync_payloads[1]["syncContext"]
    latest_cursor = store.get_sync_payload("receipt_sync_cursor")
    assert isinstance(latest_cursor, dict)
    assert isinstance(latest_cursor["last_rowid"], int)
    assert latest_cursor["last_rowid"] > first_cursor_rowid


def test_sync_receipts_backfills_when_cursor_is_ahead_of_local_rows(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store)
    for index in range(2):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"receipt-{index}",
                timestamp="2026-04-19T00:00:00+00:00",
                harness="codex",
                artifact_id=f"artifact-{index}",
                artifact_hash=f"sha256:{index:064x}",
                policy_decision="review",
                capabilities_summary="requests file write",
                changed_capabilities=("fs_write",),
                provenance_summary="local codex workspace",
                artifact_name=f"artifact-{index}",
                source_scope="workspace",
            )
        )
    store.set_sync_payload(
        "receipt_sync_cursor",
        {"last_rowid": 9999, "synced_at": "2026-04-19T00:00:05+00:00"},
        "2026-04-19T00:00:05+00:00",
    )

    uploaded_sizes: list[int] = []

    class _Response:
        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

    def _fake_urlopen(request, timeout):
        payload = json.loads(request.data.decode("utf-8"))
        if request.full_url.endswith("/api/v1/guard/events"):
            return _Response({"statuses": []})
        uploaded_sizes.append(len(payload["receipts"]))
        return _Response(
            {
                "syncedAt": "2026-04-19T00:00:10+00:00",
                "receiptsStored": len(payload["receipts"]),
                "advisories": [],
                "policy": {},
                "alertPreferences": {},
                "teamPolicyPack": {},
                "exceptions": [],
            }
        )

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)

    summary = guard_runner_module.sync_receipts(store)

    assert uploaded_sizes == [2]
    assert summary["receipt_cursor_backfill"] is True
    cursor_payload = store.get_sync_payload("receipt_sync_cursor")
    assert isinstance(cursor_payload, dict)
    assert cursor_payload["last_rowid"] == store.latest_receipt_rowid()


def test_sync_receipts_marks_latest_connect_first_sync_succeeded(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store)
    request_id = "connect-imported-state"
    with store._connect() as connection:
        connection.execute(
            """
            insert into guard_connect_states (
              request_id,
              sync_url,
              allowed_origin,
              status,
              milestone,
              reason,
              created_at,
              updated_at,
              expires_at,
              completed_at,
              proof_json
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                "https://hol.org/api/guard/receipts/sync",
                "https://hol.org",
                "connected",
                "first_sync_pending",
                "waiting_for_first_sync",
                "2026-05-23T19:20:00+00:00",
                "2026-05-23T19:21:10+00:00",
                "2026-05-23T19:25:00+00:00",
                "2026-05-23T19:21:00+00:00",
                json.dumps(
                    {
                        "pairing_completed_at": "2026-05-23T19:21:00+00:00",
                        "first_synced_at": None,
                        "receipts_stored": 0,
                        "inventory_items": 0,
                        "runtime_session_id": "runtime-session-1",
                        "runtime_session_synced_at": "2026-05-23T19:21:05+00:00",
                    }
                ),
            ),
        )
        connection.execute(
            """
            insert into guard_connect_states (
              request_id,
              sync_url,
              allowed_origin,
              status,
              milestone,
              reason,
              created_at,
              updated_at,
              expires_at,
              completed_at,
              proof_json
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "connect-waiting-state",
                "https://hol.org/api/guard/receipts/sync",
                "https://hol.org",
                "waiting",
                "waiting_for_browser",
                "waiting_for_browser",
                "2026-05-23T19:21:30+00:00",
                "2026-05-23T19:21:30+00:00",
                "2026-05-23T19:26:30+00:00",
                None,
                json.dumps({}),
            ),
        )
    store.add_receipt(
        GuardReceipt(
            receipt_id="receipt-1",
            timestamp="2026-05-23T19:22:00+00:00",
            harness="codex",
            artifact_id="artifact-1",
            artifact_hash="sha256:receipt",
            policy_decision="review",
            artifact_name="Bash",
            capabilities_summary="runs shell commands",
            changed_capabilities=("shell_exec",),
            provenance_summary="local codex workspace",
        )
    )

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "syncedAt": "2026-05-23T19:22:36.076Z",
                    "receiptsStored": 1,
                    "advisories": [],
                    "policy": {},
                    "alertPreferences": {},
                    "teamPolicyPack": {},
                    "exceptions": [],
                }
            ).encode("utf-8")

    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _Response())

    payload = guard_runner_module.sync_receipts(store)
    with store._connect() as connection:
        row = connection.execute(
            "select milestone, proof_json from guard_connect_states where request_id = ?",
            (request_id,),
        ).fetchone()
    assert row is not None
    proof = json.loads(str(row["proof_json"]))

    assert payload["receipts_stored"] == 1
    assert row["milestone"] == "first_sync_succeeded"
    assert proof["first_synced_at"] == "2026-05-23T19:22:36.076Z"
    assert proof["receipts_stored"] == 1
    assert proof["runtime_session_id"] == "runtime-session-1"
    assert proof["runtime_session_synced_at"] == "2026-05-23T19:21:05+00:00"
