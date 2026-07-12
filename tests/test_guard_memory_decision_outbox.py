from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.memory_decision_event import MEMORY_DECISION_EVENT_CONTRACT_VERSION
from codex_plugin_scanner.guard.memory_decision_outbox import enqueue_memory_decision_event
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.store import GuardStore


def _approval_request(
    *,
    request_id: str = "req-1",
    review_command: str = "npm install lodash",
    raw_command: str | None = "npm install lodash",
    artifact_id: str | None = "npm:lodash",
    artifact_name: str | None = "lodash",
    artifact_type: str | None = "package",
    harness: str = "codex",
) -> dict[str, object]:
    return {
        "request_id": request_id,
        "review_command": review_command,
        "raw_command_text": raw_command,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_type": artifact_type,
        "harness": harness,
        "risk_summary": "Supply-chain install",
        "risk_signals": ["network_install", "filesystem_write"],
        "queue_group_id": "queue-1",
        "action_identity": "action-1",
    }


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _seed_workspace(store: GuardStore) -> str:
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="demo-token",
        dpop_private_key_pem=None,  # type: ignore[arg-type]
        dpop_public_jwk=None,  # type: ignore[arg-type]
        dpop_public_jwk_thumbprint=None,  # type: ignore[arg-type]
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-07-07T00:00:00Z",
    )
    receipt = build_receipt(
        harness="codex",
        artifact_id="shell-command",
        artifact_hash="sha256:artifact",
        policy_decision="allow",
        capabilities_summary="shell",
        changed_capabilities=[],
        provenance_summary="local approval",
        artifact_name="Shell command",
        source_scope="project",
        approval_request_id="req-1",
        raw_command_text="npm install lodash",
    )
    store.add_receipt(receipt)
    return receipt.receipt_id


def _memory_events(store: GuardStore) -> list[dict[str, object]]:
    return [
        event
        for event in store.list_guard_events_v1(uploaded=False, limit=20)
        if event["event_type"] == "approval.memory_decision"
    ]


class TestMemoryDecisionOutboxEnqueue:
    def test_enqueue_writes_event_to_outbox(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        source_receipt_id = _seed_workspace(store)
        enqueued = enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert enqueued is True
        events = _memory_events(store)
        assert len(events) == 1
        assert events[0]["event_type"] == "approval.memory_decision"
        payload = events[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["eventType"] == "approval.memory_decision"
        assert payload["payload"]["decision_action"] == "approved"
        assert payload["payload"]["contractVersion"] == MEMORY_DECISION_EVENT_CONTRACT_VERSION
        assert payload["payload"]["device_id"] is not None
        assert payload["payload"]["machine_id"] is not None
        assert payload["payload"]["machine_installation_id"] is None
        assert payload["payload"]["source_receipt_id"] == source_receipt_id

    def test_enqueue_includes_project_identity_from_guard_operation(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        store.upsert_guard_session(
            session_id="session-1",
            harness="codex",
            surface="cli",
            status="active",
            client_name="codex",
            client_title=None,
            client_version=None,
            workspace=str(tmp_path),
            capabilities=[],
            now="2026-07-07T00:00:00Z",
        )
        store.upsert_guard_operation(
            operation_id="operation-1",
            session_id="session-1",
            harness="codex",
            operation_type="tool_call",
            status="waiting",
            approval_request_ids=["req-1"],
            resume_token=None,
            metadata={"project_id": "project-1", "workspace_path": str(tmp_path)},
            now="2026-07-07T00:00:00Z",
        )

        enqueued = enqueue_memory_decision_event(
            store,
            request=_approval_request(request_id="req-1"),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )

        assert enqueued is True
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["payload"]["project_id"] == "project-1"

    def test_enqueue_is_idempotent_by_request_action_time(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        for _ in range(3):
            enqueue_memory_decision_event(
                store,
                request=_approval_request(),
                action="allow",
                scope="harness",
                resolved_at="2026-07-07T00:00:00Z",
            )
        assert len(_memory_events(store)) == 1

    def test_block_and_allow_on_same_request_use_distinct_receipts(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        for action in ("allow", "block"):
            enqueue_memory_decision_event(
                store,
                request=_approval_request(),
                action=action,
                scope="harness",
                resolved_at="2026-07-07T00:00:00Z",
            )
        events = _memory_events(store)
        assert len(events) == 2
        source_receipt_ids = {
            event["payload"]["payload"]["source_receipt_id"] for event in events if isinstance(event["payload"], dict)
        }
        assert len(source_receipt_ids) == 2
        assert all(store.get_receipt(receipt_id) is not None for receipt_id in source_receipt_ids)

    def test_uses_first_matching_receipt_when_retries_share_a_request(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        first_receipt_id = _seed_workspace(store)
        retry_receipt = build_receipt(
            harness="codex",
            artifact_id="shell-command-retry",
            artifact_hash="sha256:retry",
            policy_decision="allow",
            capabilities_summary="shell",
            changed_capabilities=[],
            provenance_summary="retry",
            artifact_name="Shell command retry",
            source_scope="project",
            approval_request_id="req-1",
            raw_command_text="npm install other-package",
        )
        store.add_receipt(retry_receipt)

        assert enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["payload"]["source_receipt_id"] == first_receipt_id

    def test_enqueue_without_pattern_signal_keeps_receipt_lineage(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        request = _approval_request(
            request_id="req-no-signal",
            review_command="",
            raw_command=None,
            artifact_id=None,
            artifact_name=None,
        )
        assert enqueue_memory_decision_event(
            store,
            request=request,
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["payload"]["memory_pattern_fingerprint"] is None
        assert store.get_receipt(payload["payload"]["source_receipt_id"]) is not None

    def test_enqueue_rejects_empty_request_id(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        request = _approval_request(request_id="")
        assert not enqueue_memory_decision_event(
            store,
            request=request,
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert _memory_events(store) == []

    def test_enqueue_creates_receipt_without_cloud_pairing(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        assert enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        payload = _memory_events(store)[0]["payload"]
        assert isinstance(payload, dict)
        source_receipt_id = payload["payload"]["source_receipt_id"]
        assert store.get_receipt(source_receipt_id) is not None
