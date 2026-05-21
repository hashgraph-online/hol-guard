"""Phase 14 approval dedupe and concurrency regressions."""

from __future__ import annotations

import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_index_statements,
    approval_schema_statement,
    count_approval_requests,
)


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=5, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("pragma journal_mode=wal")
    conn.execute(approval_schema_statement())
    for statement in approval_index_statements():
        conn.execute(statement)
    return conn


def _make_request(
    *,
    artifact_id: str,
    launch_target: str,
    workspace: str = "ws-a",
    action_envelope_json: dict[str, object] | None = None,
) -> GuardApprovalRequest:
    request_id = str(uuid.uuid4())
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=artifact_id,
        artifact_name="package install",
        artifact_type="package_request",
        artifact_hash="artifact-hash",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=frozenset(["package_request"]),
        source_scope="project",
        config_path="/repo/.codex/config.toml",
        workspace=workspace,
        launch_target=launch_target,
        transport="stdio",
        risk_summary="risk",
        risk_signals=[],
        artifact_label=None,
        source_label=None,
        trigger_summary=None,
        why_now=None,
        launch_summary=None,
        risk_headline=None,
        action_envelope_json=action_envelope_json,
        decision_v2_json=None,
        fallback_cli_command=None,
        review_command=f"hol-guard review {request_id}",
        approval_url=f"http://localhost:4455/approve/{request_id}",
    )


def test_phase14_package_queue_identity_collapses_legacy_and_enriched_envelopes(tmp_path: Path) -> None:
    db_path = tmp_path / "guard.db"
    conn = _connect(db_path)
    artifact_id = "codex:project:package-request:minimist"
    launch_target = "npm install minimist@1.2.8"
    legacy_request = _make_request(
        artifact_id=artifact_id,
        launch_target=launch_target,
        action_envelope_json={
            "action_type": "shell_command",
            "tool_name": "Bash",
            "command": launch_target,
            "raw_payload_redacted": {"tool_name": "Bash"},
        },
    )
    enriched_request = _make_request(
        artifact_id=artifact_id,
        launch_target=launch_target,
        action_envelope_json={
            "action_type": "shell_command",
            "tool_name": "Bash",
            "command": launch_target,
            "package_manager": "npm",
            "package_name": "minimist",
            "package_intent_kind": "install",
            "package_targets": ["minimist@1.2.8"],
            "pre_execution_result": "require-reapproval",
            "raw_payload_redacted": {"tool_name": "Bash"},
        },
    )

    first_id = add_approval_request(conn, legacy_request, "2026-05-19T10:00:00Z")
    second_id = add_approval_request(conn, enriched_request, "2026-05-19T10:01:00Z")

    assert first_id == second_id
    assert count_approval_requests(conn, status="pending") == 1


def test_phase14_simultaneous_identical_package_requests_collapse_to_one_row(tmp_path: Path) -> None:
    db_path = tmp_path / "guard.db"
    setup_conn = _connect(db_path)
    setup_conn.close()
    artifact_id = "codex:project:package-request:minimist"
    request_one = _make_request(
        artifact_id=artifact_id,
        launch_target="npm install minimist@1.2.8",
    )
    request_two = _make_request(
        artifact_id=artifact_id,
        launch_target="npm install minimist@1.2.8",
    )
    barrier = threading.Barrier(2)

    def _insert(request: GuardApprovalRequest, now_value: str) -> str:
        conn = _connect(db_path)
        try:
            barrier.wait(timeout=5)
            request_id = add_approval_request(conn, request, now_value)
            conn.commit()
            return request_id
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(_insert, request_one, "2026-05-19T10:00:00Z")
        second_future = executor.submit(_insert, request_two, "2026-05-19T10:00:01Z")
        first_id = first_future.result()
        second_id = second_future.result()

    verify_conn = _connect(db_path)
    try:
        assert first_id == second_id
        assert count_approval_requests(verify_conn, status="pending") == 1
    finally:
        verify_conn.close()


def test_phase14_simultaneous_distinct_package_requests_stay_isolated(tmp_path: Path) -> None:
    db_path = tmp_path / "guard.db"
    setup_conn = _connect(db_path)
    setup_conn.close()
    minimist_request = _make_request(
        artifact_id="codex:project:package-request:minimist",
        launch_target="npm install minimist@1.2.8",
    )
    lodash_request = _make_request(
        artifact_id="codex:project:package-request:lodash",
        launch_target="npm install lodash@4.17.21",
    )
    barrier = threading.Barrier(2)

    def _insert(request: GuardApprovalRequest, now_value: str) -> str:
        conn = _connect(db_path)
        try:
            barrier.wait(timeout=5)
            request_id = add_approval_request(conn, request, now_value)
            conn.commit()
            return request_id
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(_insert, minimist_request, "2026-05-19T10:00:00Z")
        second_future = executor.submit(_insert, lodash_request, "2026-05-19T10:00:01Z")
        first_id = first_future.result()
        second_id = second_future.result()

    verify_conn = _connect(db_path)
    try:
        assert first_id != second_id
        assert count_approval_requests(verify_conn, status="pending") == 2
    finally:
        verify_conn.close()
