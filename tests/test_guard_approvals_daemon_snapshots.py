"""Daemon queue snapshots and approval dashboard resources."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardReceipt
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)
from tests.guard_approvals_support import (
    _guard_json_headers,
)


class TestGuardApprovals:
    def test_guard_daemon_serves_approval_queue_and_resolves_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-456",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-456",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-456",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            list_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(list_request, timeout=5) as response:
                approvals_payload = json.loads(response.read().decode("utf-8"))
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/approvals/req-456/decision",
                data=json.dumps({"action": "allow", "scope": "artifact", "reason": "approved"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                decision_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert approvals_payload["items"][0]["request_id"] == "req-456"
        assert decision_payload["resolved"] is True
        assert store.get_approval_request("req-456")["status"] == "resolved"

    def test_guard_daemon_runtime_snapshot_exposes_runtime_and_pending_queue(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-runtime",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-runtime",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-runtime",
                approval_url="http://127.0.0.1/pending",
                workspace=str(tmp_path / "workspace"),
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/runtime",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                snapshot_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert snapshot_payload["approval_center_url"] == f"http://127.0.0.1:{daemon.port}"
        assert snapshot_payload["pending_count"] == 1
        assert snapshot_payload["items"][0]["request_id"] == "req-runtime"
        assert snapshot_payload["runtime_state"]["daemon_port"] == daemon.port
        assert snapshot_payload["runtime_state"]["approval_center_url"] == f"http://127.0.0.1:{daemon.port}"
        assert snapshot_payload["runtime_state"]["session_id"]

    def test_guard_daemon_runtime_snapshot_brackets_ipv6_urls(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        monkeypatch.setattr(daemon._server, "daemon_host", lambda: "::1")
        daemon._server.runtime_host = "::1"
        runtime_state = store.get_runtime_state()
        assert runtime_state is not None
        store.upsert_runtime_state(
            session_id=str(runtime_state["session_id"]),
            daemon_host="::1",
            daemon_port=daemon.port,
            started_at=str(runtime_state["started_at"]),
            last_heartbeat_at=str(runtime_state["last_heartbeat_at"]),
        )

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/runtime",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                snapshot_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        expected_url = f"http://[::1]:{daemon.port}"
        assert snapshot_payload["approval_center_url"] == expected_url
        assert snapshot_payload["runtime_state"]["approval_center_url"] == expected_url

    def test_guard_daemon_runtime_snapshot_counts_all_pending_requests_beyond_page_limit(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for index in range(205):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=f"req-snapshot-{index}",
                    harness="codex",
                    artifact_id=f"codex:project:item-{index}",
                    artifact_name=f"item-{index}",
                    artifact_hash=f"hash-{index}",
                    policy_action="require-reapproval",
                    recommended_scope="artifact",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                    review_command=f"hol-guard approvals approve req-snapshot-{index}",
                    approval_url="http://127.0.0.1/pending",
                ),
                "2026-04-11T00:00:00+00:00",
            )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/runtime",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                snapshot_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert snapshot_payload["pending_count"] == 205
        assert len(snapshot_payload["items"]) == 200

    def test_guard_daemon_runtime_snapshot_can_omit_queue_items_for_dashboard_perf(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for index in range(3):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=f"req-lite-{index}",
                    harness="codex",
                    artifact_id=f"codex:project:item-{index}",
                    artifact_name=f"item-{index}",
                    artifact_hash=f"hash-{index}",
                    policy_action="require-reapproval",
                    recommended_scope="artifact",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / "workspace" / "guard-config.toml"),
                    review_command=f"hol-guard approvals approve req-lite-{index}",
                    approval_url="http://127.0.0.1/pending",
                ),
                "2026-04-11T00:00:00+00:00",
            )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/runtime?include_items=0",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                snapshot_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert snapshot_payload["pending_count"] == 3
        assert snapshot_payload["items"] == []
        assert snapshot_payload["queue_summary"]["remaining_pending_count"] == 3

    def test_guard_daemon_runtime_snapshot_can_omit_latest_receipts_for_request_pages(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_receipt(
            GuardReceipt(
                receipt_id="receipt-heavy-1",
                timestamp="2026-04-11T00:00:00+00:00",
                harness="codex",
                artifact_id="codex:project:tool",
                artifact_hash="hash-heavy-1",
                policy_decision="allow",
                capabilities_summary="capabilities",
                changed_capabilities=("command",),
                provenance_summary="provenance",
                scanner_evidence=({"detector": "fixture", "detail": "x" * 10_000},),
            )
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/runtime?include_items=0&include_receipts=0",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                snapshot_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert snapshot_payload["receipt_count"] == 1
        assert snapshot_payload["latest_receipts"] == []

    def test_guard_daemon_detail_page_serves_dashboard_shell(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        target_artifact = "codex:project:workspace_skill"
        target_receipt = {
            "harness": "codex",
            "artifact_id": target_artifact,
            "artifact_hash": "hash-target",
            "policy_decision": "allow",
            "capabilities_summary": "target capabilities",
            "changed_capabilities": ["args"],
            "provenance_summary": "target provenance summary",
            "artifact_name": "workspace_skill",
            "source_scope": "project",
        }
        from codex_plugin_scanner.guard.receipts import build_receipt

        store.add_receipt(build_receipt(**target_receipt))
        for index in range(250):
            store.add_receipt(
                build_receipt(
                    harness="codex",
                    artifact_id=f"codex:project:other_{index}",
                    artifact_hash=f"hash-{index}",
                    policy_decision="allow",
                    capabilities_summary=f"other capabilities {index}",
                    changed_capabilities=["args"],
                    provenance_summary=f"other provenance {index}",
                    artifact_name=f"other_{index}",
                    source_scope="project",
                )
            )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-detail",
                harness="codex",
                artifact_id=target_artifact,
                artifact_name="workspace_skill",
                artifact_hash="hash-target",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-detail",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/requests/req-detail", timeout=5) as response:
                body = response.read().decode("utf-8")
        finally:
            daemon.stop()

        assert "guard-dashboard-root" in body
        assert "Local approval center" in body
        assert "Hashgraph Online" in body

    def test_guard_daemon_serves_dashboard_assets_when_present(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            asset_url = f"http://127.0.0.1:{daemon.port}/assets/guard-dashboard.js"
            with urllib.request.urlopen(asset_url, timeout=5) as response:
                body = response.read().decode("utf-8")
                content_type = response.headers.get("Content-Type")
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/brand/Logo_Whole.png", timeout=5) as response:
                logo_bytes = response.read()
                logo_type = response.headers.get("Content-Type")
        finally:
            daemon.stop()

        assert content_type is not None
        assert "javascript" in content_type
        assert "guard-dashboard-root" in body
        assert logo_type == "image/png"
        assert len(logo_bytes) > 0
