"""Daemon versioned resources and policy validation."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)
from tests.guard_approvals_support import (
    _guard_json_headers,
)


class TestGuardApprovals:
    def test_guard_daemon_v1_endpoints_expose_requests_diff_receipts_and_policy(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:project:workspace_skill",
            name="workspace_skill",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
            publisher="hashgraph-online",
        )
        store.record_diff(
            "codex",
            artifact.artifact_id,
            ["args"],
            "hash-before",
            "hash-after",
            "2026-04-11T00:00:00+00:00",
        )
        receipt = {
            "harness": "codex",
            "artifact_id": artifact.artifact_id,
            "artifact_hash": "hash-after",
            "policy_decision": "allow",
            "capabilities_summary": "mcp server • stdio • node",
            "changed_capabilities": ["args"],
            "provenance_summary": "project artifact defined at .codex/config.toml",
            "artifact_name": "workspace_skill",
            "source_scope": "project",
        }
        from codex_plugin_scanner.guard.receipts import build_receipt

        built_receipt = build_receipt(**receipt)
        store.add_receipt(built_receipt)
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-v1",
                harness="codex",
                artifact_id=artifact.artifact_id,
                artifact_name="workspace_skill",
                artifact_hash="hash-after",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-v1",
                approval_url="http://127.0.0.1/pending",
                publisher="hashgraph-online",
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
                requests_payload = json.loads(response.read().decode("utf-8"))
            item_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-v1",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(item_request, timeout=5) as response:
                request_payload = json.loads(response.read().decode("utf-8"))
            receipt_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/receipts/{built_receipt.receipt_id}",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(receipt_request, timeout=5) as response:
                receipt_payload = json.loads(response.read().decode("utf-8"))
            latest_receipt_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/receipts/latest?harness=codex&artifact_id="
                f"{urllib.parse.quote(artifact.artifact_id, safe='')}",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(latest_receipt_request, timeout=5) as response:
                latest_receipt_payload = json.loads(response.read().decode("utf-8"))
            diff_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/artifacts/{artifact.artifact_id}/diff?harness=codex",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(diff_request, timeout=5) as response:
                diff_payload = json.loads(response.read().decode("utf-8"))
            policy_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "publisher",
                        "publisher": "hashgraph-online",
                        "action": "allow",
                        "reason": "saved from api",
                    }
                ).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            with urllib.request.urlopen(policy_request, timeout=5) as response:
                policy_save_payload = json.loads(response.read().decode("utf-8"))
            policy_list_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy?harness=codex",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(policy_list_request, timeout=5) as response:
                policy_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert requests_payload["items"][0]["request_id"] == "req-v1"
        assert request_payload["artifact_id"] == artifact.artifact_id
        assert receipt_payload["receipt_id"] == built_receipt.receipt_id
        assert latest_receipt_payload["receipt_id"] == built_receipt.receipt_id
        assert diff_payload["changed_fields"] == ["args"]
        assert policy_save_payload["saved"] is True
        assert policy_payload["items"][0]["publisher"] == "hashgraph-online"

    def test_guard_daemon_diff_route_decodes_artifact_ids(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        artifact_id = "codex:project:tools/with/slash"
        store.record_diff(
            "codex",
            artifact_id,
            ["command"],
            "hash-before",
            "hash-after",
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/artifacts/codex%3Aproject%3Atools%2Fwith%2Fslash/diff?harness=codex",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                diff_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert diff_payload["artifact_id"] == artifact_id

    def test_guard_daemon_policy_upsert_rejects_unsupported_values(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "harness",
                        "action": "deny",
                    }
                ).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for unsupported policy action")
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "unsupported_policy_value"

    def test_guard_daemon_policy_upsert_requires_scope_target(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "artifact",
                        "action": "allow",
                    }
                ).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for missing scope target")
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "missing_scope_target"

    def test_guard_daemon_policy_upsert_rejects_unsupported_harness_family(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "harness",
                        "action": "allow",
                        "artifact_id": "family:tool-output",
                        "reason": "allow command output review",
                    }
                ).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for unsupported harness family")
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "unsupported_scoped_policy_family"

    def test_guard_daemon_policy_upsert_requires_auth_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "harness",
                        "action": "allow",
                    }
                ).encode("utf-8"),
                headers=_guard_json_headers(),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for missing auth token")
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"

    def test_guard_daemon_policy_upsert_rejects_non_ascii_auth_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "harness",
                        "action": "allow",
                    }
                ).encode("utf-8"),
                headers=_guard_json_headers("ñ"),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for malformed auth token")
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"
