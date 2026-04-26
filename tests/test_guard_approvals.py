"""Behavior tests for the Guard approval queue and approval center."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import bridge as guard_bridge_module
from codex_plugin_scanner.guard.approvals import apply_approval_resolution, queue_blocked_approvals
from codex_plugin_scanner.guard.bridge import BridgeConfig, GuardBridge
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash, evaluate_detection
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import client as daemon_client_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.models import (
    GuardApprovalRequest,
    GuardArtifact,
    HarnessDetection,
    PolicyDecision,
)
from codex_plugin_scanner.guard.store import GuardStore


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _guard_json_headers(auth_token: str | None = None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if auth_token is not None:
        headers["X-Guard-Token"] = auth_token
    return headers


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
approval_policy = "never"

[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    _write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )


class TestGuardApprovals:
    def test_guard_store_persists_and_resolves_approval_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        request = GuardApprovalRequest(
            request_id="req-123",
            harness="codex",
            artifact_id="codex:project:workspace_skill",
            artifact_name="workspace_skill",
            artifact_hash="hash-123",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("args",),
            source_scope="project",
            config_path=str(workspace_dir / ".codex" / "config.toml"),
            workspace=str(workspace_dir),
            review_command="hol-guard approvals approve req-123",
            approval_url="http://127.0.0.1:4455/approvals/req-123",
        )

        store.add_approval_request(request, "2026-04-11T00:00:00+00:00")
        pending = store.list_approval_requests()
        store.resolve_approval_request(
            "req-123",
            resolution_action="allow",
            resolution_scope="artifact",
            reason="reviewed",
            resolved_at="2026-04-11T00:01:00+00:00",
        )
        resolved = store.get_approval_request("req-123")

        assert pending[0]["status"] == "pending"
        assert pending[0]["approval_url"] == "http://127.0.0.1:4455/approvals/req-123"
        assert pending[0]["workspace"] == str(workspace_dir)
        assert resolved is not None
        assert resolved["status"] == "resolved"
        assert resolved["resolution_action"] == "allow"
        assert resolved["resolution_scope"] == "artifact"

    def test_guard_surface_daemon_client_recovers_missing_auth_token(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"
        cleared: list[Path] = []
        restarted: list[Path] = []
        auth_token_calls = {"count": 0}

        monkeypatch.setattr(
            daemon_client_module,
            "load_guard_daemon_url",
            lambda _guard_home: "http://127.0.0.1:4781",
        )

        def fake_load_auth_token(_guard_home: Path) -> str | None:
            auth_token_calls["count"] += 1
            return "fresh-token" if auth_token_calls["count"] > 1 else None

        monkeypatch.setattr(daemon_client_module, "load_guard_daemon_auth_token", fake_load_auth_token)
        monkeypatch.setattr(
            daemon_client_module,
            "clear_guard_daemon_state",
            lambda path: cleared.append(path),
        )
        monkeypatch.setattr(
            daemon_client_module,
            "ensure_guard_daemon",
            lambda path: restarted.append(path) or "http://127.0.0.1:4781",
        )

        client = daemon_client_module.load_guard_surface_daemon_client(guard_home)

        assert client.daemon_url == "http://127.0.0.1:4781"
        assert client.auth_token == "fresh-token"
        assert cleared == [guard_home]
        assert restarted == [guard_home]

    def test_guard_surface_daemon_client_recovers_missing_daemon_url(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"
        cleared: list[Path] = []
        restarted: list[Path] = []
        daemon_url_calls = {"count": 0}
        auth_token_calls = {"count": 0}

        def fake_load_daemon_url(_guard_home: Path) -> str | None:
            daemon_url_calls["count"] += 1
            return "http://127.0.0.1:4781" if daemon_url_calls["count"] > 1 else None

        def fake_load_auth_token(_guard_home: Path) -> str | None:
            auth_token_calls["count"] += 1
            return "fresh-token" if auth_token_calls["count"] > 1 else None

        monkeypatch.setattr(daemon_client_module, "load_guard_daemon_url", fake_load_daemon_url)
        monkeypatch.setattr(daemon_client_module, "load_guard_daemon_auth_token", fake_load_auth_token)
        monkeypatch.setattr(
            daemon_client_module,
            "clear_guard_daemon_state",
            lambda path: cleared.append(path),
        )
        monkeypatch.setattr(
            daemon_client_module,
            "ensure_guard_daemon",
            lambda path: restarted.append(path) or "http://127.0.0.1:4781",
        )

        client = daemon_client_module.load_guard_surface_daemon_client(guard_home)

        assert client.daemon_url == "http://127.0.0.1:4781"
        assert client.auth_token == "fresh-token"
        assert cleared == [guard_home]
        assert restarted == [guard_home]

    def test_guard_surface_daemon_client_wraps_transport_failures(self, monkeypatch):
        client = daemon_client_module.GuardSurfaceDaemonClient("http://127.0.0.1:4781", "auth-token")

        def raise_transport_error(request, timeout):
            raise urllib.error.URLError("offline")

        monkeypatch.setattr(daemon_client_module.urllib.request, "urlopen", raise_transport_error)

        with pytest.raises(RuntimeError, match="Guard daemon request failed"):
            client.create_connect_request(
                sync_url="https://hol.org/registry/api/v1",
                allowed_origin="https://hol.org",
            )

    def test_guard_surface_daemon_client_wraps_malformed_state_payloads(self, monkeypatch):
        client = daemon_client_module.GuardSurfaceDaemonClient("http://127.0.0.1:4781", "auth-token")

        class FakeResponse:
            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return b"not-json"

        monkeypatch.setattr(
            daemon_client_module.urllib.request,
            "urlopen",
            lambda request, timeout=5: FakeResponse(),
        )

        with pytest.raises(RuntimeError, match="Guard daemon request failed"):
            client.get_connect_state(request_id="req-123")

    def test_browser_connect_completion_clears_stale_cloud_state(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.set_sync_credentials("https://old.example/registry/api/v1", "old-token", "2026-04-10T00:00:00+00:00")
        store.set_sync_payload("policy", {"mode": "enforce"}, "2026-04-10T00:00:00+00:00")
        request = store.create_guard_connect_request(
            sync_url="https://new.example/registry/api/v1",
            allowed_origin="https://hol.org",
            now="2026-04-10T01:00:00+00:00",
            lifetime_seconds=600,
        )

        store.complete_guard_connect_request(
            request_id=str(request["request_id"]),
            pairing_secret=str(request["pairing_secret"]),
            token="new-token",
            now="2026-04-10T01:05:00+00:00",
        )

        assert store.get_sync_credentials() == {
            "sync_url": "https://new.example/registry/api/v1",
            "token": "new-token",
        }
        assert store.get_sync_payload("policy") is None

    def test_browser_connect_completion_rolls_back_if_credentials_persist_fails(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        request = store.create_guard_connect_request(
            sync_url="https://new.example/registry/api/v1",
            allowed_origin="https://hol.org",
            now="2026-04-10T01:00:00+00:00",
            lifetime_seconds=600,
        )

        def fail_credentials_write(connection, sync_url: str, token: str, now: str) -> None:
            raise RuntimeError("credentials unavailable")

        monkeypatch.setattr(store, "_set_sync_credentials_in_connection", fail_credentials_write)

        with pytest.raises(RuntimeError, match="credentials unavailable"):
            store.complete_guard_connect_request(
                request_id=str(request["request_id"]),
                pairing_secret=str(request["pairing_secret"]),
                token="new-token",
                now="2026-04-10T01:05:00+00:00",
            )

        request_after_failure = store.get_guard_connect_request(str(request["request_id"]))
        assert request_after_failure is not None
        assert request_after_failure["status"] == "pending"
        assert store.get_sync_credentials() is None

    def test_browser_connect_result_coerces_invalid_sync_counts(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        request = store.create_guard_connect_request(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-04-16T00:00:00+00:00",
            lifetime_seconds=600,
        )

        store.complete_guard_connect_request(
            request_id=str(request["request_id"]),
            pairing_secret=str(request["pairing_secret"]),
            token="session-token-123",
            now="2026-04-16T00:01:00+00:00",
        )

        result = store.record_guard_connect_result(
            request_id=str(request["request_id"]),
            status="connected",
            milestone="first_sync_succeeded",
            now="2026-04-16T00:02:00+00:00",
            sync_payload={
                "synced_at": "2026-04-16T00:02:00+00:00",
                "receipts_stored": "bad-value",
                "inventory_tracked": "still-bad",
            },
        )

        assert result["proof"]["receipts_stored"] == 0
        assert result["proof"]["inventory_items"] == 0

    def test_guard_queue_prefers_runtime_risk_metadata_from_evaluation(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        artifact = GuardArtifact(
            artifact_id="codex:runtime:project:danger_lab:dangerous_delete",
            name="danger_lab:dangerous_delete",
            harness="codex",
            artifact_type="tool_call",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="dangerous_delete",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        queued = queue_blocked_approvals(
            detection=detection,
            evaluation={
                "artifacts": [
                    {
                        "artifact_id": artifact.artifact_id,
                        "artifact_name": artifact.name,
                        "artifact_hash": "hash-runtime",
                        "artifact_type": artifact.artifact_type,
                        "source_scope": artifact.source_scope,
                        "config_path": artifact.config_path,
                        "changed_fields": ["runtime_tool_call"],
                        "policy_action": "require-reapproval",
                        "launch_target": "dangerous_delete .env",
                        "risk_summary": "Call arguments mention sensitive local files or secrets.",
                        "risk_signals": ["call arguments mention sensitive local files or secrets"],
                    }
                ]
            },
            store=store,
            approval_center_url="http://127.0.0.1:4455",
            now="2026-04-17T00:00:00+00:00",
        )

        assert queued[0]["risk_summary"] == "Call arguments mention sensitive local files or secrets."
        assert queued[0]["risk_signals"] == ["call arguments mention sensitive local files or secrets"]
        assert queued[0]["launch_summary"] == "Launches with `dangerous_delete .env`."

    def test_guard_store_keeps_request_id_when_duplicate_pending_request_is_requeued(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        original = GuardApprovalRequest(
            request_id="req-original",
            harness="codex",
            artifact_id="codex:project:workspace_skill",
            artifact_name="workspace_skill",
            artifact_hash="hash-1",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("args",),
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            review_command="hol-guard approvals approve req-original",
            approval_url="http://127.0.0.1:4455/approvals/req-original",
        )
        updated = GuardApprovalRequest(
            request_id="req-new",
            harness="codex",
            artifact_id=original.artifact_id,
            artifact_name="workspace_skill",
            artifact_hash="hash-2",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("command",),
            source_scope="project",
            config_path=original.config_path,
            review_command="hol-guard approvals approve req-new",
            approval_url="http://127.0.0.1:4455/approvals/req-new",
        )

        first_id = store.add_approval_request(original, "2026-04-11T00:00:00+00:00")
        second_id = store.add_approval_request(updated, "2026-04-11T00:01:00+00:00")
        pending = store.list_approval_requests()

        assert first_id == "req-original"
        assert second_id == "req-original"
        assert len(pending) == 1
        assert pending[0]["request_id"] == "req-original"
        assert pending[0]["artifact_hash"] == "hash-2"
        assert pending[0]["changed_fields"] == ["command"]

    def test_guard_broad_scope_resolution_clears_matching_pending_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for request_id, artifact_id in (
            ("req-a", "codex:project:first"),
            ("req-b", "codex:project:second"),
        ):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=request_id,
                    harness="codex",
                    artifact_id=artifact_id,
                    artifact_name=artifact_id.rsplit(":", maxsplit=1)[-1],
                    artifact_hash=f"hash-{request_id}",
                    policy_action="require-reapproval",
                    recommended_scope="harness",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                    review_command=f"hol-guard approvals approve {request_id}",
                    approval_url=f"http://127.0.0.1:4455/approvals/{request_id}",
                ),
                "2026-04-11T00:00:00+00:00",
            )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-a",
            action="allow",
            scope="harness",
            workspace=None,
            reason="trusted in harness",
            now="2026-04-11T00:02:00+00:00",
        )

        assert resolved["status"] == "resolved"
        assert store.get_approval_request("req-b")["status"] == "resolved"

    def test_guard_global_scope_resolution_clears_pending_requests_across_harnesses(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for request_id, harness in (("req-codex", "codex"), ("req-copilot", "copilot")):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=request_id,
                    harness=harness,
                    artifact_id=f"{harness}:project:item",
                    artifact_name=f"{harness}-item",
                    artifact_hash=f"hash-{request_id}",
                    policy_action="require-reapproval",
                    recommended_scope="global",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / harness / ".config" / "guard.toml"),
                    review_command=f"hol-guard approvals approve {request_id}",
                    approval_url=f"http://127.0.0.1:4455/approvals/{request_id}",
                ),
                "2026-04-11T00:00:00+00:00",
            )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-codex",
            action="allow",
            scope="global",
            workspace=None,
            reason="trusted globally",
            now="2026-04-11T00:02:00+00:00",
        )

        pending = store.list_approval_requests(status="pending", limit=None)
        decisions = store.list_policy_decisions()

        assert resolved["status"] == "resolved"
        assert pending == []
        assert decisions[0]["harness"] == "*"

    def test_guard_broad_scope_resolution_clears_more_than_default_pending_page(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        for index in range(520):
            store.add_approval_request(
                GuardApprovalRequest(
                    request_id=f"req-{index}",
                    harness="codex",
                    artifact_id=f"codex:project:item-{index}",
                    artifact_name=f"item-{index}",
                    artifact_hash=f"hash-{index}",
                    policy_action="require-reapproval",
                    recommended_scope="harness",
                    changed_fields=("args",),
                    source_scope="project",
                    config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                    review_command=f"hol-guard approvals approve req-{index}",
                    approval_url=f"http://127.0.0.1:4455/approvals/req-{index}",
                ),
                "2026-04-11T00:00:00+00:00",
            )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-0",
            action="allow",
            scope="harness",
            workspace=None,
            reason="trusted in harness",
            now="2026-04-11T00:02:00+00:00",
        )

        pending = store.list_approval_requests(status="pending", harness="codex", limit=None)

        assert resolved["status"] == "resolved"
        assert pending == []

    def test_guard_store_ignores_expired_policy_decisions(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:workspace_skill",
                artifact_hash="hash-123",
                expires_at="2026-04-11T01:00:00+00:00",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        before_expiry = store.resolve_policy(
            "codex",
            "codex:project:workspace_skill",
            "hash-123",
            now="2026-04-11T00:30:00+00:00",
        )
        after_expiry = store.resolve_policy(
            "codex",
            "codex:project:workspace_skill",
            "hash-123",
            now="2026-04-11T02:00:00+00:00",
        )
        decisions = store.list_policy_decisions()

        assert before_expiry == "allow"
        assert after_expiry is None
        assert decisions[0]["expires_at"] == "2026-04-11T01:00:00+00:00"
        assert decisions[0]["source"] == "local"

    def test_guard_store_ignores_expired_policy_decisions_without_explicit_now(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:workspace_skill",
                artifact_hash="hash-legacy",
                expires_at="2000-01-01T00:00:00+00:00",
            ),
            "1999-01-01T00:00:00+00:00",
        )

        resolved = store.resolve_policy("codex", "codex:project:workspace_skill", "hash-legacy")

        assert resolved is None

    def test_guard_store_does_not_match_hash_scoped_artifact_policy_without_current_hash(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:workspace_skill",
                artifact_hash="hash-locked",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        resolved = store.resolve_policy(
            "codex",
            "codex:project:workspace_skill",
            None,
            now="2026-04-11T00:30:00+00:00",
        )

        assert resolved is None

    def test_ensure_guard_daemon_uses_stable_default_port(self, tmp_path, monkeypatch):
        launched_commands: list[list[str]] = []
        guard_home = tmp_path / "guard-home"
        expected_port = daemon_manager_module._configured_port(guard_home)
        responses = iter([None, None, f"http://127.0.0.1:{expected_port}"])

        monkeypatch.delenv("GUARD_DAEMON_PORT", raising=False)
        monkeypatch.setattr(
            daemon_manager_module,
            "load_guard_daemon_url",
            lambda _guard_home: next(responses),
        )
        monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
        monkeypatch.setattr(
            daemon_manager_module.subprocess,
            "Popen",
            lambda command, **_kwargs: launched_commands.append(command) or SimpleNamespace(),
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url == f"http://127.0.0.1:{expected_port}"
        assert launched_commands
        assert launched_commands[0][-2:] == ["--port", str(expected_port)]

    def test_load_guard_daemon_url_rejects_stale_runtime_without_connect_state_support(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        class FakeResponse:
            status = 200

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "tables": [
                            "approval_requests",
                            "guard_connect_requests",
                            "sync_state",
                        ],
                    }
                ).encode("utf-8")

        monkeypatch.setattr(
            daemon_manager_module,
            "_load_state",
            lambda _guard_home: {
                "port": 5530,
                "auth_token": "token-123",
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            },
        )
        monkeypatch.setattr(
            daemon_manager_module.urllib.request,
            "urlopen",
            lambda request, timeout=1: FakeResponse(),
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) is None

    def test_load_guard_daemon_url_accepts_healthy_daemon_for_matching_source_root(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        class FakeResponse:
            status = 200

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "tables": ["guard_connect_states"],
                        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                    }
                ).encode("utf-8")

        monkeypatch.setattr(
            daemon_manager_module,
            "_load_state",
            lambda _guard_home: {
                "port": 5530,
                "auth_token": "token-123",
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            },
        )
        monkeypatch.setattr(
            daemon_manager_module.urllib.request,
            "urlopen",
            lambda request, timeout=1: FakeResponse(),
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) == "http://127.0.0.1:5530"

    def test_load_guard_daemon_url_rejects_incompatible_daemon_state(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        class FakeResponse:
            status = 200

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "tables": ["guard_connect_states"],
                        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION - 1,
                    }
                ).encode("utf-8")

        monkeypatch.setattr(
            daemon_manager_module,
            "_load_state",
            lambda _guard_home: {
                "port": 5530,
                "auth_token": "token-123",
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION - 1,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            },
        )
        monkeypatch.setattr(
            daemon_manager_module.urllib.request,
            "urlopen",
            lambda request, timeout=1: FakeResponse(),
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) is None

    def test_load_guard_daemon_url_rejects_daemon_from_different_source_root(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        monkeypatch.setattr(
            daemon_manager_module,
            "_load_state",
            lambda _guard_home: {
                "port": 5530,
                "auth_token": "token-123",
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": "/tmp/older-source-root",
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            },
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) is None

    def test_guard_daemon_server_reuses_existing_auth_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        token_path = store.guard_home / "daemon-auth-token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("persisted-token", encoding="utf-8")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)

        try:
            daemon.start()
            assert daemon._server.auth_token == "persisted-token"
            assert token_path.read_text(encoding="utf-8").strip() == "persisted-token"
        finally:
            daemon.stop()

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
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/v1/requests", timeout=5) as response:
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
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/v1/runtime", timeout=5) as response:
                snapshot_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert snapshot_payload["approval_center_url"] == f"http://127.0.0.1:{daemon.port}"
        assert snapshot_payload["pending_count"] == 1
        assert snapshot_payload["items"][0]["request_id"] == "req-runtime"
        assert snapshot_payload["runtime_state"]["daemon_port"] == daemon.port
        assert snapshot_payload["runtime_state"]["approval_center_url"] == f"http://127.0.0.1:{daemon.port}"
        assert snapshot_payload["runtime_state"]["session_id"]

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
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/v1/runtime", timeout=5) as response:
                snapshot_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert snapshot_payload["pending_count"] == 205
        assert len(snapshot_payload["items"]) == 200

    def test_guard_daemon_updates_runtime_heartbeat_while_serving_requests(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        heartbeat_values = [
            "2026-04-11T00:00:00+00:00",
            "2026-04-11T00:00:00+00:00",
            "2026-04-11T00:05:00+00:00",
        ]

        def next_heartbeat() -> str:
            if len(heartbeat_values) > 1:
                return heartbeat_values.pop(0)
            return heartbeat_values[0]

        monkeypatch.setattr(daemon_server_module, "_now", next_heartbeat)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=5):
                pass
            runtime_state = store.get_runtime_state()
        finally:
            daemon.stop()

        assert runtime_state is not None
        assert runtime_state["last_heartbeat_at"] == "2026-04-11T00:05:00+00:00"

    def test_guard_store_clears_runtime_state_only_for_matching_session(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_runtime_state(
            session_id="session-active",
            daemon_host="127.0.0.1",
            daemon_port=4455,
            started_at="2026-04-11T00:00:00+00:00",
            last_heartbeat_at="2026-04-11T00:00:00+00:00",
        )

        store.clear_runtime_state(session_id="session-stale")
        active_state = store.get_runtime_state()

        assert active_state is not None
        assert active_state["session_id"] == "session-active"

        store.clear_runtime_state(session_id="session-active")

        assert store.get_runtime_state() is None

    def test_guard_store_touches_runtime_state_only_for_matching_session(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_runtime_state(
            session_id="session-active",
            daemon_host="127.0.0.1",
            daemon_port=4455,
            started_at="2026-04-11T00:00:00+00:00",
            last_heartbeat_at="2026-04-11T00:00:00+00:00",
        )

        store.touch_runtime_state(
            session_id="session-stale",
            last_heartbeat_at="2026-04-11T01:00:00+00:00",
        )
        unchanged_state = store.get_runtime_state()

        assert unchanged_state is not None
        assert unchanged_state["last_heartbeat_at"] == "2026-04-11T00:00:00+00:00"

        store.touch_runtime_state(
            session_id="session-active",
            last_heartbeat_at="2026-04-11T01:00:00+00:00",
        )
        updated_state = store.get_runtime_state()

        assert updated_state is not None
        assert updated_state["last_heartbeat_at"] == "2026-04-11T01:00:00+00:00"

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
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/v1/requests", timeout=5) as response:
                requests_payload = json.loads(response.read().decode("utf-8"))
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/v1/requests/req-v1", timeout=5) as response:
                request_payload = json.loads(response.read().decode("utf-8"))
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/v1/receipts/{built_receipt.receipt_id}", timeout=5
            ) as response:
                receipt_payload = json.loads(response.read().decode("utf-8"))
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/v1/receipts/latest?harness=codex&artifact_id="
                f"{urllib.parse.quote(artifact.artifact_id, safe='')}",
                timeout=5,
            ) as response:
                latest_receipt_payload = json.loads(response.read().decode("utf-8"))
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/v1/artifacts/{artifact.artifact_id}/diff?harness=codex", timeout=5
            ) as response:
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
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/v1/policy?harness=codex", timeout=5
            ) as response:
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
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/v1/artifacts/codex%3Aproject%3Atools%2Fwith%2Fslash/diff?harness=codex",
                timeout=5,
            ) as response:
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

    def test_guard_daemon_rejects_missing_decision_fields(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-400",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-400",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-400",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/approvals/req-400/decision",
                data=json.dumps({"action": "allow"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for missing scope")
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "missing_required_fields"

    def test_guard_daemon_approve_route_requires_workspace_for_workspace_scope(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-workspace-http",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-400",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-workspace-http",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-workspace-http/approve",
                data=json.dumps({"scope": "workspace"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for missing workspace path")
        finally:
            daemon.stop()

        assert status == 400
        assert "requires --workspace" in payload["error"]

    def test_guard_daemon_approve_route_requires_auth_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-auth-http",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-auth",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-auth-http",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-auth-http/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
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

    def test_guard_daemon_event_stream_rejects_non_ascii_query_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/events/stream?token={urllib.parse.quote('ñ')}",
                method="GET",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for malformed query token")
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"

    def test_guard_daemon_ignores_invalid_json_body(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/approvals/missing/decision",
                data=b"{not-json",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for invalid JSON body")
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "invalid_request_body"

    def test_guard_daemon_escapes_html_values_in_approval_center(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id='req-escape" onclick="alert(1)',
                harness="codex<script>",
                artifact_id="codex:project:workspace_skill",
                artifact_name="<img src=x onerror=alert(1)>",
                artifact_hash="hash-escape",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("<script>",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-escape",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/", timeout=5) as response:
                body = response.read().decode("utf-8")
        finally:
            daemon.stop()

        assert "<img src=x onerror=alert(1)>" not in body
        assert "codex<script>" not in body
        assert "guard-dashboard-root" in body
        assert "Local approval center" in body
        assert "Hashgraph Online" in body

    def test_guard_daemon_rejects_cross_origin_post_requests(self, tmp_path):
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
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": "https://evil.example",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for disallowed origin")
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"

    def test_guard_daemon_rejects_cross_origin_options_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/missing/approve",
                headers={"Origin": "https://evil.example"},
                method="OPTIONS",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                status = error.code
            else:
                raise AssertionError("expected HTTPError for disallowed preflight origin")
        finally:
            daemon.stop()

        assert status == 403

    def test_guard_daemon_allows_local_options_requests_with_guard_headers(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/missing/approve",
                headers={"Origin": f"http://127.0.0.1:{daemon.port}"},
                method="OPTIONS",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                allow_headers = response.headers.get("Access-Control-Allow-Headers")
                status = response.status
        finally:
            daemon.stop()

        assert status == 200
        assert allow_headers == "Content-Type, X-Guard-Token"

    def test_guard_daemon_includes_cors_headers_on_unauthorized_local_post(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/missing/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://127.0.0.1:{daemon.port}",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                status = error.code
                payload = json.loads(error.read().decode("utf-8"))
                allow_origin = error.headers.get("Access-Control-Allow-Origin")
            else:
                raise AssertionError("expected HTTPError for missing auth token")
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"
        assert allow_origin == f"http://127.0.0.1:{daemon.port}"

    def test_guard_daemon_rejects_spoofed_localhost_origin_post_requests(self, tmp_path):
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
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": "http://127.0.0.1.evil.example",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for spoofed localhost origin")
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"

    def test_guard_daemon_rejects_malformed_origin_post_requests(self, tmp_path):
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
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": "http://localhost:abc",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for malformed origin")
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"

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

    def test_guard_run_headless_enqueues_approval_request(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)
        approvals = store.list_approval_requests()

        assert rc == 1
        assert output["blocked"] is True
        assert output["approval_center_url"].startswith("http://127.0.0.1:")
        assert approvals[0]["harness"] == "codex"
        assert approvals[0]["status"] == "pending"

    def test_guard_approvals_cli_lists_and_resolves_requests(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-789",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-789",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-789",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        list_rc = main(["guard", "approvals", "--home", str(home_dir), "--json"])
        list_output = json.loads(capsys.readouterr().out)
        approve_rc = main(
            [
                "guard",
                "approvals",
                "approve",
                "req-789",
                "--home",
                str(home_dir),
                "--scope",
                "artifact",
                "--reason",
                "approved",
                "--json",
            ]
        )
        approve_output = json.loads(capsys.readouterr().out)

        assert list_rc == 0
        assert list_output["items"][0]["request_id"] == "req-789"
        assert approve_rc == 0
        assert approve_output["resolved"] is True
        assert store.resolve_policy("codex", "codex:project:workspace_skill", "hash-789") == "allow"

    def test_guard_policies_cli_clears_local_decisions_for_harness(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_hash="hash-npmrc",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="allow",
                reason="keep codex decisions",
                source="manual",
            ),
            "2026-04-23T00:00:00+00:00",
        )

        rc = main(["guard", "policies", "clear", "--home", str(home_dir), "--harness", "claude-code", "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["cleared"] == 1
        assert store.list_policy_decisions("claude-code") == []
        assert len(store.list_policy_decisions("codex")) == 1

    def test_guard_approvals_clear_history_resets_saved_decisions(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_hash="hash-env",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:workspace_skill",
                artifact_hash="hash-workspace",
                reason="keep codex allow",
                source="manual",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-claude-resolved",
                harness="claude-code",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_name=".env",
                artifact_hash="hash-env",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("first_seen",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".claude" / "settings.local.json"),
                review_command="hol-guard approvals approve req-claude-resolved",
                approval_url="http://127.0.0.1/pending/req-claude-resolved",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.resolve_approval_request(
            "req-claude-resolved",
            resolution_action="block",
            resolution_scope="artifact",
            reason="intentional block",
            resolved_at="2026-04-23T00:01:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-claude-pending",
                harness="claude-code",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_name=".npmrc",
                artifact_hash="hash-npmrc",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("first_seen",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".claude" / "settings.local.json"),
                review_command="hol-guard approvals approve req-claude-pending",
                approval_url="http://127.0.0.1/pending/req-claude-pending",
            ),
            "2026-04-23T00:02:00+00:00",
        )

        rc = main(
            [
                "guard",
                "approvals",
                "clear-history",
                "--home",
                str(home_dir),
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["history_cleared"] is True
        assert output["cleared_policies"] == 1
        assert output["cleared_resolved_requests"] == 1
        assert store.list_policy_decisions("claude-code") == []
        assert len(store.list_policy_decisions("codex")) == 1
        assert len(store.list_approval_requests(status="resolved", harness="claude-code", limit=None)) == 0
        assert len(store.list_approval_requests(status="pending", harness="claude-code", limit=None)) == 1

    def test_guard_policies_clear_renders_non_json_result(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_hash="hash-npmrc",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )

        rc = main(["guard", "policies", "clear", "--home", str(home_dir), "--harness", "claude-code"])
        output = capsys.readouterr().out

        assert rc == 0
        assert "Guard policy clear" in output
        assert "cleared 1 decision" in output
        assert store.list_policy_decisions("claude-code") == []

    def test_guard_policies_clear_renders_non_json_validation_error(self, tmp_path, capsys):
        rc = main(["guard", "policies", "clear", "--home", str(tmp_path / "home")])
        output = capsys.readouterr().out

        assert rc == 2
        assert "Guard policy clear" in output
        assert "Choose --harness <name> or --all" in output

    def test_guard_policies_clear_rejects_all_with_harness(self, tmp_path, capsys):
        rc = main(
            [
                "guard",
                "policies",
                "clear",
                "--home",
                str(tmp_path / "home"),
                "--all",
                "--harness",
                "claude-code",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["cleared"] == 0
        assert "Choose either --all or --harness <name>" in output["error"]

    def test_guard_approvals_clear_history_requires_scope_selector(self, tmp_path, capsys):
        rc = main(["guard", "approvals", "clear-history", "--home", str(tmp_path / "home"), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["history_cleared"] is False
        assert output["cleared_policies"] == 0
        assert output["cleared_resolved_requests"] == 0
        assert "Choose --harness <name> or --all" in output["error"]

    def test_guard_approvals_clear_history_with_source_only_clears_matching_policies(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="block",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_hash="hash-env",
                reason="blocked during local test",
                source="claude-ask-user-question",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(
                harness="claude-code",
                scope="artifact",
                action="allow",
                artifact_id="claude-code:runtime:file-read:.npmrc",
                artifact_hash="hash-npmrc",
                reason="keep manual allow",
                source="manual",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-claude-resolved-source",
                harness="claude-code",
                artifact_id="claude-code:runtime:file-read:.env",
                artifact_name=".env",
                artifact_hash="hash-env",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("first_seen",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".claude" / "settings.local.json"),
                review_command="hol-guard approvals approve req-claude-resolved-source",
                approval_url="http://127.0.0.1/pending/req-claude-resolved-source",
            ),
            "2026-04-23T00:00:00+00:00",
        )
        store.resolve_approval_request(
            "req-claude-resolved-source",
            resolution_action="block",
            resolution_scope="artifact",
            reason="intentional block",
            resolved_at="2026-04-23T00:01:00+00:00",
        )

        rc = main(
            [
                "guard",
                "approvals",
                "clear-history",
                "--home",
                str(home_dir),
                "--harness",
                "claude-code",
                "--source",
                "claude-ask-user-question",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["history_cleared"] is True
        assert output["source"] == "claude-ask-user-question"
        assert output["cleared_policies"] == 1
        assert output["cleared_resolved_requests"] == 0
        remaining = store.list_policy_decisions("claude-code")
        assert len(remaining) == 1
        assert remaining[0]["source"] == "manual"
        assert len(store.list_approval_requests(status="resolved", harness="claude-code", limit=None)) == 1

    def test_guard_bridge_resolves_requests_against_guard_daemon_api(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        bridge = GuardBridge(
            config=BridgeConfig(guard_url="http://127.0.0.1:4455", dry_run=False),
            store=store,
        )
        token_path = store.guard_home / "daemon-auth-token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("bridge-token", encoding="utf-8")
        post_calls: list[tuple[str, dict[str, object], dict[str, str] | None]] = []

        def fake_post(url: str, json: dict[str, object], timeout: int, headers: dict[str, str] | None = None):
            post_calls.append((url, json, headers))
            assert timeout == 30
            return SimpleNamespace(status_code=200, json=lambda: {"resolved": True})

        monkeypatch.setattr(guard_bridge_module.requests, "post", fake_post)

        resolved = bridge._execute_resolution("approve", "req-bridge")

        assert resolved is True
        assert post_calls == [
            (
                "http://127.0.0.1:4455/v1/requests/req-bridge/approve",
                {
                    "scope": "artifact",
                    "reason": "resolved from Guard Bridge",
                },
                {"X-Guard-Token": "bridge-token"},
            )
        ]

    def test_guard_approvals_cli_rejects_workspace_scope_without_workspace(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-workspace",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-workspace",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-workspace",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        try:
            main(
                [
                    "guard",
                    "approvals",
                    "approve",
                    "req-workspace",
                    "--home",
                    str(home_dir),
                    "--scope",
                    "workspace",
                    "--json",
                ]
            )
        except SystemExit as error:
            rc = error.code
        else:
            raise AssertionError("expected argparse failure for missing workspace scope target")

        captured = capsys.readouterr()

        assert rc == 2
        assert "requires --workspace" in captured.err
        assert store.get_approval_request("req-workspace")["status"] == "pending"

    def test_guard_workspace_resolution_does_not_match_sibling_workspace(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        primary_workspace = tmp_path / "workspace"
        sibling_workspace = tmp_path / "workspace-copy"
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-primary",
                harness="codex",
                artifact_id="codex:project:primary",
                artifact_name="primary",
                artifact_hash="hash-primary",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(primary_workspace / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-primary",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-sibling",
                harness="codex",
                artifact_id="codex:project:sibling",
                artifact_name="sibling",
                artifact_hash="hash-sibling",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(sibling_workspace / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-sibling",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )

        resolved = apply_approval_resolution(
            store=store,
            request_id="req-primary",
            action="allow",
            scope="workspace",
            workspace=str(primary_workspace),
            reason="trusted in workspace",
            now="2026-04-11T00:02:00+00:00",
        )

        assert resolved["status"] == "resolved"
        assert store.get_approval_request("req-primary")["status"] == "resolved"
        assert store.get_approval_request("req-sibling")["status"] == "pending"

    def test_guard_queue_blocked_approvals_creates_requests_for_changed_artifacts(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home)
        baseline = GuardArtifact(
            artifact_id="codex:project:workspace_skill",
            name="workspace_skill",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("server.js",),
            transport="stdio",
        )
        baseline_hash = artifact_hash(baseline)
        store.save_snapshot(
            "codex",
            baseline.artifact_id,
            {**baseline.to_dict(), "artifact_hash": baseline_hash},
            baseline_hash,
            "2026-04-10T00:00:00+00:00",
        )
        changed = GuardArtifact(
            artifact_id=baseline.artifact_id,
            name=baseline.name,
            harness=baseline.harness,
            artifact_type=baseline.artifact_type,
            source_scope=baseline.source_scope,
            config_path=baseline.config_path,
            command="node",
            args=("server.js", "--changed"),
            transport="stdio",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(baseline.config_path,),
            artifacts=(changed,),
        )
        config = GuardConfig(guard_home=guard_home, workspace=None)

        evaluation = evaluate_detection(detection, store, config, persist=True)
        approvals = queue_blocked_approvals(
            detection=detection,
            evaluation=evaluation,
            store=store,
            approval_center_url="http://127.0.0.1:4455",
        )

        assert evaluation["blocked"] is True
        assert approvals[0]["artifact_id"] == "codex:project:workspace_skill"
        assert "args" in approvals[0]["changed_fields"]
