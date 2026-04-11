"""Behavior tests for the Guard approval queue and approval center."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash, evaluate_detection
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
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
        assert resolved is not None
        assert resolved["status"] == "resolved"
        assert resolved["resolution_action"] == "allow"
        assert resolved["resolution_scope"] == "artifact"

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
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/approvals", timeout=5) as response:
                approvals_payload = json.loads(response.read().decode("utf-8"))
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/approvals/req-456/decision",
                data=json.dumps({"action": "allow", "scope": "artifact", "reason": "approved"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                decision_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert approvals_payload["items"][0]["request_id"] == "req-456"
        assert decision_payload["resolved"] is True
        assert store.get_approval_request("req-456")["status"] == "resolved"

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
                headers={"Content-Type": "application/json"},
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

    def test_guard_daemon_ignores_invalid_json_body(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/approvals/missing/decision",
                data=b"{not-json",
                headers={"Content-Type": "application/json"},
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
        assert payload["error"] == "missing_required_fields"

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
        assert "<script>" not in body
        assert "&lt;img src=x onerror=alert(1)&gt;" in body
        assert "codex&lt;script&gt;" in body

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
        assert store.resolve_policy("codex", "codex:project:workspace_skill", None) == "allow"

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
