"""Product-flow behavior tests for Guard onboarding and local launch setup."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.product import build_guard_status_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import detect_all
from codex_plugin_scanner.guard.consumer.service import artifact_hash
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_guard_fixture(home_dir: Path, workspace_dir: Path) -> None:
    _write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "node"
args = ["global-tool.js"]
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
    _write_json(
        workspace_dir / ".mcp.json",
        {
            "mcpServers": {
                "workspace-tools": {"command": "python", "args": ["-m", "http.server", "9100"]},
            }
        },
    )


class TestGuardProductFlow:
    def test_plugin_scanner_help_stays_scanner_only(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["plugin-scanner"])

        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])

        output = capsys.readouterr().out

        assert excinfo.value.code == 0
        assert "Scan plugin ecosystems for CI and publish readiness." in output
        assert "{scan,lint,verify,submit,doctor}" in output
        assert "guard" not in output
        assert "protect" not in output
        assert "preflight" not in output
        assert "approvals" not in output
        assert "receipts" not in output
        assert "abom" not in output
        assert "events" not in output

    def test_python_module_entry_keeps_combined_surface(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cli.py"])

        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])

        output = capsys.readouterr().out

        assert excinfo.value.code == 0
        assert "Run HOL Guard locally or scan plugin ecosystems for CI and publish readiness." in output
        assert "{scan,lint,verify,submit,doctor,guard}" in output

    def test_guard_start_json_guides_first_run(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        codex_summary = next(item for item in output["harnesses"] if item["harness"] == "codex")

        assert rc == 0
        assert output["recommended_harness"] == "codex"
        assert output["sync_configured"] is False
        assert output["cloud_state"] == "local_only"
        assert output["receipt_count"] == 0
        assert codex_summary["managed"] is False
        assert codex_summary["next_action"] == "install"
        assert codex_summary["approval_flow"]["prompt_channel"] == "native"
        assert codex_summary["approval_flow"]["auto_open_browser"] is False
        assert "native Codex PreToolUse hooks" in codex_summary["approval_flow"]["summary"]
        assert "authoritative complete-command boundary" in codex_summary["approval_flow"]["summary"]
        assert "same-chat approvals" in codex_summary["approval_flow"]["summary"]
        assert output["next_steps"][0]["command"] == "hol-guard install codex"
        assert output["next_steps"][1]["command"] == "hol-guard run codex --dry-run"

    def test_guard_status_review_count_does_not_resolve_policy(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)
        context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)
        config = GuardConfig(guard_home=guard_home, workspace=workspace_dir)
        store = GuardStore(guard_home)
        detections = detect_all(context)
        codex_detection = next(item for item in detections if item.harness == "codex")

        assert codex_detection.artifacts

        for artifact in codex_detection.artifacts:
            store.save_snapshot(
                codex_detection.harness,
                artifact.artifact_id,
                artifact.to_dict(),
                artifact_hash(artifact),
                "2026-06-04T12:00:00+00:00",
            )

        _write_text(
            workspace_dir / ".codex" / "config.toml",
            """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js", "--changed"]
""".strip()
            + "\n",
        )
        monkeypatch.setattr(
            store,
            "resolve_policy",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("status should not resolve policy")),
        )

        payload = build_guard_status_payload(context, store, config)
        codex_summary = next(item for item in payload["harnesses"] if item["harness"] == "codex")

        assert codex_summary["review_count"] >= 1

    def test_guard_bootstrap_stays_local_when_cloud_is_unreachable(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.cli.bootstrap.ensure_guard_daemon",
            lambda _guard_home: "http://127.0.0.1:5474",
        )

        def fail_cloud_call(*_args, **_kwargs):
            raise AssertionError("offline bootstrap must not call Guard Cloud")

        monkeypatch.setattr("codex_plugin_scanner.guard.cli.commands.sync_receipts", fail_cloud_call)
        monkeypatch.setattr("codex_plugin_scanner.guard.cli.commands.sync_runtime_session", fail_cloud_call)
        monkeypatch.setattr("codex_plugin_scanner.guard.cli.commands.webbrowser.open", fail_cloud_call)

        rc = main(
            [
                "guard",
                "bootstrap",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--skip-install",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["sync_configured"] is False
        assert output["cloud_state"] == "local_only"
        assert output["approval_center_url"] == "http://127.0.0.1:5474"
        assert output["bootstrap_install"]["reason"] == "skipped_by_flag"
        assert GuardStore(guard_home).get_cloud_sync_profile() is None

    def test_guard_start_recommends_copilot_when_it_is_the_only_detected_harness(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            home_dir / ".copilot" / "mcp-config.json",
            {"servers": {"global-tool": {"command": "npx", "args": ["server.js"]}}},
        )
        monkeypatch.setattr("shutil.which", lambda _command: None)

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        copilot_summary = next(item for item in output["harnesses"] if item["harness"] == "copilot")

        assert rc == 0
        assert output["recommended_harness"] == "copilot"
        assert copilot_summary["install_command"] == "hol-guard install copilot"
        assert output["next_steps"][1]["command"] == "hol-guard run copilot --dry-run"

    def test_guard_start_surfaces_opencode_native_approval_path(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "permission": {"bash": "allow"},
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-lab.py"],
                    }
                },
            },
        )

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        opencode_summary = next(item for item in output["harnesses"] if item["harness"] == "opencode")

        assert rc == 0
        assert opencode_summary["approval_flow"]["prompt_channel"] == "native"
        assert opencode_summary["approval_flow"]["auto_open_browser"] is False
        assert "native ask" in opencode_summary["approval_flow"]["summary"]

    def test_guard_start_prefers_opencode_over_browser_only_harnesses(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _write_json(
            workspace_dir / "opencode.json",
            {
                "mcp": {
                    "danger_lab": {
                        "type": "local",
                        "command": ["python3", "danger-lab.py"],
                    }
                }
            },
        )
        _write_json(
            workspace_dir / ".gemini" / "settings.json",
            {
                "mcpServers": {
                    "browser-only-lab": {
                        "command": "python3",
                        "args": ["browser-only.py"],
                    }
                }
            },
        )

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recommended_harness"] == "opencode"

    def test_guard_status_json_surfaces_local_only_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "status",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["cloud_state"] == "local_only"
        assert output["sync_configured"] is False
        assert output["connect_url"] == "https://hol.org/guard/connect"
        assert output["dashboard_url"] == "https://hol.org/guard"
        assert output["inbox_url"] == "https://hol.org/guard/inbox"
        assert output["fleet_url"] == "https://hol.org/guard/protect"
        assert output["connect_command"] == "hol-guard connect"
        assert output["connect_status_command"] == "hol-guard connect status"
        assert output["connect_recovery_command"] == "hol-guard connect"

    def test_guard_status_json_uses_oauth_profile_for_cloud_state(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(guard_home)
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now="2026-06-04T18:30:00+00:00",
        )

        rc = main(
            [
                "guard",
                "status",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["sync_configured"] is True
        assert output["cloud_state"] == "paired_waiting"
        assert output["sync_url"] == "https://hol.org/api/guard/receipts/sync"
        assert output["connect_url"] == "https://hol.org/guard/connect"
        assert output["dashboard_url"] == "https://hol.org/guard"
        assert output["inbox_url"] == "https://hol.org/guard/inbox"
        assert output["fleet_url"] == "https://hol.org/guard/protect"
        assert "retry automatically" in output["cloud_state_detail"]
        assert "finish the pairing loop" not in output["cloud_state_detail"]

    def test_guard_status_json_surfaces_first_sync_repair_over_generic_pending_copy(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(guard_home)
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now="2026-06-04T18:30:00+00:00",
        )
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-04T18:30:00+00:00",
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now="2026-06-04T18:31:00+00:00",
            reason="Guard authorization expired.",
        )

        rc = main(
            [
                "guard",
                "status",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["cloud_state"] == "paired_waiting"
        assert "needs repair before the first shared proof can land" in output["cloud_state_detail"]
        assert "retry automatically" not in output["cloud_state_detail"]

    def test_guard_help_groups_commands_by_everyday_cloud_and_advanced_work(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["hol-guard"])

        with pytest.raises(SystemExit) as excinfo:
            main(["guard", "--help"])

        output = capsys.readouterr().out

        assert excinfo.value.code == 0
        assert "HOL Guard AI Antivirus command center:" in output
        assert "Team and cloud coordination:" in output
        assert "Advanced and diagnostics:" in output
        assert "start        First-run protection setup for one local AI harness" in output
        assert "connect      Pair this machine to Guard Cloud" in output
        assert "doctor       Run local diagnostics" in output
        assert "Use status for Home posture" in output

    def test_hol_guard_top_level_doctor_help_shows_guard_doctor(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["hol-guard"])

        with pytest.raises(SystemExit) as excinfo:
            main(["doctor", "--help"])

        output = capsys.readouterr().out

        assert excinfo.value.code == 0
        assert "--repair, --fix" in output
        assert "Repair common local Guard issues" in output
        assert "--component" not in output

    def test_guard_status_softens_refresh_race_copy_when_local_protection_stays_active(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        guard_home = home_dir / ".hol-guard"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(guard_home)
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            supply_chain_entitlement_expires_at="2026-07-04T18:30:00+00:00",
            supply_chain_firewall=True,
            supply_chain_plan_id="team",
            workspace_id="workspace-123",
            now="2026-06-04T18:30:00+00:00",
        )
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-04T18:30:00+00:00",
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now="2026-06-04T18:31:00+00:00",
            reason="Guard authorization expired. The grant is missing, expired, or already consumed.",
        )

        rc = main(
            [
                "guard",
                "status",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["cloud_state"] == "paired_waiting"
        assert "stays locally protected" in output["cloud_state_detail"]
        assert "needs repair before the first shared proof can land" not in output["cloud_state_detail"]

    def test_guard_status_reports_post_sync_reauth_as_local_only(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        guard_home = home_dir / ".hol-guard"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True)
        store = GuardStore(guard_home)
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n",
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now="2026-06-04T18:30:00+00:00",
        )
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-04T18:30:00+00:00",
            request_id="connect-post-sync-401",
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now="2026-06-04T19:00:00+00:00",
            reason=(
                "Guard Cloud sign-in on this device is no longer valid. "
                "Run `hol-guard disconnect` then `hol-guard connect` to sign in again."
            ),
        )
        store.set_sync_payload(
            "sync_summary",
            {
                "synced_at": "2026-06-04T18:45:00+00:00",
                "receipts_stored": 11,
                "inventory": 0,
                "inventory_tracked": 261,
            },
            "2026-06-04T18:45:00+00:00",
        )

        rc = main(
            [
                "guard",
                "status",
                "--home",
                str(home_dir),
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["cloud_state"] == "local_only"
        assert "needs repair before shared proof can resume" in output["cloud_state_detail"]
        assert output["latest_connect_state"]["status"] == "retry_required"

    def test_guard_start_human_output_highlights_guard_loop(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
            ]
        )
        output = capsys.readouterr().out

        assert rc == 0
        assert "Install Guard for codex" in output
        assert "Run Guard before launch" in output
        assert "Optional cloud connect" in output

    def test_hol_guard_direct_entrypoint_runs_without_nested_guard_command(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(sys, "argv", ["hol-guard"])

        rc = main(
            [
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recommended_harness"] == "codex"
        assert output["next_steps"][0]["command"] == "hol-guard install codex"

    def test_hol_guard_windows_entrypoint_runs_without_nested_guard_command(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(sys, "argv", ["hol-guard.exe"])

        rc = main(
            [
                "start",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recommended_harness"] == "codex"
        assert output["next_steps"][0]["command"] == "hol-guard install codex"

    def test_guard_install_creates_wrapper_shim(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        rc = main(
            [
                "guard",
                "install",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        shim_path = Path(output["managed_install"]["manifest"]["shim_path"])

        assert rc == 0
        assert output["managed_install"]["active"] is True
        assert shim_path.exists() is True
        assert os.access(shim_path, os.X_OK) is True
        assert "'--guard-home'" in shim_path.read_text(encoding="utf-8")
        assert f"'{home_dir}'" in shim_path.read_text(encoding="utf-8")
        assert "'guard'" in shim_path.read_text(encoding="utf-8")
        assert "'run'" in shim_path.read_text(encoding="utf-8")
        assert "'codex'" in shim_path.read_text(encoding="utf-8")

    def test_guard_install_without_home_override_keeps_real_home_detection(self, tmp_path, capsys, monkeypatch):
        real_home = tmp_path / "real-home"
        workspace_dir = tmp_path / "workspace"
        guard_home = tmp_path / "guard-home"
        _build_guard_fixture(real_home, workspace_dir)
        monkeypatch.setattr(Path, "home", lambda: real_home)

        rc = main(
            [
                "guard",
                "install",
                "codex",
                "--guard-home",
                str(guard_home),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        shim_path = Path(output["managed_install"]["manifest"]["shim_path"])
        shim_text = shim_path.read_text(encoding="utf-8")

        assert rc == 0
        assert "'--guard-home'" in shim_text
        assert f"'{guard_home}'" in shim_text
        assert "'--home'" not in shim_text

    def test_guard_status_reports_managed_launch_and_review_queue(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        daemon = GuardDaemonServer(GuardStore(home_dir), host="127.0.0.1", port=0)

        install_rc = main(
            [
                "guard",
                "install",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        first_run_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "require-reapproval"\n')
        _write_text(
            workspace_dir / ".codex" / "config.toml",
            """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js", "--changed"]
""".strip()
            + "\n",
        )

        daemon.start()
        try:
            status_rc = main(
                [
                    "guard",
                    "status",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--json",
                ]
            )
            status_output = json.loads(capsys.readouterr().out)
        finally:
            daemon.stop()
        codex_summary = next(item for item in status_output["harnesses"] if item["harness"] == "codex")

        assert install_rc == 0
        assert first_run_rc == 0
        assert status_rc == 0
        assert status_output["managed_harnesses"] == 1
        assert status_output["receipt_count"] >= 1
        assert status_output["runtime_status"] == "active"
        assert status_output["runtime_state"]["daemon_port"] == daemon.port
        assert status_output["approval_center_url"] == f"http://127.0.0.1:{daemon.port}"
        assert codex_summary["managed"] is True
        assert codex_summary["review_count"] >= 1
        assert codex_summary["next_action"] == "review"

    def test_guard_shim_forwards_dash_prefixed_args(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        fake_bin = tmp_path / "fake-bin"
        fake_codex = fake_bin / "codex"
        args_file = tmp_path / "codex-args.txt"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _write_text(
            fake_codex,
            "\n".join(
                (
                    "#!/bin/sh",
                    f'printf "%s\\n" "$@" > "{args_file}"',
                    "exit 0",
                    "",
                )
            ),
        )
        fake_bin.mkdir(parents=True, exist_ok=True)
        fake_codex.chmod(fake_codex.stat().st_mode | 0o755)

        main(
            [
                "guard",
                "install",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        shim_path = Path(install_output["managed_install"]["manifest"]["shim_path"])
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"

        try:
            result = subprocess.run(
                [str(shim_path), "--help"],
                capture_output=True,
                text=True,
                env=env,
                check=False,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            pytest.fail(
                "guard-codex --help timed out after 15 seconds\n"
                f"stdout:\n{exc.stdout or ''}\n"
                f"stderr:\n{exc.stderr or ''}"
            )

        assert result.returncode == 0, (
            f"guard-codex --help exited with {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert args_file.read_text(encoding="utf-8").strip() == "--help"

    def test_guard_shim_keeps_pythonpath_for_source_checkout_launches(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        fake_bin = tmp_path / "fake-bin"
        fake_codex = fake_bin / "codex"
        args_file = tmp_path / "codex-args.txt"
        env_file = tmp_path / "codex-env.txt"
        source_root = Path(__file__).resolve().parents[1] / "src"
        runtime_pythonpath = tmp_path / "runtime-modules"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _write_text(
            fake_codex,
            "\n".join(
                (
                    "#!/bin/sh",
                    f'printf "%s\\n" "$@" > "{args_file}"',
                    f'printf "%s" "$PYTHONPATH" > "{env_file}"',
                    "exit 0",
                    "",
                )
            ),
        )
        fake_bin.mkdir(parents=True, exist_ok=True)
        fake_codex.chmod(fake_codex.stat().st_mode | 0o755)
        monkeypatch.chdir(Path(__file__).resolve().parents[1])
        monkeypatch.setenv("PYTHONPATH", "src")

        main(
            [
                "guard",
                "install",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        install_output = json.loads(capsys.readouterr().out)
        shim_path = Path(install_output["managed_install"]["manifest"]["shim_path"])
        try:
            result = subprocess.run(
                [str(shim_path), "--help"],
                capture_output=True,
                text=True,
                env={
                    "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    "HOME": str(home_dir),
                    "PYTHONPATH": str(runtime_pythonpath),
                },
                check=False,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            pytest.fail(
                "guard-codex --help timed out after 15 seconds\n"
                f"stdout:\n{exc.stdout or ''}\n"
                f"stderr:\n{exc.stderr or ''}"
            )

        assert result.returncode == 0, (
            f"guard-codex --help exited with {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert args_file.read_text(encoding="utf-8").strip() == "--help"
        assert env_file.read_text(encoding="utf-8") == os.pathsep.join((str(runtime_pythonpath), str(source_root)))
