"""Guard CLI config diff run behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.config import GuardConfig
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.guard_cli_fixture_support import _build_guard_fixture, _build_stable_guard_fixture, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle


class TestGuardCli:
    def test_guard_diff_reports_config_changes(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_stable_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')

        first_run = main(
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
        assert first_run == 0
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

        rc = main(
            [
                "guard",
                "diff",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["changed"] is True
        assert output["artifacts"][0]["changed_fields"]

        rerun_rc = main(
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
        rerun_output = json.loads(capsys.readouterr().out)

        assert rerun_rc == 1
        assert rerun_output["blocked"] is True
        assert any(item["policy_action"] == "require-reapproval" for item in rerun_output["artifacts"])
        assert any(item["changed"] is True for item in rerun_output["artifacts"])

    def test_guard_run_returns_launched_harness_exit_code(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setattr(
            guard_commands_module,
            "guard_run",
            lambda *args, **kwargs: {
                "harness": "codex",
                "artifacts": [],
                "blocked": False,
                "receipts_recorded": 0,
                "launched": True,
                "return_code": 7,
            },
        )

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

        assert output["return_code"] == 7
        assert rc == 7

    def test_guard_run_current_config_provider_reloads_local_and_synced_policy(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        captured: dict[str, GuardConfig] = {}

        def fake_guard_run(*_args, **kwargs):
            store = kwargs["store"]
            current_config_provider = kwargs["current_config_provider"]
            _write_text(store.guard_home / "config.toml", 'default_action = "warn"\n')
            policy_bundle = build_cloud_exception_policy_bundle(workspace_id="workspace-1")
            policy_defaults = policy_bundle["policyDefaults"]
            assert isinstance(policy_defaults, dict)
            policy_defaults["defaultAction"] = "block"
            store.set_sync_payload(
                "oauth_local_credentials",
                {"workspace_id": "workspace-1"},
                "2026-07-17T00:00:00+00:00",
            )
            store.set_sync_payload(
                "policy_bundle_keyring",
                policy_bundle_test_keyring(workspace_id="workspace-1"),
                "2026-07-17T00:00:00+00:00",
            )
            store.set_sync_payload(
                "policy_bundle",
                sign_policy_bundle(policy_bundle, workspace_id="workspace-1"),
                "2026-07-17T00:00:00+00:00",
            )
            captured["config"] = current_config_provider()
            return {
                "harness": "codex",
                "artifacts": [],
                "blocked": False,
                "receipts_recorded": 0,
                "launched": False,
            }

        monkeypatch.setattr(guard_commands_module, "guard_run", fake_guard_run)

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
        json.loads(capsys.readouterr().out)

        assert rc == 0
        assert captured["config"].default_action == "block"
        assert captured["config"].workspace == workspace_dir.resolve()
