"""Guard CLI policy inventory behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from tests.guard_cli_fixture_support import _build_guard_fixture, _build_stable_guard_fixture
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_policies_and_exceptions_show_persisted_rules(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        allow_rc = main(
            [
                "guard",
                "allow",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--scope",
                "artifact",
                "--artifact-id",
                "codex:project:workspace_skill",
                "--expires-in-hours",
                "2",
                "--owner",
                "local-dev",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        deny_rc = main(
            [
                "guard",
                "deny",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--scope",
                "publisher",
                "--publisher",
                "hashgraph-online",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)

        policies_rc = main(["guard", "policies", "--home", str(home_dir), "--json"])
        policies_output = json.loads(capsys.readouterr().out)
        exceptions_rc = main(["guard", "exceptions", "--home", str(home_dir), "--json"])
        exceptions_output = json.loads(capsys.readouterr().out)

        assert allow_rc == 0
        assert deny_rc == 0
        assert policies_rc == 0
        assert exceptions_rc == 0
        assert len(policies_output["items"]) == 2
        assert {item["scope"] for item in policies_output["items"]} == {"artifact", "publisher"}
        assert exceptions_output["items"][0]["artifact_id"] == "codex:project:workspace_skill"
        assert exceptions_output["items"][0]["owner"] == "local-dev"
        assert exceptions_output["items"][0]["expires_at"].endswith("+00:00")

    def test_guard_inventory_and_abom_export_local_artifacts(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_stable_guard_fixture(home_dir, workspace_dir)

        run_rc = main(
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
        run_output = json.loads(capsys.readouterr().out)

        inventory_rc = main(
            [
                "guard",
                "inventory",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        inventory_output = json.loads(capsys.readouterr().out)

        abom_rc = main(
            [
                "guard",
                "abom",
                "--home",
                str(home_dir),
                "--format",
                "json",
                "--json",
            ]
        )
        abom_output = json.loads(capsys.readouterr().out)

        assert run_rc == 0
        assert run_output["blocked"] is False
        assert inventory_rc == 0
        assert inventory_output["items"][0]["artifact_id"] == "codex:global:global_tools"
        assert inventory_output["items"][0]["present"] is True
        assert inventory_output["items"][0]["last_policy_action"] == "allow"
        assert inventory_output["items"][0]["first_seen_at"].endswith("+00:00")
        assert abom_rc == 0
        assert abom_output["artifacts"][0]["artifact_id"] == "codex:global:global_tools"
        assert abom_output["artifacts"][0]["trust_verdict"] == "allow"
