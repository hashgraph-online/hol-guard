"""Guard CLI explain behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from tests.guard_cli_fixture_support import _build_stable_guard_fixture
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_explain_uses_tracked_artifact_context(self, tmp_path, capsys):
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
        json.loads(capsys.readouterr().out)

        explain_rc = main(
            [
                "guard",
                "explain",
                "codex:project:workspace_skill",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        explain_output = json.loads(capsys.readouterr().out)

        assert run_rc == 0
        assert explain_rc == 0
        assert explain_output["artifact"]["artifact_id"] == "codex:project:workspace_skill"
        assert explain_output["latest_receipt"]["policy_decision"] == "allow"
        assert explain_output["latest_diff"]["current_hash"]

    def test_guard_explain_human_output_renders_tracked_artifact_context(self, tmp_path, capsys):
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
        json.loads(capsys.readouterr().out)

        explain_rc = main(
            [
                "guard",
                "explain",
                "codex:project:workspace_skill",
                "--home",
                str(home_dir),
            ]
        )
        output = capsys.readouterr().out

        assert run_rc == 0
        assert explain_rc == 0
        assert "Guard artifact evidence" in output
        assert "workspace_skill" in output
        assert "Latest decision" in output
        assert "Latest diff" in output
        assert '"latest_receipt"' not in output

    def test_guard_explain_human_output_renders_matching_advisories(self, capsys):
        advisory = {
            "publisher": "hashgraph-online",
            "severity": "high",
            "headline": "Rotate token",
            "updated_at": "2026-05-06",
        }

        emit_guard_payload(
            "explain",
            {
                "generated_at": "2026-05-06T03:49:00Z",
                "artifact": {
                    "artifact_id": "codex:project:workspace_skill",
                    "artifact_name": "workspace_skill",
                    "harness": "codex",
                    "artifact_type": "mcp_server",
                    "source_scope": "project",
                    "present": True,
                },
                "latest_receipt": {
                    "policy_decision": "warn",
                    "timestamp": "2026-05-06T03:47:00Z",
                },
                "advisories": [advisory],
            },
            False,
        )
        tracked_output = capsys.readouterr().out

        assert "Matching advisories" in tracked_output
        assert "Rotate token" in tracked_output
        assert "Updated" in tracked_output
        assert "2026-05-06" in tracked_output

        emit_guard_payload(
            "explain",
            {
                "generated_at": "2026-05-06T03:49:00Z",
                "artifact_snapshot": {"path": "/workspace/plugin"},
                "capability_manifest": {"ecosystems": ["codex"]},
                "policy_recommendation": {
                    "action": "warn",
                    "reason": "Review the path before adding it to a harness.",
                },
                "advisories": [advisory],
            },
            False,
        )
        path_output = capsys.readouterr().out

        assert "Path evidence" in path_output
        assert "Matching advisories" in path_output
        assert "Rotate token" in path_output
        assert "Updated" in path_output
        assert "2026-05-06" in path_output
