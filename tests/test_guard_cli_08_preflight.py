"""Guard CLI preflight behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_preflight_enforce_returns_nonzero_for_non_allow_verdict(self, tmp_path, capsys, monkeypatch):
        target = tmp_path / "incoming-plugin"
        target.mkdir(parents=True)
        payload = {
            "schema_version": "guard-consumer.v2",
            "generated_at": "2026-04-11T00:00:00+00:00",
            "install_target": {
                "path": str(target),
                "intended_harness": "codex",
            },
            "artifact_snapshot": {
                "path": str(target),
                "artifact_hash": "abc123",
            },
            "capability_manifest": {
                "ecosystems": ["codex"],
                "packages": [],
                "category_names": ["Security"],
            },
            "artifact_diff": {
                "changed": False,
                "changed_fields": [],
            },
            "provenance_record": {
                "scope": "plugin",
                "plugin_dir": str(target),
                "trust_score": None,
            },
            "trust_evidence_bundle": {
                "findings": ["Posts environment secrets to a remote host."],
                "severity_counts": {"critical": 1},
                "integrations": [],
            },
            "policy_recommendation": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
            },
            "install_verdict": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
                "can_install": False,
            },
            "abom_entry": {
                "artifact_id": "preflight:incoming-plugin",
                "artifact_type": "plugin",
            },
            "threat_intelligence": {
                "verdict_source": "local-scan",
                "highest_severity": "critical",
            },
        }
        monkeypatch.setattr(
            guard_commands_module,
            "run_consumer_scan",
            lambda path, intended_harness=None, options=None: payload,
        )

        rc = main(
            [
                "guard",
                "preflight",
                str(target),
                "--harness",
                "codex",
                "--enforce",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 2
        assert output["install_verdict"]["action"] == "review"
        assert output["install_target"]["intended_harness"] == "codex"
        assert output["threat_intelligence"]["verdict_source"] == "local-scan"

    def test_guard_preflight_human_output_stays_summary_first(self, tmp_path, capsys, monkeypatch):
        target = tmp_path / "incoming-plugin"
        target.mkdir(parents=True)
        payload = {
            "schema_version": "guard-consumer.v2",
            "generated_at": "2026-04-11T00:00:00+00:00",
            "install_target": {
                "path": str(target),
                "intended_harness": "codex",
            },
            "artifact_snapshot": {
                "path": str(target),
                "artifact_hash": "abc123",
            },
            "capability_manifest": {
                "ecosystems": ["codex"],
                "packages": [],
                "category_names": ["Security"],
            },
            "artifact_diff": {
                "changed": False,
                "changed_fields": [],
            },
            "provenance_record": {
                "scope": "plugin",
                "plugin_dir": str(target),
                "trust_score": None,
            },
            "trust_evidence_bundle": {
                "findings": ["Posts environment secrets to a remote host."],
                "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                "integrations": [],
            },
            "policy_recommendation": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
            },
            "install_verdict": {
                "action": "review",
                "reason": "Install-time scan found risky network and secret access behavior.",
                "can_install": False,
            },
            "abom_entry": {
                "artifact_id": "preflight:incoming-plugin",
                "artifact_type": "plugin",
            },
            "threat_intelligence": {
                "verdict_source": "local-scan",
                "highest_severity": "critical",
                "finding_count": 1,
            },
        }
        monkeypatch.setattr(
            guard_commands_module,
            "run_consumer_scan",
            lambda path, intended_harness=None, options=None: payload,
        )

        rc = main(
            [
                "guard",
                "preflight",
                str(target),
                "--harness",
                "codex",
            ]
        )
        output = capsys.readouterr().out

        assert rc == 0
        assert "Install-time preflight" in output
        assert "Install verdict" in output
        assert "Highest severity" in output
        assert '"install_verdict"' not in output
