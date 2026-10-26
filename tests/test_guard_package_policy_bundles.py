"""Native package-policy precedence regressions with deterministic managers."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.shim_execution_helpers import write_fake_manager_script
from tests.test_guard_package_shims import (
    _cached_policy_rule,
    _seed_workspace_sync_credentials,
    _signed_cached_policy_bundle,
    _start_cloud_eval_server,
    _stop_cloud_eval_server,
)
from tests.test_guard_supply_chain_evaluator import _force_unpaid_entitlement


@pytest.mark.usefixtures("approval_questionnaire_mode")
def test_guard_protect_ignores_stale_policy_bundle_package_family_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    _force_unpaid_entitlement(monkeypatch)
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    marker_path = tmp_path / "npm-ran.json"
    write_fake_manager_script(fake_bin=fake_bin, manager="npm", marker_path=marker_path, exit_code=0)
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", os.pathsep.join(filter(None, [str(fake_bin), original_path])))
    server, thread, sync_url = _start_cloud_eval_server(
        decision="allow",
        package_name="cli",
        evaluate_status=400,
    )
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    try:
        store = GuardStore(home_dir)
        store.replace_remote_policies(
            [
                PolicyDecision(
                    harness="*",
                    scope="harness",
                    action="block",
                    artifact_id="family:package-request",
                    source="policy-bundle",
                    owner="policy-graph-default-high-block",
                    reason="Block immediately high risk.",
                )
            ],
            "2026-05-19T00:00:00Z",
            remote_write_authorized=True,
        )
        store.set_sync_payload(
            "policy_bundle",
            _signed_cached_policy_bundle(
                [
                    _cached_policy_rule(
                        "policy-graph-default-high-block",
                        matcher_families=["package-request"],
                    )
                ]
            ),
            "2026-05-19T00:00:00Z",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "i",
                "-g",
                "@stripe/cli",
            ]
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    payload = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert payload["primary_approval_url"].startswith("http://127.0.0.1:5474/requests/")
    reason_codes = {
        reason["code"]
        for reason in payload["supply_chain_evaluation"]["reasons"]
        if isinstance(reason, dict) and isinstance(reason.get("code"), str)
    }
    assert "cloud_validation_error" in reason_codes
    assert "saved_package_block" not in reason_codes
    assert "saved package policy" not in payload["supply_chain_evaluation"]["user_copy"]["harness_message"]


def test_guard_protect_ignores_ecosystem_scoped_policy_bundle_family_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    home_dir = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    server, thread, sync_url = _start_cloud_eval_server(
        decision="allow",
        package_name="cli",
        evaluate_status=200,
    )
    try:
        store = GuardStore(home_dir)
        store.replace_remote_policies(
            [
                PolicyDecision(
                    harness="*",
                    scope="harness",
                    action="block",
                    artifact_id="family:package-request",
                    source="policy-bundle",
                    owner="npm-block",
                    reason="Test-only cached package policy.",
                )
            ],
            "2026-05-19T00:00:00Z",
            remote_write_authorized=True,
        )
        store.set_sync_payload(
            "policy_bundle",
            _signed_cached_policy_bundle(
                [_cached_policy_rule("npm-block", matcher_families=["package-request"], ecosystems=["npm"])]
            ),
            "2026-05-19T00:00:00Z",
        )
        _seed_workspace_sync_credentials(home_dir, sync_url)
        rc = main(
            [
                "guard",
                "protect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
                "--dry-run",
                "npm",
                "i",
                "-g",
                "@stripe/cli",
            ]
        )
    finally:
        _stop_cloud_eval_server(server, thread)

    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["supply_chain_evaluation"]["decision"] == "warn"
    reason_codes = {
        reason["code"]
        for reason in payload["supply_chain_evaluation"]["reasons"]
        if isinstance(reason, dict) and isinstance(reason.get("code"), str)
    }
    assert "saved_package_block" not in reason_codes
    assert "current_package_policy" in reason_codes
