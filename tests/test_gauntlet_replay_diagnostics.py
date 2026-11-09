from __future__ import annotations

import json
from types import SimpleNamespace

from tests.gauntlet_replay_diagnostics import replay_diagnostics


def fixture_tree(tmp_path):
    home = tmp_path / "private-home"
    worktree = home / "workspace"
    tmp_org = tmp_path / "temp-parent" / "org"
    for path in (home, worktree, tmp_org / "app", tmp_org.parent / "app-followup"):
        path.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(home=home, worktree=worktree, tmp_org=tmp_org)


def test_diagnostics_keep_proof_but_exclude_payload_and_host_paths(tmp_path):
    fixture = fixture_tree(tmp_path)
    secret = "never-print-this-secret"
    result = {
        "reason_code": "native_policy_reapproval_required",
        "reason": f"command {secret} in {fixture.home}",
        "decision": "deny",
        "minimum_action": "require-reapproval",
        "command": secret,
        "environment": {"TOKEN": secret},
    }
    text = replay_diagnostics(
        fixture, fixture.tmp_org, result, [{"reason_code": "native_review", "body": secret}], 1.23456
    )
    evidence = json.loads(text)
    assert secret not in text and str(tmp_path) not in text
    assert evidence["elapsed_seconds"] == 1.235
    assert evidence["decision"] == "deny"
    assert evidence["reason_code"] == "native_policy_reapproval_required"
    assert evidence["approval_reason_codes"] == ["native_review"]
    assert evidence["relations"]["cwd_below_tmp_parent"]
    assert not evidence["relations"]["cwd_equals_workspace"]
    assert evidence["paths"]["tmp_checkout"]["same_owner_as_home"]
    assert len(evidence["reason_sha256"]) == 64


def test_diagnostics_report_missing_fixture_without_masking_failure(tmp_path):
    fixture = fixture_tree(tmp_path)
    missing = fixture.tmp_org.parent / "missing"
    evidence = json.loads(replay_diagnostics(fixture, missing, {"decision": [], "minimum_action": {}}, [], 0))
    assert evidence["paths"]["cwd"] == {"available": False, "error": "ENOENT"}
    assert evidence["relations"]["error"] == "ENOENT"
    assert evidence["decision"] is None
    assert evidence["minimum_action"] is None


def test_diagnostics_report_writable_fixture_and_known_policy_setting(tmp_path):
    fixture = fixture_tree(tmp_path)
    fixture.tmp_org.chmod(0o777)
    reason = "HOL Guard requires fresh approval under the installed policy's command execution setting."
    evidence = json.loads(replay_diagnostics(fixture, fixture.worktree, {"reason": reason}, [], 0))
    assert evidence["policy_setting"] == "command execution"
    assert evidence["paths"]["tmp_org"]["group_or_other_writable"]
    assert evidence["relations"]["cwd_equals_workspace"]
