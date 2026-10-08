from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import (
    NativePolicySnapshotError,
    build_policy_snapshot_v3,
    snapshot_bytes_v3,
)

from .native_policy_snapshot_test_fixtures import _config


def _build(tmp_path, *, workspace, rule):
    return build_policy_snapshot_v3(
        config={**_config(), "cloud_workspace_id": workspace, "exact_command_actions": [rule]},
        guard_home=tmp_path,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=b"k" * 32,
        generation=1,
        issued_at_ms=100,
        expires_at_ms=200,
    )


def _rule():
    return {
        "harness": "codex",
        "command_sha256": "c" * 64,
        "cloud_workspace_id": "workspace-a",
        "action": "block",
        "expires_at": "2099-01-01T00:00:00Z",
    }


def test_signed_snapshot_accepts_exact_memory_bound_to_current_cloud_workspace(tmp_path):
    snapshot = _build(tmp_path, workspace="workspace-a", rule=_rule())
    snapshot["effective_policy"]["exact_command_actions"][0]["command_sha256"] = "d" * 64
    with pytest.raises(NativePolicySnapshotError):
        snapshot_bytes_v3(snapshot)


@pytest.mark.parametrize("change", ["workspace", "digest", "unknown"])
def test_exact_memory_snapshot_rejects_mismatched_or_malformed_authority(tmp_path, change):
    rule = _rule()
    if change == "workspace":
        rule["cloud_workspace_id"] = "workspace-b"
    elif change == "digest":
        rule["command_sha256"] = "C" * 64
    else:
        rule["untrusted_allow"] = True
    with pytest.raises(NativePolicySnapshotError, match="native_policy_snapshot_exact_command_invalid"):
        _build(tmp_path, workspace="workspace-a", rule=rule)
