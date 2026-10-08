"""Scope-sweep regressions: one decision must never resolve unrelated actions.

Native pretool requests share one artifact id per tool
(``harness:native-pretool:Bash``); the per-action discriminator is the
artifact hash. These tests pin the sweep to that discriminator so deciding
one call cannot resolve other pending calls of the same tool.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _native_request(request_id: str, *, harness: str = "zcode", tool: str = "Bash",
                    command: str | None = None) -> GuardApprovalRequest:
    command = command or f"echo {request_id}"
    return GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=f"{harness}:native-pretool:{tool}",
        artifact_name=f"{tool} call",
        artifact_type="tool_action_request",
        artifact_hash=f"hash-{request_id}",
        publisher="guard-hook",
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        workspace="/workspace/repo",
        launch_target=command,
        action_envelope_json={"action_type": "shell_command", "tool_name": tool, "command": command},
        decision_v2_json={
            "guard_action": "review",
            "action": "ask",
            "reason": "review",
            "user_title": "Approval required",
            "user_body": "HOL Guard needs your approval before this action can run.",
            "harness_message": "HOL Guard needs your approval before this action can run.",
            "dashboard_primary_detail": "HOL Guard needs your approval before this action can run.",
            "approval_scopes": ["artifact", "workspace", "publisher", "harness"],
            "retry_instruction": "Choose an approval scope, then retry in the harness.",
            "signals": [],
            "confidence": "likely",
        },
        review_command=f"hol-guard approvals {request_id}",
        approval_url=f"http://127.0.0.1:1/requests/{request_id}",
    )


def _pending_ids(store: GuardStore) -> list[str]:
    with store._connect() as connection:
        rows = connection.execute(
            "select request_id from approval_requests where status = 'pending' order by request_id"
        ).fetchall()
    return [str(row["request_id"]) for row in rows]


def _seed_unrelated_queue(home: Path) -> GuardStore:
    store = GuardStore(home)
    store.add_approval_request(_native_request("target", command="rm -rf /tmp/old"), "2026-07-20T00:00:05+00:00")
    store.add_approval_request(_native_request("other-bash", command="deploy prod"), "2026-07-20T00:00:04+00:00")
    store.add_approval_request(
        _native_request("other-read", tool="Read", command="cat src/main.py"),
        "2026-07-20T00:00:03+00:00",
    )
    store.add_approval_request(
        _native_request("other-write", tool="Write", command="write notes.md"),
        "2026-07-20T00:00:02+00:00",
    )
    store.add_approval_request(
        _native_request("other-omp", harness="omp", tool="read", command="omp read notes"),
        "2026-07-20T00:00:01+00:00",
    )
    return store


def _duplicate_request(request_id: str, *, command: str = "rm -rf /tmp/old") -> GuardApprovalRequest:
    return _native_request(request_id, command=command)


def test_allow_once_never_resolves_other_actions_of_the_same_tool(tmp_path: Path) -> None:
    store = _seed_unrelated_queue(tmp_path / "allow-once")

    result = apply_approval_resolution(
        store=store, request_id="target", action="allow", scope="artifact",
        workspace=None, reason="reviewed once", return_queue_result=True,
    )

    assert store.get_approval_request("target")["status"] == "resolved"
    assert _pending_ids(store) == ["other-bash", "other-omp", "other-read", "other-write"]
    assert result.get("resolved_scope_ids") in (None, [])


def test_allow_once_still_folds_duplicate_retries_into_one_decision(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "allow-duplicates")
    store.add_approval_request(_duplicate_request("target"), "2026-07-20T00:00:05+00:00")
    # A retried identical action folds into the same queue row instead of a
    # second pending approval, so one allow covers the retry by construction.
    store.add_approval_request(_duplicate_request("target-retry"), "2026-07-20T00:00:06+00:00")
    store.add_approval_request(_native_request("other-bash", command="deploy prod"), "2026-07-20T00:00:04+00:00")

    apply_approval_resolution(
        store=store, request_id="target", action="allow", scope="artifact",
        workspace=None, reason="reviewed once", return_queue_result=True,
    )

    assert store.get_approval_request("target")["status"] == "resolved"
    assert store.get_approval_request("target-retry") is None
    assert _pending_ids(store) == ["other-bash"]


def test_block_scope_sweeps_stay_bound_to_the_decided_action(tmp_path: Path) -> None:
    store = _seed_unrelated_queue(tmp_path / "block-artifact")

    apply_approval_resolution(
        store=store, request_id="target", action="block", scope="artifact",
        workspace=None, reason="blocked", return_queue_result=True,
    )

    assert store.get_approval_request("target")["status"] == "resolved"
    assert _pending_ids(store) == ["other-bash", "other-omp", "other-read", "other-write"]


def test_global_block_without_artifact_keeps_legacy_queue_sweep(tmp_path: Path) -> None:
    """Direct store callers without an artifact keep the documented global sweep."""

    store = _seed_unrelated_queue(tmp_path / "global-legacy")

    resolved_ids = store.resolve_matching_approval_requests(
        harness=None,
        scope="global",
        artifact_id=None,
        artifact_hash=None,
        workspace=None,
        publisher=None,
        resolution_action="block",
        resolution_scope="global",
        reason="operator flush",
        resolved_at="2026-07-20T00:00:07+00:00",
    )

    assert sorted(resolved_ids) == ["other-bash", "other-omp", "other-read", "other-write", "target"]


def test_workspace_sweep_without_artifact_binding_covers_the_workspace(tmp_path: Path) -> None:
    """A workspace-wide decision without an artifact binding sweeps the workspace."""

    store = _seed_unrelated_queue(tmp_path / "workspace-broad")

    resolved_ids = store.resolve_matching_approval_requests(
        harness="zcode",
        scope="workspace",
        artifact_id=None,
        artifact_hash=None,
        workspace="/workspace/repo",
        publisher=None,
        resolution_action="block",
        resolution_scope="workspace",
        reason="blocked workspace-wide",
        resolved_at="2026-07-20T00:00:07+00:00",
    )

    # The zcode rows share the workspace config path; the omp row does not.
    assert sorted(resolved_ids) == ["other-bash", "other-read", "other-write", "target"]
    assert _pending_ids(store) == ["other-omp"]


def test_workspace_sweep_with_artifact_binding_stays_on_the_decided_action(tmp_path: Path) -> None:
    """A workspace decision bound to one artifact never resolves other actions."""

    store = _seed_unrelated_queue(tmp_path / "workspace-bound")

    resolved_ids = store.resolve_matching_approval_requests(
        harness="zcode",
        scope="workspace",
        artifact_id="zcode:native-pretool:Bash",
        artifact_hash="hash-target",
        workspace="/workspace/repo",
        publisher=None,
        resolution_action="block",
        resolution_scope="workspace",
        reason="blocked this action in the workspace",
        resolved_at="2026-07-20T00:00:07+00:00",
    )

    assert resolved_ids == ["target"]
    assert _pending_ids(store) == ["other-bash", "other-omp", "other-read", "other-write"]
