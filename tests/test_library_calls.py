from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.library_calls import run_library_call
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

COPY = {
    "codex": {"title": "Approved. Retry in chat.", "body": "Return to Codex and retry"},
    "": {"title": "Approved. Retry in chat.", "body": "Return to your AI assistant and retry"},
}


def _call(home: Path, name: str, args: object) -> dict[str, object]:
    return run_library_call(home, json.dumps({"call": name, "args": args}).encode("utf-8"))


def _seed(home: Path) -> None:
    GuardStore(home).add_approval_request(
        GuardApprovalRequest(
            request_id="req-lib",
            harness="codex",
            artifact_id="codex:session:prompt:demo",
            artifact_name="prompt request",
            artifact_type="prompt_request",
            artifact_hash="hash-lib",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("prompt_request",),
            source_scope="session",
            config_path=str(home / "workspace" / ".codex" / "config.toml"),
            review_command="hol-guard approvals approve req-lib",
            approval_url="http://127.0.0.1/pending/req-lib",
        ),
        "2026-05-01T00:00:00+00:00",
    )


def _resolve_args(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "request_id": "req-lib",
        "action": "allow",
        "scope": "artifact",
        "payload": {"scope": "artifact"},
        "resolve_scope_matches": True,
        "copy": COPY,
    }
    args.update(overrides)
    return args


def test_malformed_and_unknown_calls_are_library_errors(tmp_path: Path) -> None:
    assert run_library_call(tmp_path, b"not json")["error"]["kind"] == "library_call"  # type: ignore[index]
    assert run_library_call(tmp_path, b"[]")["error"]["kind"] == "library_call"  # type: ignore[index]
    unknown = _call(tmp_path, "no.such.call", {})
    assert unknown["error"] == {"type": "LibraryCallError", "message": "unknown_call", "kind": "library_call"}
    missing_args = _call(tmp_path, "approval.resolve", {"action": "allow"})
    assert missing_args["error"]["kind"] == "library_call"  # type: ignore[index]


def test_unknown_request_is_not_found(tmp_path: Path) -> None:
    answer = _call(tmp_path, "approval.resolve", _resolve_args(request_id="req-missing"))
    assert answer["error"]["kind"] == "not_found"  # type: ignore[index]


def test_invalid_remember_is_a_value_error(tmp_path: Path) -> None:
    _seed(tmp_path)
    answer = _call(tmp_path, "approval.resolve", _resolve_args(payload={"scope": "artifact", "remember": "maybe"}))
    assert answer["error"]["kind"] == "value"  # type: ignore[index]
    assert answer["error"]["message"] == "invalid boolean value"  # type: ignore[index]


def test_resolve_applies_copy_and_repeats_are_idempotent(tmp_path: Path) -> None:
    _seed(tmp_path)
    answer = _call(tmp_path, "approval.resolve", _resolve_args())
    updated = answer["ok"]["updated"]  # type: ignore[index]
    # The Codex continuation finds no chat to resume, so it replaces the copy.
    assert updated["copy"]["title"] == "Decision saved. Return to Codex."
    assert updated["retry_hint"] == updated["copy"]["body"]
    stored = GuardStore(tmp_path).get_approval_request("req-lib")
    assert isinstance(stored, dict)
    assert stored["status"] != "pending"
    assert stored["resolution_action"] == "allow"
    assert GuardStore(tmp_path).list_events(event_name="approval_resolved")

    repeat = _call(tmp_path, "approval.resolve", _resolve_args())
    body = repeat["ok"]["idempotent"]  # type: ignore[index]
    assert body["resolved"] is True
    assert body["idempotent"] is True

    conflict = _call(tmp_path, "approval.resolve", _resolve_args(action="block"))
    assert conflict["ok"] == {"already_resolved": True}


def test_resolve_rejects_a_missing_copy_table(tmp_path: Path) -> None:
    _seed(tmp_path)
    answer = _call(tmp_path, "approval.resolve", _resolve_args(copy={}))
    assert answer["error"]["kind"] == "library_call"  # type: ignore[index]


def test_cli_answers_one_call_on_stdout(tmp_path: Path) -> None:
    import subprocess
    import sys

    command = [sys.executable, "-m", "codex_plugin_scanner.cli", "guard", "desktop", "library-call"]
    command += ["--guard-home", str(tmp_path)]
    request = json.dumps({"call": "no.such.call", "args": {}}).encode("utf-8")
    completed = subprocess.run(
        command,
        input=request,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert json.loads(completed.stdout)["error"]["message"] == "unknown_call"

    empty = subprocess.run(
        command,
        input=b"",
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert empty.returncode == 2
    assert empty.stdout == b""


def test_policy_lookups_answer_with_route_replies(tmp_path: Path) -> None:
    assert _call(tmp_path, "route.policy_resolve", {"payload": {}}) == {
        "ok": {"status": 400, "body": {"error": "invalid_harness"}, "no_store": False}
    }
    resolved = _call(tmp_path, "route.policy_resolve", {"payload": {"harness": "codex", "artifact_id": "a"}})
    assert resolved["ok"]["status"] == 200  # type: ignore[index]
    assert resolved["ok"]["no_store"] is True  # type: ignore[index]
    assert resolved["ok"]["body"]["decision"] is None  # type: ignore[index]
    assert _call(tmp_path, "route.policy_claim", {"payload": {"decision": 1}}) == {
        "ok": {"status": 400, "body": {"error": "invalid_decision"}, "no_store": False}
    }


def test_resume_retry_of_an_unknown_request_is_not_found(tmp_path: Path) -> None:
    answer = _call(tmp_path, "route.request_resume_retry", {"request_id": "req-missing", "payload": {}})
    assert answer == {"ok": {"status": 404, "body": {"error": "not_found"}, "no_store": False}}


def test_bulk_allow_rejects_a_malformed_body(tmp_path: Path) -> None:
    answer = _call(tmp_path, "route.bulk_allow_once", {"payload": {"request_ids": "nope"}})
    assert answer["ok"]["status"] == 400  # type: ignore[index]


def test_policy_writes_reject_malformed_bodies(tmp_path: Path) -> None:
    for name in ("route.policy_clear", "route.policy_upsert"):
        answer = _call(tmp_path, name, {"payload": {}})
        assert answer["ok"]["status"] == 400, name  # type: ignore[index]


def test_harness_action_rejects_an_unknown_harness(tmp_path: Path) -> None:
    answer = _call(
        tmp_path,
        "route.harness_action",
        {"harness": "not-a-harness", "action": "repair", "payload": {"dry_run": True}},
    )
    assert answer["ok"]["status"] in {400, 404}  # type: ignore[index]


def test_insights_share_raises_on_an_invalid_boolean(tmp_path: Path) -> None:
    answer = _call(tmp_path, "route.insights_share", {"payload": {"includeTopArtifacts": "maybe"}})
    assert answer["error"]["kind"] == "value"  # type: ignore[index]


def test_cloud_exception_request_rejects_an_invalid_body(tmp_path: Path) -> None:
    answer = _call(tmp_path, "route.cloud_exception_request_create", {"payload": {}})
    assert answer["ok"]["status"] in {400, 401, 403, 409, 502, 503}  # type: ignore[index]


def _handler_post(home: Path, path: str, payload: object) -> dict[str, object]:
    return _call(home, "route.handler_post", {"path": path, "payload": payload})


def test_handler_post_records_the_reply_each_handler_writes(tmp_path: Path) -> None:
    cases = [
        ("/v1/harness-versions/acknowledge", {"harness": "not-a-harness"}, 400, {"error": "invalid_harness"}),
        (
            "/v1/mcp-policy/requests/r-1/decision",
            {"action": "maybe"},
            400,
            {"resolved": False, "error": "missing_required_fields"},
        ),
        ("/v1/supply-chain/workspace-assessments/cancel", {"run_id": ""}, 400, {"error": "invalid_run_id"}),
        ("/v1/supply-chain/workspace-fix-proposals/../apply", {}, 400, {"error": "invalid_proposal_id"}),
    ]
    for path, payload, status, body in cases:
        answer = _handler_post(tmp_path, path, payload)
        assert answer["ok"] == {"status": status, "body": body, "no_store": False}, path


def test_handler_post_keeps_the_no_store_header(tmp_path: Path) -> None:
    answer = _handler_post(tmp_path, "/v1/context-assistance/codex-lean", {"enabled": "yes"})
    assert answer["ok"]["status"] == 400  # type: ignore[index]
    assert answer["ok"]["no_store"] is True  # type: ignore[index]


def test_handler_post_refuses_paths_it_does_not_run(tmp_path: Path) -> None:
    assert "error" in _handler_post(tmp_path, "/v1/settings", {})
    assert _handler_post(tmp_path, "/v1/context-assistance/stop", [])["error"]["kind"] == "library_call"  # type: ignore[index]


def test_handler_post_runs_version_administration(tmp_path: Path) -> None:
    answer = _handler_post(tmp_path, "/v1/context-assistance/versions", {"input": "releases"})
    assert answer["ok"] == {"status": 400, "body": {"error": "invalid_context_input"}, "no_store": False}


def _handler_get(home: Path, path: str, query: str = "") -> dict[str, object]:
    return _call(home, "route.handler_get", {"path": path, "query": query})


def test_handler_get_records_the_workspace_reads(tmp_path: Path) -> None:
    answer = _handler_get(tmp_path, "/v1/supply-chain/workspace-findings", "root=%2Fnot-tracked")
    body = answer["ok"]["body"]  # type: ignore[index]
    assert answer["ok"]["status"] == 200  # type: ignore[index]
    assert body["worktrees"] == [] and body["suggested_root_tracked"] is False  # type: ignore[index]
    runs = _handler_get(tmp_path, "/v1/supply-chain/workspace-assessments")["ok"]["body"]  # type: ignore[index]
    assert runs["runs"] == [] and runs["latest_runs"] == []  # type: ignore[index]


def test_handler_get_refuses_paths_it_does_not_run(tmp_path: Path) -> None:
    assert _handler_get(tmp_path, "/v1/settings")["error"]["kind"] == "library_call"  # type: ignore[index]
    assert "error" in _call(tmp_path, "route.handler_get", {"path": "/v1/context-assistance", "query": 1})


def test_settings_calls_answer_without_a_daemon(tmp_path: Path) -> None:
    setup = _call(tmp_path, "route.approval_gate_setup", {"payload": {"settings": {}}})["ok"]
    assert setup["status"] == 400  # type: ignore[index]
    channel = _call(tmp_path, "route.update_channel", {"payload": {"update_channel": "nightly-unknown"}})["ok"]
    assert channel["status"] == 400 and channel["body"]["error"] == "invalid_update_channel"  # type: ignore[index]


def test_policy_sync_refuses_a_request_without_a_bundle(tmp_path: Path) -> None:
    harness = _call(tmp_path, "route.policy_sync", {"payload": {}})["ok"]
    assert harness == {"status": 400, "body": {"error": "missing_harness"}, "no_store": False}
    unknown = _call(tmp_path, "route.policy_sync", {"payload": {"harness": "no-such-harness"}})["ok"]
    assert unknown["status"] == 404  # type: ignore[index]
    assert _call(tmp_path, "route.policy_sync", {"payload": []})["error"]["kind"] == "library_call"  # type: ignore[index]


def test_control_library_steps_read_the_daemon_state(tmp_path: Path) -> None:
    facts = _call(tmp_path, "connect.facts", {"kind": "cloud", "port": 5999, "daemon_pid": 1})["ok"]
    assert set(facts) == {"required", "repair", "connect_url", "cloud_state", "package_state"}  # type: ignore[arg-type]
    update = _call(tmp_path, "update.status", {"progress": True})["ok"]
    assert "current_version" in update  # type: ignore[operator]
    unknown = _call(tmp_path, "headless.app_action", {"harness": "no-such-harness", "port": 5999})["ok"]
    assert unknown == {"error": "unknown_harness"}
    listed = _call(tmp_path, "local_clis.list", {"port": 5999, "daemon_pid": 1})["ok"]
    assert set(listed) == {"payload"}  # type: ignore[arg-type]


def test_native_daemon_worker_passes_are_not_library_calls(tmp_path: Path) -> None:
    # The native daemon runs the heartbeat, the idle hold and storage
    # maintenance itself.
    for name in ("worker.idle_holds", "worker.maintain_activity", "worker.runtime_heartbeat"):
        assert _call(tmp_path, name, {})["error"]["message"] == "unknown_call"  # type: ignore[index]


def test_worker_reconcile_leaves_an_unmanaged_home_untouched(tmp_path: Path) -> None:
    reconciled = _call(tmp_path, "worker.reconcile_artifacts", {"home": str(tmp_path / "home")})
    assert reconciled["ok"]["ok"] is True  # type: ignore[index]
    assert reconciled["ok"]["repaired_harnesses"] == []  # type: ignore[index]


def test_worker_aibom_and_onefile_passes_answer(tmp_path: Path) -> None:
    aibom = _call(tmp_path, "worker.aibom_inventory", {})
    assert aibom["ok"]["status"] == "missing_workspace_context"  # type: ignore[index]
    payload = GuardStore(tmp_path).get_sync_payload("aibom_inventory_daemon")
    assert isinstance(payload, dict) and payload["status"] == "missing_workspace_context"
    assert _call(tmp_path, "worker.onefile_reclaim", {})["ok"] == {"ok": True, "skipped": True}


def test_replayed_attention_reaches_the_worker_host_without_the_daemon_key(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.workers.host import DurableApprovalAttention, _take_attention

    store = GuardStore(tmp_path)
    requests: list[dict[str, object]] = [{"request_id": "req-1", "approval_url": "http://127.0.0.1:1/approve/req-1"}]
    DurableApprovalAttention(store).schedule(operation_id="op-1", requests=requests, browser_url="http://x/?k=secret")
    taken = _take_attention(store)
    assert taken == [{"operation_id": "op-1", "requests": requests}]
    assert "secret" not in json.dumps(taken)
    assert _take_attention(store) == []


def test_hook_removal_needs_its_confirmation(tmp_path: Path) -> None:
    answer = _call(tmp_path, "route.repair", {"path": "/v1/protection/remove-hooks", "payload": {}})
    assert answer["ok"] == {  # type: ignore[index]
        "status": 400,
        "body": {"error": "confirmation_required", "confirm": "remove-guard-hooks"},
        "no_store": False,
    }


def test_repair_refuses_a_path_it_does_not_answer(tmp_path: Path) -> None:
    answer = _call(tmp_path, "route.repair", {"path": "/v1/other", "payload": {}})
    assert "ok" not in answer
