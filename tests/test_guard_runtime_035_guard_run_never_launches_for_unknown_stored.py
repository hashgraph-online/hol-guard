"""Runtime regression tests: guard run never launches for unknown stored."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    GuardArtifact,
    GuardConfig,
    GuardStore,
    HarnessContext,
    HarnessDetection,
    Path,
    PolicyDecision,
    argparse,
    decide_action_with_v2,
    guard_commands_module,
    guard_runner_module,
    io,
    json,
    main,
    pytest,
    sqlite3,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_run_never_launches_for_unknown_stored_policy_action(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    home_dir.mkdir()
    workspace_dir.mkdir()
    artifact = GuardArtifact(
        artifact_id="codex:project:mcp:future-policy",
        name="future-policy",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        command="node",
        args=("server.js",),
        transport="stdio",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    store = GuardStore(home_dir)
    launch_calls: list[object] = []
    monkeypatch.setattr(
        store,
        "resolve_policy_decision_lookup_with_memory_pattern",
        lambda *_args, **_kwargs: {
            "decision": {"action": "future-action"},
            "ignored_local_integrity": None,
            "trust_status": {},
            "authority_revision": 0,
        },
    )
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: launch_calls.append((args, kwargs)),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store,
        GuardConfig(guard_home=home_dir, workspace=workspace_dir, default_action="allow"),
        dry_run=False,
        passthrough_args=[],
        default_action="allow",
        interactive_resolver=None,
        blocked_resolver=lambda _detection, evaluation: evaluation,
    )

    assert result["blocked"] is True
    assert result["artifacts"][0]["policy_action"] == "require-reapproval"
    assert launch_calls == []


def test_decide_action_with_v2_preserves_legacy_action_and_adds_decision(tmp_path):
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=None,
        default_action="block",
    )

    action, decision = decide_action_with_v2(
        configured_action=None,
        default_action=None,
        config=config,
        changed=False,
        reason="invalid-default-fallback",
    )

    assert action == "block"
    assert decision.action == "block"
    assert decision.reason == "invalid-default-fallback"
    assert decision.harness_message == "HOL Guard blocked this action."


def test_guard_hook_invalid_policy_action_falls_back_to_reapproval(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)

    event = {
        "event": "PreToolUse",
        "tool_name": "workspace-tools",
        "artifact_id": "claude-code:project:mcp:workspace-tools",
        "policy_action": "require_reapproval",
        "source_scope": "project",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "claude-code",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert output["policy_action"] == "require-reapproval"


def test_runtime_hook_saved_v1_allow_satisfies_exact_unchanged_current_review(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        'approval_wait_timeout_seconds = 0\n[risk_actions]\nlocal_secret_read = "review"\n',
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"path": ".env"},
        "source_scope": "project",
    }

    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )
    store = GuardStore(home_dir)
    first_receipt = store.list_receipts(limit=1)[0]
    context_token = str(first_receipt["artifact_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=str(first_output["artifact_id"]),
            artifact_hash=context_token,
            reason="Reviewed exact hook context",
            source="manual",
        ),
        "2026-07-17T12:00:00+00:00",
    )

    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert first_rc == 1
    assert first_output["policy_action"] == "review"
    assert context_token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert second_rc == 0
    assert second_output["policy_action"] == "allow"
    assert second_output["approval_reuse"]["status"] == "accepted"
    assert second_output["approval_reuse"]["reason_code"] == "approval_reuse_accepted"


@pytest.mark.parametrize("scope", ("artifact", "workspace", "publisher", "harness", "global"))
def test_runtime_hook_saved_v1_allow_matches_every_scope_in_actual_evaluator(tmp_path, scope: str) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    config = GuardConfig(
        guard_home=home_dir,
        workspace=workspace_dir,
        default_action="allow",
        approval_wait_timeout_seconds=0,
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:scope-matrix",
        name="Codex exact scope matrix action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        command="echo",
        args=("scope-matrix",),
        publisher="publisher-a",
        metadata={"guard_default_action": "review", "action_class": "routine shell command"},
    )
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace_dir, guard_home=home_dir)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo scope-matrix"},
        "source_scope": "project",
    }

    first = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
    )
    assert not isinstance(first, int)
    assert first.policy_action == "review"
    token = first.runtime_artifact_hash
    policy_kwargs: dict[str, object] = {
        "artifact_id": artifact.artifact_id if scope in {"artifact", "workspace", "harness", "global"} else None,
        "artifact_hash": token,
        "workspace": str(workspace_dir) if scope == "workspace" else None,
        "publisher": artifact.publisher if scope == "publisher" else None,
    }
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope=scope,
            action="allow",
            reason=f"reviewed exact v1 context at {scope} scope",
            source="manual",
            **policy_kwargs,  # type: ignore[arg-type]
        ),
        "2026-07-17T12:00:00+00:00",
    )

    second = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
    )

    assert not isinstance(second, int)
    assert second.runtime_artifact_hash == token
    assert second.policy_action == "allow"
    assert second.response_payload["approval_reuse"]["status"] == "accepted"


def test_runtime_hook_browser_exact_override_atomically_claims_one_waiter(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    config = GuardConfig(
        guard_home=home_dir,
        workspace=workspace_dir,
        default_action="allow",
        approval_wait_timeout_seconds=0,
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:browser-claim",
        name="Codex browser claim action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        command="echo",
        args=("browser-claim",),
        metadata={
            "guard_default_action": "require-reapproval",
            "action_class": "sensitive shell command",
        },
    )
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace_dir, guard_home=home_dir)
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo browser-claim"},
        "source_scope": "project",
    }
    initial = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
    )
    assert not isinstance(initial, int)
    assert initial.policy_action == "require-reapproval"
    token = initial.runtime_artifact_hash
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=token,
            reason="exact browser allow",
            source="approval-gate",
            expires_at="2099-07-17T12:00:00+00:00",
        ),
        "2026-07-17T12:00:00+00:00",
    )

    first_waiter = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
        trusted_request_override_hash=token,
    )
    second_waiter = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
        trusted_request_override_hash=token,
    )

    assert not isinstance(first_waiter, int)
    assert not isinstance(second_waiter, int)
    assert first_waiter.policy_action == "allow"
    assert first_waiter.response_payload["policy_composition"]["trusted_request_override"] is True
    assert second_waiter.policy_action == "require-reapproval"
    assert second_waiter.response_payload["policy_composition"]["trusted_request_override"] is False
    assert second_waiter.response_payload["policy_composition"]["trusted_request_override_reason"] == (
        "trusted_request_override_allow_missing"
    )

    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="global",
            action="block",
            reason="saved block added while browser waits",
            source="manual",
        ),
        "2026-07-17T12:01:00+00:00",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=token,
            reason="stale exact browser allow",
            source="approval-gate",
            expires_at="2099-07-17T12:00:00+00:00",
        ),
        "2026-07-17T12:02:00+00:00",
    )
    blocked_waiter = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
        trusted_request_override_hash=token,
    )

    assert not isinstance(blocked_waiter, int)
    assert blocked_waiter.policy_action == "block"
    assert blocked_waiter.response_payload["policy_composition"]["trusted_request_override"] is False
    with sqlite3.connect(store.path) as connection:
        remaining_browser_allows = connection.execute(
            "select count(*) from policy_decisions where action = 'allow' and source = 'approval-gate'"
        ).fetchone()[0]
    assert remaining_browser_allows == 1
