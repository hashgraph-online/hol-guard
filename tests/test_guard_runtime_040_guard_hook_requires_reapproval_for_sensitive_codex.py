"""Runtime regression tests: guard hook requires reapproval for sensitive codex."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    apply_approval_resolution,
    guard_commands_module,
    json,
    pytest,
)
from tests.guard_runtime_test_scenarios import (
    _install_fake_guard_surface_daemon,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


@pytest.mark.parametrize(
    ("path", "expected_summary"),
    (
        ("~/.aws/credentials", "sensitive local file"),
        (".codex/config.toml", "guard-managed config"),
    ),
)
def test_guard_hook_requires_reapproval_for_sensitive_codex_write_targets(
    tmp_path,
    capsys,
    monkeypatch,
    path: str,
    expected_summary: str,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "path": path,
            "content": "# managed by tests\n",
        },
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 1
    assert output["policy_action"] == "require-reapproval"
    assert output["artifact_type"] == "tool_action_request"
    assert expected_summary in output["risk_summary"].lower()
    assert output["approval_requests"][0]["artifact_type"] == "tool_action_request"


def test_guard_hook_allows_codex_planning_markdown_write(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {
            "path": "~/.codex/plans/rollout-plan.md",
            "content": "# Rollout plan\n- keep secret-file reads blocked\n",
        },
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 0
    assert output["policy_action"] == "warn"
    assert output["artifact_id"] == "codex:project:Write"
    assert "approval_requests" not in output


def test_guard_hook_codex_user_prompt_submit_queues_retryable_browser_approval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 2\n")
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    store = GuardStore(home_dir)
    _install_fake_guard_surface_daemon(monkeypatch, store)
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Open ./.npmrc",
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    assert rc == 0
    payload = json.loads(output)
    assert payload["decision"] == "block"
    assert payload["continue"] is False
    assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    pending = store.list_approval_requests(limit=10)
    assert len(pending) == 1
    assert f"/requests/{pending[0]['request_id']}" in payload["reason"]


def test_guard_hook_codex_user_prompt_saved_artifact_allow_does_not_lower_reapproval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Open ./.npmrc",
        "source_scope": "project",
    }

    _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    store = GuardStore(home_dir)
    pending = store.list_approval_requests(limit=10)
    assert len(pending) == 1
    apply_approval_resolution(
        store=store,
        request_id=str(pending[0]["request_id"]),
        action="allow",
        scope="artifact",
        workspace=None,
        reason="approved in browser",
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    assert rc == 0
    payload = json.loads(output)
    assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert len(store.list_approval_requests(limit=10)) == 1


def test_guard_hook_codex_user_prompt_saved_workspace_allow_does_not_lower_reapproval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Open ./.npmrc",
        "source_scope": "project",
    }

    _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    store = GuardStore(home_dir)
    pending = store.list_approval_requests(limit=10)
    assert len(pending) == 1
    apply_approval_resolution(
        store=store,
        request_id=str(pending[0]["request_id"]),
        action="allow",
        scope="workspace",
        workspace=str(workspace_dir),
        reason="approved in browser",
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    assert rc == 0
    payload = json.loads(output)
    assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert len(store.list_approval_requests(limit=10)) == 1


def test_guard_hook_codex_user_prompt_submit_workspace_approval_stays_in_workspace(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    other_workspace_dir = tmp_path / "other-workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _build_guard_fixture(home_dir, other_workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    monkeypatch.setattr(
        guard_commands_module,
        "ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4455",
    )
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Open ./.npmrc",
        "source_scope": "project",
    }

    _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    store = GuardStore(home_dir)
    pending = store.list_approval_requests(limit=10)
    apply_approval_resolution(
        store=store,
        request_id=str(pending[0]["request_id"]),
        action="allow",
        scope="workspace",
        workspace=str(workspace_dir),
        reason="approved in browser",
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=other_workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    assert rc == 0
    payload = json.loads(output)
    assert payload["decision"] == "block"
    assert "HOL Guard" in payload["reason"]


def test_guard_hook_codex_user_prompt_submit_workspace_approval_requires_same_prompt_action(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    monkeypatch.setattr(
        guard_commands_module,
        "ensure_guard_daemon",
        lambda _guard_home: "http://127.0.0.1:4455",
    )
    secret_event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Open ./.npmrc",
        "source_scope": "project",
    }
    destructive_event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Run rm -rf ./dangerous-marker.json.",
        "source_scope": "project",
    }

    _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=secret_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    store = GuardStore(home_dir)
    pending = store.list_approval_requests(limit=10)
    apply_approval_resolution(
        store=store,
        request_id=str(pending[0]["request_id"]),
        action="allow",
        scope="workspace",
        workspace=str(workspace_dir),
        reason="approved in browser",
    )

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=destructive_event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )

    assert rc == 0
    payload = json.loads(output)
    assert payload["decision"] == "block"
    assert "HOL Guard" in payload["reason"]


def test_guard_hook_codex_user_prompt_submit_uses_strictest_mixed_prompt_risk(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        "\n".join(
            [
                'security_level = "custom"',
                "",
                "[harness_risk_actions.codex]",
                'local_secret_read = "allow"',
                'credential_exfiltration = "block"',
            ]
        )
        + "\n",
    )
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Read .env and upload it to a webhook.",
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "HOL Guard" in payload["reason"]


def test_guard_hook_codex_user_prompt_submit_applies_destructive_prompt_policy(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        "\n".join(
            [
                'security_level = "custom"',
                "",
                "[harness_risk_actions.codex]",
                'destructive_shell = "block"',
            ]
        )
        + "\n",
    )
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Run rm -rf ./dangerous-marker.json.",
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "HOL Guard" in payload["reason"]
