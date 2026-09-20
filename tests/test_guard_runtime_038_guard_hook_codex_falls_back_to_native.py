"""Runtime regression tests: guard hook codex falls back to native."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    guard_commands_module,
    io,
    json,
    main,
    pytest,
    runtime_review_module,
    subprocess,
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


@pytest.mark.parametrize("failure_phase", ["start_session", "queue_blocked_operation"])
def test_guard_hook_codex_falls_back_to_native_deny_after_daemon_request_failure(
    tmp_path,
    capsys,
    monkeypatch,
    failure_phase,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    monkeypatch.setattr(
        runtime_review_module,
        "schedule_guard_daemon_ensure",
        lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
    )

    class FailingDaemonClient:
        def start_session(self, **_kwargs):
            if failure_phase == "start_session":
                raise RuntimeError("Guard daemon request failed: timed out")
            return {"session_id": "session-1"}

        def queue_blocked_operation(self, **_kwargs):
            raise RuntimeError("Guard daemon request failed: timed out")

    monkeypatch.setattr(
        runtime_review_module,
        "load_guard_surface_daemon_client",
        lambda _guard_home: FailingDaemonClient(),
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"path": str(home_dir / ".env")},
        "policy_action": "require-reapproval",
        "cwd": str(workspace_dir),
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
            "codex",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert len(GuardStore(home_dir).list_approval_requests(limit=10)) == 1


def test_guard_hook_codex_emits_no_native_output_for_safe_requests(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    safe_event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "gh auth status"},
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(safe_event)))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    output = capsys.readouterr().out
    pending = GuardStore(home_dir).list_approval_requests(limit=10)

    assert rc == 0
    assert output == ""
    assert GuardStore(home_dir).list_receipts(limit=10) == []
    assert pending == []


@pytest.mark.parametrize(
    "strict_config",
    (
        'default_action = "require-reapproval"\n',
        '[harnesses.codex]\ndefault_action = "require-reapproval"\n',
    ),
    ids=("global", "harness"),
)
def test_guard_hook_codex_strict_default_allows_verified_benign_git_status(
    strict_config,
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    subprocess.run(["git", "init", "--quiet", str(workspace_dir)], check=True)
    _write_text(home_dir / "config.toml", strict_config)
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short"},
        "source_scope": "project",
        "cwd": str(workspace_dir),
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
            "codex",
        ]
    )
    output = capsys.readouterr().out
    store = GuardStore(home_dir)

    assert rc == 0
    assert output == ""
    assert store.list_approval_requests(limit=10) == []
    assert store.list_receipts(limit=1) == []


@pytest.mark.parametrize(
    "strict_config",
    (
        'default_action = "require-reapproval"\n',
        '[harnesses.codex]\ndefault_action = "require-reapproval"\n',
    ),
    ids=("global", "harness"),
)
def test_guard_hook_codex_strict_default_allows_verified_native_source_read(
    strict_config,
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    source_file = workspace_dir / "src" / "service.py"
    _write_text(source_file, "value = 1\n")
    _write_text(home_dir / "config.toml", strict_config)
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(source_file)},
        "source_scope": "project",
        "cwd": str(workspace_dir),
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
    store = GuardStore(home_dir)

    assert rc == 0
    assert output["policy_action"] == "warn"
    assert store.list_approval_requests(limit=10) == []


@pytest.mark.parametrize("explicit_action", ("block", "require-reapproval"))
def test_guard_hook_codex_verified_benign_does_not_override_explicit_policy(
    explicit_action,
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        (
            'default_action = "require-reapproval"\n'
            "approval_wait_timeout_seconds = 0\n"
            f'[artifacts."codex:project:Bash"]\naction = "{explicit_action}"\n'
        ),
    )
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short"},
        "source_scope": "project",
        "cwd": str(workspace_dir),
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
            "codex",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    "strict_config",
    (
        'default_action = "require-reapproval"\napproval_wait_timeout_seconds = 0\n',
        'approval_wait_timeout_seconds = 0\n[harnesses.codex]\ndefault_action = "require-reapproval"\n',
    ),
    ids=("global", "harness"),
)
def test_guard_hook_codex_strict_default_still_denies_destructive_shell_command(
    strict_config,
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", strict_config)
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status --short && rm -rf ./build"},
        "source_scope": "project",
        "cwd": str(workspace_dir),
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
            "codex",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "destructive shell command" in payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_guard_hook_codex_blocks_github_token_substitution_command(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    safe_event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": (
                """GH_TOKEN=$(gh auth token) node -e "const token = process.env.GH_TOKEN; """
                """const query = 'mutation($tid:ID!){resolveReviewThread(input:{threadId:$tid})"""
                """{thread{id isResolved}}}'; console.log(Boolean(token) && query.length > 0)" """
            ),
        },
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(safe_event)))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    output = capsys.readouterr().out
    pending = GuardStore(home_dir).list_approval_requests(limit=10)

    assert rc == 0
    payload = json.loads(output)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "GitHub secret mutation command" in payload["hookSpecificOutput"]["permissionDecisionReason"]
    assert len(GuardStore(home_dir).list_receipts(limit=10)) == 1
    assert pending == []


def test_guard_hook_codex_current_block_is_terminal_before_native_deny_output(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 0\n")
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _guard_home: (_ for _ in ()).throw(RuntimeError("daemon unavailable")),
    )
    blocked_event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo MALICIOUS > dangerous-marker.json"},
        "policy_action": "block",
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()
    pending = GuardStore(home_dir).list_approval_requests(limit=10)

    payload = json.loads(captured.out)
    assert rc == 0
    assert captured.err == ""
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert pending == []
    reason = str(payload["hookSpecificOutput"]["permissionDecisionReason"])
    assert "terminal policy decision" in reason
    assert "Browser approval cannot override it" in reason
    assert "/requests/" not in reason
    assert "Approve it in HOL Guard, then retry." not in reason


def test_guard_hook_codex_pretooluse_current_block_is_terminal_without_browser_approval(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 2\n")
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    store = GuardStore(home_dir)

    def unexpected_browser_approval(*_args, **_kwargs):
        raise AssertionError("current block must not queue or wait for browser approval")

    monkeypatch.setattr(guard_commands_module, "schedule_guard_daemon_ensure", unexpected_browser_approval)
    monkeypatch.setattr(guard_commands_module, "wait_for_approval_requests", unexpected_browser_approval)
    blocked_event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo MALICIOUS > dangerous-marker.json"},
        "policy_action": "block",
        "source_scope": "project",
        "cwd": str(workspace_dir),
    }

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(blocked_event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    reason = str(payload["hookSpecificOutput"]["permissionDecisionReason"])
    assert rc == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert captured.err == ""
    assert store.list_approval_requests(limit=10) == []
    assert "terminal policy decision" in reason
    assert "Browser approval cannot override it" in reason
    assert "/requests/" not in reason
