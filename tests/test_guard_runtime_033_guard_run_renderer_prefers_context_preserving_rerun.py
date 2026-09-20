"""Runtime regression tests: guard run renderer prefers context preserving rerun."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardArtifact,
    GuardStore,
    HarnessDetection,
    apply_approval_resolution,
    argparse,
    guard_commands_module,
    guard_render_module,
    guard_runner_module,
    main,
    subprocess,
    threading,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _install_codex_native_hooks,
    _make_pinnable_harness_executable,
    _write_json,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_run_renderer_prefers_context_preserving_rerun_command():
    steps = guard_render_module._build_run_steps(
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "rerun_command": (
                "hol-guard run codex --home /guard-home --workspace /workspace "
                "--default-action warn --arg '--model gpt-5'"
            ),
        },
        blocked=True,
        dry_run=True,
    )

    assert steps[0]["command"] == (
        "hol-guard run codex --home /guard-home --workspace /workspace --default-action warn --arg '--model gpt-5'"
    )


def test_guard_rerun_command_preserves_run_context():
    command = guard_commands_module._guard_rerun_command(
        argparse.Namespace(
            harness="codex",
            home="/guard-home",
            guard_home=None,
            workspace="/workspace",
            default_action="warn",
            passthrough_args=["--model gpt-5"],
        )
    )

    assert command == (
        "hol-guard run codex --home /guard-home --workspace /workspace --default-action warn --arg '--model gpt-5'"
    )


def test_guard_rerun_command_uses_windows_safe_quoting(monkeypatch):
    monkeypatch.setattr(guard_commands_module.sys, "platform", "win32")
    command = guard_commands_module._guard_rerun_command(
        argparse.Namespace(
            harness="codex",
            home=r"C:\Guard Home",
            guard_home=None,
            workspace=r"C:\Workspace Root",
            default_action="warn",
            passthrough_args=["--model gpt-5"],
        )
    )

    expected = subprocess.list2cmdline(
        [
            "hol-guard",
            "run",
            "codex",
            "--home",
            r"C:\Guard Home",
            "--workspace",
            r"C:\Workspace Root",
            "--default-action",
            "warn",
            "--arg",
            "--model gpt-5",
        ]
    )

    assert command == expected


def test_guard_diff_command_preserves_common_context():
    command = guard_commands_module._guard_diff_command(
        argparse.Namespace(
            harness="codex",
            home="/guard-home",
            guard_home=None,
            workspace="/workspace",
        )
    )

    assert command == "hol-guard diff codex --home /guard-home --workspace /workspace"


def test_guard_run_renderer_uses_context_preserving_diff_command():
    steps = guard_render_module._build_run_steps(
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "diff_command": "hol-guard diff codex --home /guard-home --workspace /workspace",
        },
        blocked=True,
        dry_run=True,
    )

    assert [step["command"] for step in steps] == [
        "hol-guard run codex",
        "hol-guard diff codex --home /guard-home --workspace /workspace",
    ]


def test_guard_run_renderer_uses_context_preserving_launch_command_for_clean_dry_runs():
    steps = guard_render_module._build_run_steps(
        {
            "harness": "codex",
            "dry_run": True,
            "rerun_command": (
                "hol-guard run codex --home /guard-home --workspace /workspace "
                "--default-action warn --arg '--model gpt-5'"
            ),
        },
        blocked=False,
        dry_run=True,
    )

    assert steps[0]["command"] == (
        "hol-guard run codex --home /guard-home --workspace /workspace --default-action warn --arg '--model gpt-5'"
    )


def test_guard_approvals_command_preserves_common_context():
    command = guard_commands_module._guard_approvals_command(
        argparse.Namespace(
            harness="codex",
            home="/guard-home",
            guard_home="/guard-db",
            workspace="/workspace",
        )
    )

    assert command == "hol-guard approvals --home /guard-home --guard-home /guard-db --workspace /workspace"


def test_guard_run_renderer_uses_context_preserving_approvals_command_for_blocked_launches():
    steps = guard_render_module._build_run_steps(
        {
            "harness": "codex",
            "approval_center_url": "http://127.0.0.1:4455",
            "approvals_command": "hol-guard approvals --home /guard-home --workspace /workspace",
            "review_hint": "Open the approval center and resolve the pending request.",
        },
        blocked=True,
        dry_run=False,
    )

    assert steps[0]["command"] == "hol-guard approvals --home /guard-home --workspace /workspace"


def test_guard_run_renderer_uses_approval_queue_for_blocked_dry_run_when_center_is_available():
    steps = guard_render_module._build_run_steps(
        {
            "harness": "codex",
            "blocked": True,
            "dry_run": True,
            "approval_center_url": "http://127.0.0.1:4455",
            "approvals_command": "hol-guard approvals --home /guard-home --workspace /workspace",
            "diff_command": "hol-guard diff codex --home /guard-home --workspace /workspace",
        },
        blocked=True,
        dry_run=True,
    )

    assert [step["command"] for step in steps] == [
        "hol-guard run codex",
        "hol-guard approvals --home /guard-home --workspace /workspace",
        "hol-guard diff codex --home /guard-home --workspace /workspace",
    ]


def test_guard_run_renderer_uses_rerun_command_when_blocked_launch_has_no_approval_queue():
    steps = guard_render_module._build_run_steps(
        {
            "harness": "codex",
            "approvals_command": "hol-guard approvals --home /guard-home --workspace /workspace",
            "rerun_command": "hol-guard run codex --home /guard-home --workspace /workspace",
            "review_hint": "Approve the interactive prompt, then retry the guarded command.",
        },
        blocked=True,
        dry_run=False,
    )

    assert steps[0]["command"] == "hol-guard run codex --home /guard-home --workspace /workspace"


def test_guard_run_headless_allow_persists_state_when_approval_center_is_available(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _make_pinnable_harness_executable(tmp_path, monkeypatch, "codex")
    _install_codex_native_hooks(home_dir, workspace_dir)
    safe_detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(
            str(home_dir / ".codex" / "config.toml"),
            str(workspace_dir / ".codex" / "config.toml"),
        ),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:global:global_tools",
                name="global_tools",
                harness="codex",
                artifact_type="configuration",
                source_scope="global",
                config_path=str(home_dir / ".codex" / "config.toml"),
            ),
            GuardArtifact(
                artifact_id="codex:project:workspace_skill",
                name="workspace_skill",
                harness="codex",
                artifact_type="configuration",
                source_scope="project",
                config_path=str(workspace_dir / ".codex" / "config.toml"),
            ),
        ),
    )
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: safe_detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    )

    rc = main(
        [
            "guard",
            "run",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--default-action",
            "allow",
        ]
    )
    output = capsys.readouterr().out
    store = GuardStore(home_dir)
    receipts = store.list_receipts(limit=10)
    snapshots = store.list_snapshots("codex")

    if rc == 127:
        assert len(receipts) == 2
        assert {
            "codex:global:global_tools",
            "codex:project:workspace_skill",
        } <= set(snapshots)
        return
    assert rc == 0
    assert "Launch allowed" in output
    assert len(receipts) == 2
    assert {
        "codex:global:global_tools",
        "codex:project:workspace_skill",
    } <= set(snapshots)


def test_guard_run_headless_waits_for_local_approval_and_resumes(tmp_path, capsys, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _make_pinnable_harness_executable(tmp_path, monkeypatch, "python")
    claude_executable = _make_pinnable_harness_executable(tmp_path, monkeypatch, "claude")
    _write_text(workspace_dir / "guard-pre.py", "pass\n")
    _write_json(
        workspace_dir / ".mcp.json",
        {"mcpServers": {"workspace-tools": {"command": str(claude_executable), "args": []}}},
    )
    _write_text(
        home_dir / "config.toml",
        'approval_wait_timeout_seconds = 8\ndefault_action = "review"\nchanged_hash_action = "review"\n',
    )

    store = GuardStore(home_dir)
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    )

    stop_resolver = threading.Event()
    observed_actions: list[str] = []

    def resolve_pending() -> None:
        while not stop_resolver.is_set():
            pending = store.list_approval_requests(limit=10)
            if pending:
                for request in pending:
                    observed_actions.append(str(request["policy_action"]))
                    apply_approval_resolution(
                        store=store,
                        request_id=str(request["request_id"]),
                        action="allow",
                        scope="artifact",
                        workspace=None,
                        reason="approved from test",
                    )
                if not store.list_approval_requests(limit=10):
                    return
            threading.Event().wait(0.03)

    worker = threading.Thread(target=resolve_pending, daemon=True)
    worker.start()

    rc = main(
        [
            "guard",
            "run",
            "claude-code",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
        ]
    )
    stop_resolver.set()
    worker.join(timeout=1.0)
    output = capsys.readouterr().out

    assert rc == 0
    assert "Launch allowed" in output
    assert "Approval received" in output
    assert observed_actions
    assert "review" in observed_actions
