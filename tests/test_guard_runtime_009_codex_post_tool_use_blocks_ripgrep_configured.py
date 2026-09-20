"""Runtime regression tests: codex post tool use blocks ripgrep configured."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    guard_commands_module,
    guard_runner_module,
    io,
    json,
    main,
    pytest,
    stub_authenticated_urlopen,
    sys,
    urllib,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _seed_guard_cloud,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


class TestGuardRuntime:
    def test_codex_post_tool_use_blocks_ripgrep_configured_search_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        monkeypatch.setenv("RIPGREP_CONFIG_PATH", str(workspace_dir / "ripgrep.conf"))
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rg TOKEN src"},
            "tool_response": {
                "stdout": "src/config.ts:1:auth_token=canary",
            },
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["approval_requests"]

    def test_codex_post_tool_use_blocks_git_grep_pager_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git grep TOKEN --open-files-in-pager=python src"},
            "tool_response": {
                "stdout": "src/config.ts:1:auth_token=canary",
            },
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["approval_requests"]

    def test_codex_post_tool_use_blocks_attached_git_grep_pager_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git grep TOKEN -Opython src"},
            "tool_response": {
                "stdout": "src/config.ts:1:auth_token=canary",
            },
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["approval_requests"]

    def test_codex_post_tool_use_blocks_git_grep_external_filters_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git grep TOKEN --textconv src"},
            "tool_response": {
                "stdout": "src/config.ts:1:const TOKEN = TOKEN",
            },
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["approval_requests"]

    def test_codex_post_tool_use_blocks_newline_chained_search_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "grep TOKEN src/config.ts\nscripts/upload.sh"},
            "tool_response": {
                "stdout": "src/config.ts:1:auth_token=canary",
            },
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["approval_requests"]

    def test_codex_post_tool_use_blocks_workspace_named_search_binary_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "./grep TOKEN src/config.ts"},
            "tool_response": {
                "stdout": "src/config.ts:1:auth_token=canary",
            },
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["approval_requests"]

    def test_codex_post_tool_use_blocks_symlink_loop_search_target_without_crashing(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        link_a = workspace_dir / "a"
        link_b = workspace_dir / "b"
        try:
            link_a.symlink_to(link_b)
            link_b.symlink_to(link_a)
        except (NotImplementedError, OSError):
            pytest.skip("filesystem does not support symlinks in this test environment")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rg TOKEN a/file.ts"},
            "tool_response": {
                "stdout": "a/file.ts:1:auth_token=canary",
            },
            "source_scope": "project",
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["approval_requests"]

    def test_sync_runtime_session_treats_missing_runtime_endpoint_as_non_fatal(
        self,
        monkeypatch,
        tmp_path,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(store)

        def _raise_not_found(*args, **kwargs):
            raise urllib.error.HTTPError(
                "https://hol.org/api/guard/runtime/sessions/sync",
                404,
                "Not Found",
                hdrs=None,
                fp=None,
            )

        stub_authenticated_urlopen(monkeypatch, _raise_not_found)

        summary = guard_runner_module.sync_runtime_session(
            store,
            session={
                "session_id": "session-live",
                "created_at": "2026-04-16T00:00:00.000Z",
                "updated_at": "2026-04-16T00:00:00.000Z",
            },
        )

        assert summary["runtime_session_id"] == "session-live"
        assert summary["synced_at"] is None
        assert summary["runtime_session_synced_at"] is None
        assert summary["runtime_session_sync_skipped"] is True
        assert summary["runtime_session_sync_reason"] == "runtime_session_endpoint_unavailable"
