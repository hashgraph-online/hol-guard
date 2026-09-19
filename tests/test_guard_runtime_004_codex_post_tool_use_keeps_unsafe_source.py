"""Runtime regression tests: codex post tool use keeps unsafe source."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    guard_commands_module,
    io,
    json,
    main,
    pytest,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


class TestGuardRuntime:
    @pytest.mark.parametrize(
        "command",
        (
            "sed -n '1,20p' src/example.ts; rm src/example.ts",
            "nl -ba .env",
        ),
    )
    def test_codex_post_tool_use_keeps_unsafe_source_inspection_guarded(
        self,
        command,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(workspace_dir / "src" / "example.ts", "const SMTP_TOKEN = process.env.SMTP_TOKEN;\n")
        _write_text(workspace_dir / ".github" / "workflows" / "publish.yml", "jobs: {}\n")
        _write_text(workspace_dir / ".env", "API_TOKEN=fixture-only\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "API_TOKEN=fixture-only\n"},
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
                "codex",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["artifact_type"] == "tool_action_request"
        assert output["policy_action"] in {"block", "require-reapproval"}
        assert output["approval_requests"]

    def test_codex_post_tool_use_allows_absolute_source_view_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        source_file = workspace_dir / "__tests__" / "guard-connect-shell.test.tsx"
        _write_text(source_file, "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"sed -n '1,40p' {source_file}"},
            "tool_response": {"stdout": "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n"},
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
                "codex",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recorded"] is True
        assert "approval_requests" not in output

    def test_codex_post_tool_use_allows_multi_range_test_source_view_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        source_file = workspace_dir / "__tests__" / "analytics-client.test.ts"
        _write_text(
            source_file,
            "const analyticsApiKey = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n",
        )
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sed -n '206,224p;1728,1744p' __tests__/analytics-client.test.ts"},
            "tool_response": {"stdout": "const analyticsApiKey = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n"},
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
                "codex",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recorded"] is True
        assert "approval_requests" not in output

    def test_codex_post_tool_use_blocks_absolute_source_view_outside_workspace_with_secret_like_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        outside_file = tmp_path / "outside" / "src" / "config.ts"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(outside_file, "const token = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"sed -n '1,40p' {outside_file}"},
            "tool_response": {"stdout": "const token = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n"},
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

    def test_codex_post_tool_use_blocks_hidden_file_view_with_secret_like_output(
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
            "tool_input": {"command": "sed -n '1,40p' .npmrc 2>/dev/null | head -40"},
            "tool_response": {"stdout": "token = fixture-only\n"},
            "source_scope": "project",
        }
        monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
        )
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
        assert payload["continue"] is True
        assert "credential-looking output" in payload["stopReason"]

    @pytest.mark.parametrize(
        "command",
        [
            "./sed -n '1,40p' __tests__/guard-connect-shell.test.tsx",
            "sed -n '1,40p' __tests__/guard-connect-shell.test.tsx | ./head -40",
        ],
    )
    def test_codex_post_tool_use_blocks_path_qualified_read_only_binaries(
        self,
        monkeypatch,
        tmp_path,
        capsys,
        command,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        source_file = workspace_dir / "__tests__" / "guard-connect-shell.test.tsx"
        _write_text(source_file, "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n"},
            "source_scope": "project",
        }
        monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
        )
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
        assert payload["continue"] is True
        assert "credential-looking output" in payload["stopReason"]

    def test_codex_post_tool_use_blocks_parameter_expansion_source_view(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        source_file = workspace_dir / "__tests__" / "guard-connect-shell.test.tsx"
        _write_text(source_file, "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sed -n '1,40p' ${GUARD_SOURCE_FILE}.tsx | head -40"},
            "tool_response": {"stdout": "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n"},
            "source_scope": "project",
        }
        monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
        )
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
        assert payload["continue"] is True
        assert "credential-looking output" in payload["stopReason"]

    def test_codex_post_tool_use_blocks_unbraced_env_expansion_source_view(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        source_file = workspace_dir / "__tests__" / "guard-connect-shell.test.tsx"
        _write_text(source_file, "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sed -n '1,40p' $GUARD_SOURCE_FILE.tsx | head -40"},
            "tool_response": {"stdout": "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n"},
            "source_scope": "project",
        }
        monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
        monkeypatch.setattr(
            guard_commands_module,
            "schedule_guard_daemon_ensure",
            lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
        )
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
        assert payload["continue"] is True
        assert "credential-looking output" in payload["stopReason"]

    def test_codex_post_tool_use_allows_quoted_greater_than_search_pipeline(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        source_file = workspace_dir / "__tests__" / "guard-connect-shell.test.tsx"
        _write_text(source_file, "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rg '>' __tests__/guard-connect-shell.test.tsx | head -40"},
            "tool_response": {"stdout": "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n"},
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
                "codex",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recorded"] is True
        assert "approval_requests" not in output
