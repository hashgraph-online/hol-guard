"""Runtime regression tests: codex post tool use asks for local."""

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
        ("command", "stdout"),
        [
            ("cat .env", "OPENAI_API_KEY=" + "sk-" + "A" * 32 + "\n"),
            ("cat .npmrc", "//registry.npmjs.org/:_authToken=" + "n" * 36 + "\n"),
        ],
    )
    def test_codex_post_tool_use_asks_for_local_secret_file_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
        command,
        stdout,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": stdout},
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
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["continue"] is True
        assert "credential-looking output" in output["stopReason"]

    def test_codex_post_tool_use_queues_secret_family_copy_for_local_secret_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        raw_secret = "sk-" + "A" * 32
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat .env"},
            "tool_response": {"stdout": f"OPENAI_API_KEY={raw_secret}\n"},
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
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)
        rendered = json.dumps(output)
        approval = output["approval_requests"][0]

        assert rc == 1
        assert "local secrets" in approval["risk_summary"].lower()
        assert ".env file" in approval["risk_summary"]
        assert raw_secret not in rendered
        assert "credential-looking output" not in approval["risk_summary"].lower()

    @pytest.mark.parametrize(
        "command",
        [
            "python -c \"print(open('.env').read())\"",
            "node -e \"require('fs').readFileSync('.env', 'utf8')\"",
        ],
    )
    def test_codex_post_tool_use_asks_for_inline_interpreter_local_secret_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
        command,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "token=definitely-invalid\n"},
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
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["continue"] is True
        assert "credential-looking output" in output["stopReason"]

    @pytest.mark.parametrize(
        "command",
        [
            "cat secrets.json",
            "head -40 config/secrets.yaml",
            "cat src/secret",
        ],
    )
    def test_codex_post_tool_use_does_not_skip_secret_like_source_views(
        self,
        monkeypatch,
        tmp_path,
        capsys,
        command,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "token=definitely-invalid\n"},
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
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["continue"] is True
        assert "credential-looking output" in output["stopReason"]

    def test_codex_post_tool_helpers_treat_env_ignore_environment_with_shell_expansion_as_local_secret_read(
        self,
        tmp_path,
    ) -> None:
        command = "env -i OPENAI_API_KEY=$OPENAI_API_KEY | grep OPENAI_API_KEY"

        assert guard_commands_module._codex_command_reads_environment_pipeline(command) is True
        assert guard_commands_module._codex_command_may_read_local_content(
            command,
            cwd=tmp_path,
        )

    def test_codex_post_tool_use_detects_url_looking_local_secret_paths(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        local_secret = workspace_dir / "https:" / "example.test" / ".env"
        _write_text(local_secret, "OPENAI_API_KEY=token=definitely-invalid\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "python -c \"print(open('https://example.test/.env').read())\""},
            "tool_response": {"stdout": "token=definitely-invalid\n"},
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
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["continue"] is True
        assert "credential-looking output" in output["stopReason"]

    def test_codex_url_looking_local_path_does_not_escape_workspace(self, tmp_path) -> None:
        outside_secret = tmp_path.parent / f"{tmp_path.name}-outside" / ".env"
        outside_secret.parent.mkdir(parents=True)
        outside_secret.write_text("OPENAI_API_KEY=token=definitely-invalid\n", encoding="utf-8")

        matches = guard_commands_module._codex_sensitive_path_matches_in_text(
            f"python -c \"print(open('https://example.test/../../{outside_secret.parent.name}/.env').read())\"",
            cwd=tmp_path,
        )

        assert matches == []

    def test_codex_post_tool_use_allows_short_option_value_payloads(
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
            "tool_input": {"command": "rg -gLICENSE TOKEN src"},
            "tool_response": {
                "stdout": "src/config.ts:1:const auth_token = process.env.TOKEN",
            },
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

    def test_codex_post_tool_use_allows_double_dash_terminated_literal_pattern(
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
            "tool_input": {"command": "rg -- --follow src"},
            "tool_response": {
                "stdout": "src/config.ts:1:const auth_token = process.env.TOKEN",
            },
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

    @pytest.mark.parametrize(
        "command",
        (
            "rg --follow TOKEN src",
            "rg -L TOKEN src",
            "grep -R TOKEN src",
        ),
    )
    def test_codex_post_tool_use_blocks_symlink_following_source_search_flags(
        self,
        monkeypatch,
        tmp_path,
        capsys,
        command: str,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        secret_file = home_dir / ".aws" / "credentials"
        _write_text(secret_file, "auth_token=outside-secret\n")
        src_dir = workspace_dir / "src"
        src_dir.mkdir()
        (src_dir / "config.ts").symlink_to(secret_file)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": "src/config.ts:1:auth_token=outside-secret",
            },
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
        assert output["approval_requests"]
