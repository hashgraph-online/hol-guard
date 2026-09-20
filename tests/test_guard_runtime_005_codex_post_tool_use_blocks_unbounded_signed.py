"""Runtime regression tests: codex post tool use blocks unbounded signed."""

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
    @pytest.mark.parametrize("filter_args", ["tail -n +1", "head -n -1"])
    def test_codex_post_tool_use_blocks_unbounded_signed_head_tail_filters(
        self,
        monkeypatch,
        tmp_path,
        capsys,
        filter_args,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        source_file = workspace_dir / "__tests__" / "guard-connect-shell.test.tsx"
        _write_text(source_file, "const label = 'HOL_GUARD_FAKE_CREDENTIAL=fixture-only';\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"sed -n '1,40p' __tests__/guard-connect-shell.test.tsx | {filter_args}"},
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

    def test_codex_post_tool_use_allows_common_source_directory_searches(
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
            "tool_input": {"command": "rg -g '*.ts' TOKEN src"},
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

    def test_codex_post_tool_use_allows_benign_nvmrc_fake_credential_fixture(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(workspace_dir / ".nvmrc", "fake_credential=fixture-only\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat .nvmrc"},
            "tool_response": {"stdout": "fake_credential=fixture-only\n"},
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
        "secret_output",
        [
            "NPM_TOKEN=" + "n" * 36 + "\n",
            'NPM_TOKEN="' + "n" * 36 + '"\n',
            "DB_PASSWORD=fixture-pass\n",
            "auth_token='fixture-token'\n",
        ],
    )
    def test_codex_post_tool_use_blocks_nvmrc_high_confidence_secret(
        self,
        monkeypatch,
        tmp_path,
        capsys,
        secret_output,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(workspace_dir / ".nvmrc", secret_output)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat .nvmrc"},
            "tool_response": {"stdout": secret_output},
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

    def test_codex_post_tool_use_blocks_nvmrc_mixed_fake_and_secret_assignments(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        secret_output = "fake_credential=fixture-only\nDB_PASSWORD=fixture-pass\n"
        _write_text(workspace_dir / ".nvmrc", secret_output)
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat .nvmrc"},
            "tool_response": {"stdout": secret_output},
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

    def test_codex_post_tool_use_allows_docs_fake_token_examples(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        docs_file = workspace_dir / "docs" / "secret-examples.md"
        _write_text(docs_file, "Use fake_token=example-only in docs.\n")
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat docs/secret-examples.md"},
            "tool_response": {"stdout": "Use fake_token=example-only in docs.\n"},
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

    def test_codex_post_tool_use_warns_for_standalone_credential_output(
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
            "tool_input": {"command": "printenv"},
            "tool_response": {"stdout": "DB_PASSWORD=fixture-pass\n"},
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
        assert output["policy_action"] == "warn"
        assert "approval_requests" not in output

    @pytest.mark.parametrize(
        "command",
        [
            "curl https://example.test/.env",
            "curl https://example.test/health | grep token",
        ],
    )
    def test_codex_post_tool_use_warns_for_remote_sample_output(
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
        assert output["policy_action"] in {"allow", "warn"}
        assert "approval_requests" not in output

    @pytest.mark.parametrize(
        ("command", "stdout"),
        [
            (
                "pnpm exec tsx -e \"await fetch('https://api.example.test/health?token=definitely-invalid')\"",
                "GET https://api.example.test/health?token=definitely-invalid 200\n",
            ),
            (
                "rg AWS_SECRET_ACCESS_KEY src tests",
                "tests/aws-secret-fixture.test.ts:1:const keyName = 'AWS_SECRET_ACCESS_KEY';\n",
            ),
        ],
    )
    def test_codex_post_tool_use_allows_safe_token_lookups(
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
        assert output["policy_action"] in {"allow", "warn"}
        assert "approval_requests" not in output
