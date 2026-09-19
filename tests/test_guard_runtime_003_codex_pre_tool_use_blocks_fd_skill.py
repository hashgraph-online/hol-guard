"""Runtime regression tests: codex pre tool use blocks fd skill."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
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
    def test_codex_pre_tool_use_blocks_fd_skill_docs_clustered_shell_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = "fd -a 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees -d 1 -Hx sh -c 'echo blocked' {}"
        event = {
            "event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
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
        assert output["policy_action"] == "block"
        assert "destructive shell command" in output["artifact_name"]

    def test_codex_pre_tool_use_blocks_fd_implicit_root_sed_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = "fd 'SKILL.md' -x sed -n '1,20p' {}"
        event = {
            "event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
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
        assert output["policy_action"] == "block"
        assert "destructive shell command" in output["artifact_name"]

    def test_codex_pre_tool_use_blocks_fd_skill_doc_symlink_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        ssh_dir = home_dir / ".ssh"
        ssh_dir.mkdir(parents=True)
        symlink_target = home_dir / ".codex" / "superpowers" / "skills" / "ssh-link"
        symlink_target.parent.mkdir(parents=True, exist_ok=True)
        symlink_target.symlink_to(ssh_dir, target_is_directory=True)
        command = "fd -a 'SKILL.md' ~/.codex/superpowers/skills/ssh-link -d 1 -x sed -n '1,20p' {}"
        event = {
            "event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
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
        assert output["policy_action"] == "block"
        assert "destructive shell command" in output["artifact_name"]

    def test_codex_pre_tool_use_blocks_fd_follow_symlink_descendant_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        ssh_dir = home_dir / ".ssh"
        ssh_dir.mkdir(parents=True)
        (ssh_dir / "id_rsa").write_text("private-key\n", encoding="utf-8")
        src_dir = workspace_dir / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "ssh-link").symlink_to(ssh_dir, target_is_directory=True)
        command = "fd -L 'id_rsa' src -x sed -n '1,20p' {}"
        event = {
            "event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
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
        assert output["policy_action"] == "block"
        assert output["approval_requests"] == []

    def test_codex_pre_tool_use_blocks_fd_search_path_sensitive_dir_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = "fd --search-path ~/.ssh 'SKILL.md' -x sed -n '1,20p' {}"
        event = {
            "event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
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
        assert output["policy_action"] == "block"
        assert "destructive shell command" in output["artifact_name"]
        assert output["approval_requests"] == []

    def test_codex_pre_tool_use_allows_fd_path_separator_skill_docs_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = (
            "fd --path-separator / 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees -d 1 -x sed -n '1,20p' {}"
        )
        event = {
            "event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
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

    def test_codex_pre_tool_use_allows_fd_type_shorthand_skill_docs(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = "fd -tx 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees"
        event = {
            "event": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
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

    def test_codex_post_tool_use_allows_fd_skill_docs_bounded_sed_output(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = (
            "fd -a 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees "
            "~/.codex/superpowers/skills/test-driven-development "
            "~/.codex/superpowers/skills/verification-before-completion "
            "-d 1 -x sed -n '1,180p' {}"
        )
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": (
                    "---\n"
                    "name: test-driven-development\n"
                    "description: Use before writing implementation code.\n"
                    "Never read `.env` files or expose secrets.\n"
                ),
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

    def test_codex_post_tool_use_allows_read_only_source_view_with_secret_like_output(
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
            "tool_input": {"command": ("sed -n '1,40p' __tests__/guard-connect-shell.test.tsx 2>/dev/null | head -40")},
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

    @pytest.mark.parametrize(
        "command",
        (
            "rg -n 'SMTP_TOKEN' src/example.ts; sed -n '1,20p' src/example.ts",
            "nl -ba src/example.ts | sed -n '1,20p'",
            "wc -l src/example.ts; sed -n '1,20p' src/example.ts",
            ("yq '.jobs.build.steps[] | select(.name == \"Compute publish version\")' .github/workflows/publish.yml"),
        ),
    )
    def test_codex_post_tool_use_allows_common_read_only_source_inspection(
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
        _write_text(
            workspace_dir / ".github" / "workflows" / "publish.yml",
            "jobs:\n  build:\n    steps:\n      - name: Compute publish version\n",
        )
        event = {
            "event": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "const SMTP_TOKEN = process.env.SMTP_TOKEN;\n"},
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
