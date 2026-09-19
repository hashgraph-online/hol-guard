"""Runtime regression tests: codex prompt request queue shows original prompt."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardStore,
    guard_commands_module,
    io,
    json,
    main,
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
    def test_codex_prompt_request_queue_shows_original_prompt(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(workspace_dir / ".authrc", "fake_credential=canary\n")
        event = {
            "event": "UserPromptSubmit",
            "prompt": "read .authrc",
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
        approval_requests = GuardStore(home_dir).list_approval_requests(limit=10)

        assert rc == 0
        assert output["decision"] == "block"
        assert output["continue"] is False
        assert output["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
        assert "http://127.0.0.1:4455/requests/" in output["reason"]
        assert approval_requests[0]["approval_url"].startswith("http://127.0.0.1:4455/requests/")
        assert approval_requests[0]["approval_url"] in output["reason"]
        assert approval_requests[0]["launch_target"] == "Codex prompt for `.authrc`: read .authrc"
        assert approval_requests[0]["action_envelope_json"]["action_type"] == "prompt"
        assert approval_requests[0]["action_envelope_json"]["prompt_excerpt"] == "read .authrc"

    def test_codex_prompt_display_sanitizes_common_home_paths(self) -> None:
        display = guard_commands_module._codex_prompt_display_text(
            r"Read /Users/alice/.npmrc, /home/bob/.env, and C:\Users\carol\.ssh\id_rsa with API_KEY=sk-test"
        )

        assert "alice" not in display
        assert "bob" not in display
        assert "carol" not in display
        assert "sk-test" not in display
        assert "API_KEY=[redacted]" in display
        assert "/Users/" not in display
        assert "/home/" not in display
        assert r"C:\Users" not in display

    def test_codex_post_tool_use_allows_read_only_source_search_with_secret_like_output(
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
            "tool_input": {
                "command": (
                    'rg -n "Maileroo|maileroo|fetch\\(|transporter|sendMail|EMAIL_|SMTP_|MAIL" '
                    "src/lib/email-service.ts src/lib/admin-email.ts src/lib/auth-email-delivery.ts "
                    "workers/scripts -S"
                )
            },
            "tool_response": {
                "stdout": "src/lib/email-service.ts:12:const SMTP_TOKEN = process.env.SMTP_TOKEN",
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

    def test_pi_post_tool_use_allows_native_grep_of_external_source_tree(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = home_dir / "workspace"
        external_source_dir = tmp_path / "codex_plugin_scanner_full"
        external_source_dir.mkdir(parents=True)
        _build_guard_fixture(home_dir, workspace_dir)
        event = {
            "event": "PostToolUse",
            "tool_name": "grep",
            "tool_input": {
                "pattern": (
                    "def.*hook.*handler|def.*serve|def.*v1.*hooks|class.*Daemon|class.*HookServer|def.*handle_post"
                ),
                "path": str(external_source_dir),
            },
            "stdout": (
                "guard/server.py:42:def handle_post(self):\n"
                "guard/server.py:43:    daemon_auth_token = self.headers.get('X-Guard-Token')\n"
            ),
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
                "pi",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["recorded"] is True
        assert "approval_requests" not in output

    def test_pi_post_tool_use_blocks_private_key_from_external_source_tree(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        home_dir = tmp_path / "home"
        workspace_dir = home_dir / "workspace"
        external_source_dir = tmp_path / "source"
        external_source_dir.mkdir(parents=True)
        _build_guard_fixture(home_dir, workspace_dir)
        private_key_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode("ascii")
        )
        event = {
            "event": "PostToolUse",
            "tool_name": "grep",
            "tool_input": {"pattern": "PRIVATE KEY", "path": str(external_source_dir)},
            "stdout": private_key_pem,
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
                "pi",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["approval_requests"]
        assert "tool output contains credential-looking material" in output["risk_signals"]

    def test_codex_post_tool_use_allows_read_only_constants_source_search_with_fixture_output(
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
            "tool_input": {
                "command": (
                    'rg -n "guardLead|GOOGLE_ADS_CONVERSION|Dbd2|AW-175|send_to|conversion" '
                    "__tests__ src constants scripts/guard-tracking -g '*.ts' -g '*.tsx'"
                )
            },
            "tool_response": {
                "stdout": (
                    "__tests__/ayet-adapter.test.ts:118:"
                    "'https://example.test/offers?apiKey=static-key&conversion_type%5B%5D=cpe'\n"
                    "constants/analytics.ts:3:"
                    "export const DEFAULT_GUARD_GOOGLE_ADS_CONVERSION_ID = 'AW-17512816237';\n"
                    "src/lib/analytics-client.ts:1322:"
                    "send_to: `${GOOGLE_ADS_CONVERSION_ID}/${config.label}`,\n"
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

    def test_codex_pre_tool_use_allows_fd_skill_docs_bounded_sed_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        process_home_dir = tmp_path / "process-home"
        _build_guard_fixture(home_dir, workspace_dir)
        process_home_dir.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(process_home_dir))
        command = (
            "fd -a 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees "
            "~/.codex/superpowers/skills/test-driven-development "
            "~/.codex/superpowers/skills/verification-before-completion "
            "-d 1 -x sed -n '1,180p' {}"
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
        assert output["policy_action"] == "warn"
        assert "approval_requests" not in output

    def test_codex_pre_tool_use_blocks_fd_skill_docs_mutating_sed_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = "fd -a 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees -d 1 -x sed -i '1,180p' {}"
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

    def test_codex_pre_tool_use_blocks_fd_skill_docs_metachar_sed_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = "fd -a 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees -d 1 -x 'sed;rm' -n '1,180p' {}"
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

    def test_codex_pre_tool_use_blocks_fd_skill_docs_compact_shell_exec(
        self,
        monkeypatch,
        tmp_path,
        capsys,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        command = "fd -a 'SKILL.md' ~/.codex/superpowers/skills/using-git-worktrees -d 1 -xsh -c 'echo blocked' {}"
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
