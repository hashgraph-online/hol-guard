"""Tests for the daemon hook worker."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker, HookWorkerUnsupported
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture()
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "src").mkdir()
    (ws / "docs").mkdir()
    return ws


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    hd = tmp_path / "home"
    hd.mkdir()
    return hd


@pytest.fixture()
def guard_home(tmp_path: Path) -> Path:
    gh = tmp_path / "guard-home"
    gh.mkdir(exist_ok=True)
    return gh


@pytest.fixture()
def worker(store: GuardStore) -> HookWorker:
    return HookWorker(store=store)


class TestHookWorkerReviewSafeSourceRef:
    def test_safe_source_ref_returns_allow_original(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "output_sha256": sha256_text(stripped),
                "output_chars": len(stripped),
                "tool_input_path": "src/foo.ts",
            },
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"
        assert result["reason_code"] == "source_full_scan_allow"
        assert "reviewed_output_sha256" in result


class TestHookWorkerDoesNotCallRunGuardCommand:
    def test_worker_path_does_not_call_run_guard_command(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path, monkeypatch
    ) -> None:
        # Monkeypatch run_guard_command to fail if called.
        import codex_plugin_scanner.guard.cli.commands as cli_commands

        def fail_if_called(*args, **kwargs):
            raise AssertionError("run_guard_command should not be called in worker path")

        monkeypatch.setattr(cli_commands, "run_guard_command", fail_if_called)

        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "output_sha256": sha256_text(stripped),
                "output_chars": len(stripped),
                "tool_input_path": "src/foo.ts",
            },
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "allow"


class TestHookWorkerMalformedPayload:
    def test_malformed_source_ref_fails_safe(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "guard_source_ref": {
                "version": "not-an-int",
                "path": 123,
            },
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        # Invalid source ref version should not allow original
        assert result["model_output_action"] != "allow_original"

    def test_posttooluse_without_source_ref_uses_output_scan(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """PostToolUse without guard_source_ref uses server-side output scanning.

        The fast path now handles PostToolUse for all harnesses by scanning
        the full tool output from the payload. No client-side guard_source_ref
        is required.
        """
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "safe file content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        # Safe output should be allowed
        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"


class TestHookWorkerException:
    def test_worker_exception_returns_deny_block(
        self, store: GuardStore, workspace: Path, home_dir: Path, guard_home: Path, monkeypatch
    ) -> None:
        # Create a worker with a broken engine inner method.
        # The engine's review() catches exceptions and returns deny/block.
        worker = HookWorker(store=store)

        def broken_review_inner(request, *, start):
            raise RuntimeError("engine crashed")

        monkeypatch.setattr(worker.engine, "_review_inner", broken_review_inner)

        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "output_sha256": "0" * 64,
                "output_chars": 10,
            },
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        # The engine's exception handler returns deny/block
        assert result["decision"] == "deny"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "engine_exception"


class TestHookWorkerNonPostTool:
    def test_pre_tool_use_raises_unsupported(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """PreToolUse must fall back to legacy CLI for policy/permission checks.

        The fast path only handles PostToolUse with guard_source_ref.
        PreToolUse must raise HookWorkerUnsupported so the server falls
        through to the legacy CLI path, which performs the full policy
        evaluation, permission checks, and approval-center queueing.
        """
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
        }

        with pytest.raises(HookWorkerUnsupported):
            worker.review_http_payload(
                payload=payload,
                params={},
                default_harness="pi",
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )
class TestHookWorkerAllHarnessFallback:
    """Tests proving all harnesses without client-side guard_source_ref
    use the server-side output scanning fast path.

    All harnesses (claude-code, codex, grok, zcode) now get the fast path
    for PostToolUse file reads. The engine extracts the full tool output
    from the payload, scans it for secrets, and returns allow_original
    if clean.
    """

    def test_claude_code_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Claude Code PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "     1\tfile content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["model_output_action"] == "allow_original"
        assert result["decision"] == "allow"

    def test_codex_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Codex PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "stdout": "file content",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="codex",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["model_output_action"] == "allow_original"
        assert result["decision"] == "allow"

    def test_grok_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Grok PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "file content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="grok",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["model_output_action"] == "allow_original"
        assert result["decision"] == "allow"

    def test_zcode_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """ZCode PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "file content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="zcode",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["model_output_action"] == "allow_original"
        assert result["decision"] == "allow"

    def test_pi_with_source_ref_still_works(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Pi with client-side guard_source_ref uses the fast path (not legacy)."""
        content = 'export const x = 1;\n'
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        client_hash = sha256_text(content)
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "tool_input_path": "src/foo.ts",
                "output_sha256": client_hash,
                "output_chars": len(content),
            },
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["model_output_action"] == "allow_original"
        assert result["reviewed_output_sha256"] == client_hash


class TestHookWorkerOutputScanning:
    """Tests for the server-side output scanning fast path."""

    def test_secret_in_output_blocks(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Output containing a secret pattern is blocked."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/config.ts"},
            "tool_response": [
                {"type": "text", "text": "api_key = 'sk-1234567890abcdef1234567890abcdef'\n"}
            ],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "deny"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_non_file_read_falls_back(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Non-file-read PostToolUse (e.g. shell command) falls back to standard path."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "stdout": "hello",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        # Shell commands go through _review_standard which scans the excerpt
        assert result["model_output_action"] != "allow_original"

    def test_empty_output_falls_back(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """PostToolUse with no extractable output text falls back to standard path."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        # No output to review — should block conservatively
        assert result["decision"] == "deny"
        assert result["model_output_action"] == "block"

    def test_codex_stdout_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Codex PostToolUse with stdout output uses output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "read",
            "tool_input": {"file_path": "src/foo.ts"},
            "stdout": "export const hello = 'world';\n",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="codex",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["model_output_action"] == "allow_original"
        assert result["decision"] == "allow"
