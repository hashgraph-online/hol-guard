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

    def test_missing_output_summary_raises_unsupported(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """PostToolUse without guard_source_ref must fall back to legacy CLI.

        The fast path only handles PostToolUse with guard_source_ref.
        Without a source ref, the worker raises HookWorkerUnsupported so
        the server falls through to the legacy CLI path, preserving
        existing policy/permission checks.
        """
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
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
    correctly fall through to legacy CLI (HookWorkerUnsupported).

    Server-side synthesis was considered but rejected because harness
    output includes formatting (line numbers, banners) that won't match
    the raw file hash. The fast path requires exact hash match between
    output text and file content (see output_equivalent() in
    hook_source_read.py). Only client-side generation (like Pi's
    digestOutputText) can produce a matching hash.

    These tests prove the fallback is safe for all harnesses.
    """

    def test_claude_code_posttooluse_without_source_ref_falls_back(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Claude Code PostToolUse without guard_source_ref falls back to legacy."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "     1\tfile content"}],
        }

        with pytest.raises(HookWorkerUnsupported):
            worker.review_http_payload(
                payload=payload,
                params={},
                default_harness="claude-code",
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )

    def test_codex_posttooluse_without_source_ref_falls_back(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Codex PostToolUse without guard_source_ref falls back to legacy."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "stdout": "file content",
        }

        with pytest.raises(HookWorkerUnsupported):
            worker.review_http_payload(
                payload=payload,
                params={},
                default_harness="codex",
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )

    def test_grok_posttooluse_without_source_ref_falls_back(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Grok PostToolUse without guard_source_ref falls back to legacy."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "file content"}],
        }

        with pytest.raises(HookWorkerUnsupported):
            worker.review_http_payload(
                payload=payload,
                params={},
                default_harness="grok",
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )

    def test_zcode_posttooluse_without_source_ref_falls_back(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """ZCode PostToolUse without guard_source_ref falls back to legacy."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "file content"}],
        }

        with pytest.raises(HookWorkerUnsupported):
            worker.review_http_payload(
                payload=payload,
                params={},
                default_harness="zcode",
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )

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
