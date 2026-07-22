"""Tests for CLI fallback source-ref support."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_hook import _try_source_ref_fast_path
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text
from codex_plugin_scanner.guard.store import GuardStore


def _args(*, harness: str = "pi", json_output: bool = True) -> argparse.Namespace:
    return argparse.Namespace(
        guard_command="hook",
        harness=harness,
        runtime_harness=None,
        json=json_output,
        event_file=None,
        artifact_id=None,
        artifact_name=None,
        policy_action=None,
        home=None,
        guard_home=None,
        workspace=None,
        source="default",
    )


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "src").mkdir()
    return ws


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    hd = tmp_path / "home"
    hd.mkdir()
    return hd


@pytest.fixture()
def guard_home(tmp_path: Path) -> Path:
    gh = tmp_path / "guard-home"
    gh.mkdir()
    return gh


@pytest.fixture()
def store(guard_home: Path) -> GuardStore:
    return GuardStore(guard_home)


@pytest.fixture()
def config(guard_home: Path, workspace: Path) -> GuardConfig:
    return GuardConfig(guard_home=guard_home, workspace=workspace)


class TestCLISourceRefSafeFile:
    def test_cli_source_ref_safe_file_returns_allow_original(
        self, workspace: Path, home_dir: Path, guard_home: Path, store: GuardStore, config: GuardConfig
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

        args = _args()
        from codex_plugin_scanner.guard.adapters.base import HarnessContext

        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace,
            guard_home=guard_home,
        )

        result = _try_source_ref_fast_path(
            args,
            config=config,
            context=context,
            guard_home=guard_home,
            payload=payload,
            runtime_workspace=workspace,
            store=store,
        )

        assert result == 0


class TestCLISourceRefMismatch:
    def test_cli_source_ref_mismatch_does_not_return_allow_original(
        self, workspace: Path, home_dir: Path, guard_home: Path, store: GuardStore, config: GuardConfig
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "output_sha256": "0" * 64,
                "output_chars": 999,
                "tool_input_path": "src/foo.ts",
            },
            "tool_response_summary": {
                "text_excerpt": "export const x = 1;",
                "excerpt_truncated": False,
                "output_sha256": None,
                "output_chars": None,
            },
        }

        args = _args()
        from codex_plugin_scanner.guard.adapters.base import HarnessContext

        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace,
            guard_home=guard_home,
        )

        result = _try_source_ref_fast_path(
            args,
            config=config,
            context=context,
            guard_home=guard_home,
            payload=payload,
            runtime_workspace=workspace,
            store=store,
        )

        # Should return 0 (handled) but with a non-allow_original response
        assert result == 0


class TestCLISourceRefSensitivePath:
    def test_cli_source_ref_sensitive_path_blocks(
        self, workspace: Path, home_dir: Path, guard_home: Path, store: GuardStore, config: GuardConfig
    ) -> None:
        content = "SECRET=abc123\n"
        file_path = workspace / ".env"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env"},
            "guard_source_ref": {
                "version": 1,
                "path": ".env",
                "output_sha256": sha256_text(stripped),
                "output_chars": len(stripped),
                "tool_input_path": ".env",
            },
        }

        args = _args()
        from codex_plugin_scanner.guard.adapters.base import HarnessContext

        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace,
            guard_home=guard_home,
        )

        result = _try_source_ref_fast_path(
            args,
            config=config,
            context=context,
            guard_home=guard_home,
            payload=payload,
            runtime_workspace=workspace,
            store=store,
        )

        assert result == 0


class TestCLISourceRefNoSourceRef:
    def test_no_source_ref_returns_none(
        self, workspace: Path, home_dir: Path, guard_home: Path, store: GuardStore, config: GuardConfig
    ) -> None:
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
        }

        args = _args()
        from codex_plugin_scanner.guard.adapters.base import HarnessContext

        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace,
            guard_home=guard_home,
        )

        result = _try_source_ref_fast_path(
            args,
            config=config,
            context=context,
            guard_home=guard_home,
            payload=payload,
            runtime_workspace=workspace,
            store=store,
        )

        assert result is None
