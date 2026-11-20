"""Tests for runtime harness attribution (Cursor vs Claude Code hooks)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_harness_client as harness_client
from codex_plugin_scanner.guard.runtime import harness_attribution
from tests.conftest import guard_commands_module


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[str, dict[str, object]]]]:
    """Record what reaches the native runtime and answer as it would."""
    calls: list[tuple[str, dict[str, object]]] = []

    def answer(kind: str, args: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        if kind == "harness_adapter" and args.get("op") == "describe":
            # The cached adapter description the request environment reads; not an attribution question.
            return {"adapters": [], "env_names": ["CURSOR_VERSION"], "env_prefixes": []}
        calls.append((kind, dict(args)))
        return {"harness": "cursor", "env": {"HOL_GUARD_ORIGIN_HARNESS": "grok"}}

    # `describe` is cached per process; a description from another test must not leak in or out.
    harness_client.describe.cache_clear()
    monkeypatch.setattr("codex_plugin_scanner.guard.native_runner_authority.native_runner_authority", answer)
    yield calls
    harness_client.describe.cache_clear()


# The markers, the precedence, the parent walk and the origin stamp are the native runtime's
# (`adapters/harness_attribution_tests.rs`); these prove Python only passes facts in and returns the answer.


def test_environment_harness_passes_the_named_env_and_returns_the_answer(asked) -> None:
    env = {"CURSOR_VERSION": "2.0.0"}
    assert harness_attribution.resolve_environment_harness(env) == "cursor"
    assert asked == [("harness_attribution", {"op": "environment", "env": env})]


def test_environment_harness_defaults_to_the_markers_in_this_process(asked, monkeypatch) -> None:
    monkeypatch.setenv("CURSOR_VERSION", "2.0.0")
    monkeypatch.setenv("UNRELATED_SECRET_TOKEN", "x")
    harness_attribution.resolve_environment_harness()
    ((_, args),) = asked
    assert args["op"] == "environment"
    assert args["env"]["CURSOR_VERSION"] == "2.0.0"
    assert "UNRELATED_SECRET_TOKEN" not in args["env"]


def test_parent_harness_passes_this_process_parent(asked, monkeypatch) -> None:
    monkeypatch.setattr(harness_attribution.os, "getppid", lambda: 42)
    assert harness_attribution.resolve_parent_process_harness() == "cursor"
    assert asked == [("harness_attribution", {"op": "parent", "ppid": 42})]


def test_runtime_hook_harness_asks_for_the_requested_harness(asked) -> None:
    env = {"CURSOR_VERSION": "2.0.0"}
    assert harness_attribution.resolve_runtime_hook_harness("claude-code", env=env) == "cursor"
    assert asked == [("harness_attribution", {"op": "runtime_hook", "requested": "claude-code", "env": env})]


def test_runtime_hook_harness_keeps_the_request_when_the_answer_names_none(monkeypatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_runner_authority.native_runner_authority",
        lambda *_a, **_k: {},
    )
    assert harness_attribution.resolve_runtime_hook_harness("opencode", env={}) == "opencode"
    assert harness_attribution.resolve_environment_harness({}) is None


def test_origin_env_returns_the_native_stamp(asked) -> None:
    assert harness_attribution.origin_harness_env("grok") == {"HOL_GUARD_ORIGIN_HARNESS": "grok"}
    assert asked == [("harness_attribution", {"op": "origin_env", "harness": "grok"})]


@pytest.mark.usefixtures("native_hook_force")
def test_guard_hook_records_cursor_harness_for_cursor_env(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    native_hook_force: Path,
) -> None:
    from tests.test_guard_runtime import _build_guard_fixture, _run_guard_hook

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    # Claude Code's own markers would keep the hook Claude's; a run from inside
    # a Claude session must not inherit them.
    monkeypatch.delenv("CLAUDECODE", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_ENTRYPOINT", raising=False)
    monkeypatch.setenv("CURSOR_VERSION", "2.0.0")
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(workspace_dir))
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")

    rc, payload = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "tool_input": {"command": "rm -rf /tmp/hol-guard-cursor-attribution-test"},
            "source_scope": "project",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 2  # canonical: detected cursor harness, _RC_BLOCK_IS_TWO
    assert isinstance(payload, dict)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    with sqlite3.connect(home_dir / "guard.db") as connection:
        harnesses = [row[0] for row in connection.execute("select harness from native_hook_decision_receipts")]
    assert harnesses == ["cursor"]
