"""Direct-tool adapters present native verdicts and caller routing facts."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_direct_tool_context as client
from codex_plugin_scanner.guard.native_request_context import NativeRequestContextFailure
from codex_plugin_scanner.guard.runtime import direct_vitest


def test_caller_routing_environment_is_carried_without_unrelated_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BUN_OPTIONS", "--preload=synthetic.js")
    monkeypatch.setenv("NODE_OPTIONS", "--require=synthetic.js")
    monkeypatch.setenv("BASH_FUNC_synthetic%%", "synthetic function")
    monkeypatch.setenv("DYLD_SYNTHETIC", "synthetic loader")
    monkeypatch.setenv("UNRELATED_SYNTHETIC_SECRET", "must not travel")
    monkeypatch.setattr(client, "_process_groups", lambda: [123])
    facts = client._facts(tmp_path, tmp_path / "home")
    assert facts["environment"]["BUN_OPTIONS"] == "--preload=synthetic.js"
    assert facts["environment"]["NODE_OPTIONS"] == "--require=synthetic.js"
    assert "BASH_FUNC_synthetic%%" in facts["environment"]
    assert "DYLD_SYNTHETIC" in facts["environment"]
    assert "UNRELATED_SYNTHETIC_SECRET" not in facts["environment"]
    assert facts["groups"] == [123]


@pytest.mark.parametrize(
    "reply",
    [
        NativeRequestContextFailure("native_request_context_unavailable"),
        {},
        {"kind": "direct_tool", "accepted": False, "context": None},
        {"kind": "direct_tool", "accepted": 1, "context": {}},
        {"kind": "other", "accepted": True, "context": {}},
        {"kind": "direct_tool", "accepted": True, "context": {}, "extra": True},
        {"kind": "direct_tool", "accepted": True, "context": "unreviewed"},
    ],
)
def test_native_context_refusal_or_malformed_reply_cannot_recover_a_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: Any
) -> None:
    monkeypatch.setattr(client, "_call", lambda *_args, **_kwargs: reply)
    assert (
        direct_vitest.direct_local_vitest_execution_context("cd synthetic && vitest", cwd=tmp_path, home_dir=tmp_path)
        is None
    )


@pytest.mark.parametrize("tool", ["vitest", "typescript"])
def test_context_is_hydrated_from_one_bound_native_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tool: str
) -> None:
    from codex_plugin_scanner.guard.runtime import shell_execution_context

    report = {"synthetic_native_report": True}
    native_context = SimpleNamespace(shell=report)
    expected = object()
    calls: list[dict[str, Any]] = []

    def call(action: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        calls.append({"action": action, **kwargs})
        return {"kind": "direct_tool", "accepted": True, "context": {"synthetic_context": True}}

    monkeypatch.setattr(client, "_call", call)
    monkeypatch.setattr(client, "_decode_build", lambda _wire: native_context)
    monkeypatch.setattr(
        shell_execution_context, "_context_from_report", lambda wire: expected if wire is report else None
    )
    entrypoint = getattr(direct_vitest, f"direct_local_{tool}_execution_context")
    result = entrypoint("cd synthetic && npx tsc --noEmit && vitest", cwd=tmp_path, home_dir=tmp_path)
    assert result is expected
    assert len(calls) == 1
    assert calls[0]["action"]["body"]["script"] == "cd synthetic && npx tsc --noEmit && vitest"
    assert calls[0]["action"]["body"]["tool"] == tool
    assert calls[0]["source"] == "direct_command"


@pytest.mark.parametrize(
    "reply,expected",
    [
        (NativeRequestContextFailure("native_request_context_unavailable"), False),
        ({}, False),
        ({"kind": "trusted_tool", "trusted": False}, False),
        ({"kind": "trusted_tool", "trusted": 1}, False),
        ({"kind": "trusted_tool", "trusted": True, "extra": True}, False),
        ({"kind": "trusted_tool", "trusted": True}, True),
    ],
)
def test_trusted_path_command_only_presents_strict_native_boolean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: Any, expected: bool
) -> None:
    monkeypatch.setattr(client, "_call", lambda *_args, **_kwargs: reply)
    assert direct_vitest._trusted_path_command("bun", cwd=tmp_path, home_dir=tmp_path) is expected


@pytest.mark.parametrize("command", ["pwd", "ls -la", "echo hello", "cd workspace && echo hello", "npx tsc --noEmit"])
@pytest.mark.parametrize("tool", ["vitest", "typescript"])
def test_impossible_literal_inputs_do_not_contact_the_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str, tool: str
) -> None:
    def unexpected(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("impossible input contacted the resident")

    monkeypatch.setattr(client, "_call", unexpected)
    entrypoint = getattr(direct_vitest, f"direct_local_{tool}_execution_context")
    assert entrypoint(command, cwd=tmp_path, home_dir=tmp_path) is None
