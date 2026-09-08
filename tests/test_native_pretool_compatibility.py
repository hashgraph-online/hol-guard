"""Compatibility preparation preserves the native retry seam."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.store import GuardStore


def test_cli_retries_native_after_compatibility_payload_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard-home")
    store = GuardStore(context.guard_home)
    config = GuardConfig(guard_home=context.guard_home, workspace=context.workspace_dir)
    args = type("HookArgs", (), {"harness": "codex", "runtime_harness": None, "event_file": None, "json": True})()
    raw_payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "true"}}
    routed: list[dict[str, object]] = []

    monkeypatch.setattr(commands_hook, "_require_guard_context", lambda _value: context)
    monkeypatch.setattr(commands_hook, "_require_guard_store", lambda _value: store)
    monkeypatch.setattr(commands_hook, "_require_guard_config", lambda _value: config)
    monkeypatch.setattr(commands_hook, "_load_hook_payload", lambda *_args, **_kwargs: raw_payload)
    monkeypatch.setattr(
        commands_hook,
        "prepare_compatibility_hook_state",
        lambda *_args, **kwargs: (
            kwargs["payload"],
            None,
            True,
            context.workspace_dir,
            None,
            None,
            None,
            None,
        ),
    )

    def route(*_args: object, **kwargs: object) -> int | None:
        payload = kwargs["payload"]
        assert isinstance(payload, dict)
        routed.append(
            {
                "payload": payload,
                "allow_compatibility": kwargs.get("allow_compatibility", True),
            }
        )
        return None if len(routed) == 1 else 23

    monkeypatch.setattr(commands_hook, "try_native_or_source_ref_hook", route)

    result = commands_hook._run_guard_hook_command(
        args,
        guard_home=context.guard_home,
        workspace=context.workspace_dir,
        context=context,
        store=store,
        config=config,
        input_text=json.dumps(raw_payload),
    )

    assert result == 23
    assert [entry["allow_compatibility"] for entry in routed] == [False, True]
    assert routed[0]["payload"] == raw_payload
