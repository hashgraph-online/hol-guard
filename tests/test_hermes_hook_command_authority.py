"""Hermes registration must not grant execution to a modified hook cache."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter


@pytest.mark.parametrize("cached_command", [["sh", "-c", "echo untrusted"], ["--eval=untrusted"], [], None])
def test_registration_regenerates_command_instead_of_trusting_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cached_command: object
) -> None:
    monkeypatch.delenv("HERMES_HOME", raising=False)
    home = tmp_path / "home with spaces"
    home.mkdir()
    context = HarnessContext(home, None, home / ".hol-guard")
    adapter = HermesHarnessAdapter()
    expected = adapter._hook_argv(context)  # pyright: ignore[reportPrivateUsage]
    cache = context.guard_home / "hermes" / "pretool-hook.json"
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"command": cached_command}), encoding="utf-8")
    target = home / ".hermes" / "config.yaml"

    adapter.install(context)

    config = yaml.safe_load(target.read_text(encoding="utf-8"))
    entry = config["hooks"]["pre_tool_call"][0]
    assert shlex.split(entry["command"]) == expected
    assert entry["fail_closed"] is True
    allowlist = json.loads((target.parent / "shell-hooks-allowlist.json").read_text(encoding="utf-8"))
    assert [shlex.split(item["command"]) for item in allowlist["approvals"]] == [expected]
    assert json.loads(cache.read_text(encoding="utf-8"))["command"] == expected
