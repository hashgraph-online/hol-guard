"""Hermes registration must not grant execution to a modified hook cache."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest
import yaml

from codex_plugin_scanner.guard.adapters import hermes
from codex_plugin_scanner.guard.adapters.base import HarnessContext


@pytest.mark.parametrize("cached_command", [["sh", "-c", "echo untrusted"], ["--eval=untrusted"], [], None])
def test_registration_regenerates_command_instead_of_trusting_cache(tmp_path: Path, monkeypatch, cached_command) -> None:
    monkeypatch.delenv("HERMES_HOME", raising=False)
    home = tmp_path / "home with spaces"
    home.mkdir()
    context = HarnessContext(home, None, home / ".hol-guard")
    managed = hermes._managed_root(context)
    managed.mkdir(parents=True)
    cache = managed / "pretool-hook.json"
    cache.write_text(json.dumps({"command": cached_command}), encoding="utf-8")
    monkeypatch.setattr(hermes, "_resolve_guard_consumer_base_url", lambda _context: "http://127.0.0.1:5474")
    expected = hermes._pretool_payload(context=context)["command"]
    target = home / ".hermes" / "config.yaml"

    _, _, written = hermes._write_guard_to_hermes_config_yaml(
        context=context, config_yaml_path=target, overlay_servers={}, managed_names=[]
    )

    assert written is True
    config = yaml.safe_load(target.read_text(encoding="utf-8"))
    entry = config["hooks"]["pre_tool_call"][0]
    assert shlex.split(entry["command"]) == expected
    assert entry["fail_closed"] is True
    allowlist = json.loads((target.parent / "shell-hooks-allowlist.json").read_text(encoding="utf-8"))
    assert [shlex.split(item["command"]) for item in allowlist["approvals"]] == [expected]
    assert json.loads(cache.read_text(encoding="utf-8"))["command"] == cached_command
