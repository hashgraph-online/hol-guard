from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_runtime_trust import validate_codex_hook_launch


def _command(config: dict[str, object], name: str) -> list[str]:
    value = config[name]
    assert isinstance(value, list) and all(isinstance(token, str) for token in value)
    return [token for token in value if isinstance(token, str)]


def _validate(config: dict[str, object], config_json: str):
    return validate_codex_hook_launch(
        manifest_path=str(config["manifest_path"]),
        state_path=str(config["state_path"]),
        fallback_command=_command(config, "fallback_command"),
        start_command=_command(config, "start_command"),
        config_json=config_json,
    )


def test_repair_keeps_an_open_codex_session_authenticated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
        home_override_explicit=True,
    )
    context.workspace_dir.mkdir(parents=True)
    monkeypatch.setattr(codex_adapter, "_post_tool_hook_timeout_seconds", lambda _context: 35)
    CodexHarnessAdapter().install(context)
    old_bridge_command = codex_adapter._hook_command_parts(context)
    old_config_json = old_bridge_command[3]
    old_config = json.loads(old_config_json)

    monkeypatch.setattr(codex_adapter, "_post_tool_hook_timeout_seconds", lambda _context: 65)
    CodexHarnessAdapter().install(context)

    trusted = _validate(old_config, old_config_json)
    assert trusted.cwd == Path(str(old_config["manifest_path"])).parent.resolve(strict=True)

    changed_config = dict(old_config)
    changed_timeouts = dict(changed_config["hook_timeouts"])
    changed_timeouts["PreToolUse"] = 34
    changed_config["hook_timeouts"] = changed_timeouts
    with pytest.raises(ValueError, match="bridge config changed after authentication"):
        _validate(changed_config, json.dumps(changed_config, separators=(",", ":")))
