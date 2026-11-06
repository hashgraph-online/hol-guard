from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import (
    _render_bounded_hook_script,
    run_bounded_cli_hook,
)


@pytest.mark.parametrize("bridge", [False, True])
@pytest.mark.parametrize("cwd", [None, "", " \t", "/explicit/workspace", 42])
def test_owned_workspace_fallback_preserves_explicit_and_invalid_context(
    tmp_path: Path, monkeypatch, bridge, cwd
) -> None:
    workspace = str(tmp_path / "workspace")
    config = {
        "python_executable": sys.executable,
        "package_root": str(tmp_path),
        "guard_home": str(tmp_path / "guard"),
        "harness": "grok",
        "timeout_seconds": 85,
        "cli_args": [
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard"),
            "--harness",
            "grok",
            "--workspace",
            workspace,
            "--json",
        ],
    }
    payload = json.dumps({"hook_event_name": "UserPromptSubmit", "cwd": cwd, "prompt": "synthetic"})
    expected = workspace if cwd is None or (isinstance(cwd, str) and not cwd.strip()) else cwd
    if bridge:
        from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon

        captured = []

        def daemon(**kwargs):
            captured.append(json.loads(kwargs["input_text"]))
            return "{}", "", 0

        monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", daemon)
        assert run_bounded_cli_hook(config, input_text=payload) == 0
        assert captured[0]["cwd"] == expected
        assert captured[0]["prompt"] == "synthetic"
    else:
        module = ModuleType("configured_workspace_client")
        exec(
            _render_bounded_hook_script(guard_home=tmp_path / "guard", harness="grok", timeout_seconds=85),
            module.__dict__,
        )
        monkeypatch.setattr(module.sys, "argv", ["grok.py", json.dumps(config)])
        assert module._configure_grok_invocation()
        result = json.loads(module._grok_invocation_payload(payload))
        assert result["cwd"] == expected
        assert result["prompt"] == "synthetic"
