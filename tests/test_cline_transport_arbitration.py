from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_hooks import _hook_source
from codex_plugin_scanner.guard.adapters.cline_plugin import _plugin_source


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _activate(context: HarnessContext, transport: str) -> None:
    path = context.guard_home / "managed" / "cline" / "adapter-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, "active_transport": transport}) + "\n", encoding="utf-8")


def _fake_guard(tmp_path: Path) -> tuple[Path, Path]:
    path = tmp_path / "fake_guard.py"
    log = tmp_path / "guard-calls.jsonl"
    path.write_text(
        """from __future__ import annotations
import json, os, sys
payload=json.load(sys.stdin)
with open(os.environ["CLINE_TEST_LOG"],"a",encoding="utf-8") as handle:
    handle.write(json.dumps(payload,sort_keys=True)+"\\n")
print(json.dumps({"decision":"block","reason":"blocked by arbitration test"}))
""",
        encoding="utf-8",
    )
    return path, log


def _run_hook(source: str, tmp_path: Path, payload: dict[str, object], *, log: Path) -> dict[str, object]:
    worker = tmp_path / "hook.py"
    worker.write_text(source, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(worker)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "CLINE_TEST_LOG": str(log)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _run_plugin(source: str, tmp_path: Path, expression: str, *, log: Path) -> object:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for Cline transport arbitration tests")
    plugin = tmp_path / "plugin.mjs"
    plugin.write_text(source, encoding="utf-8")
    code = (
        'import { pathToFileURL } from "node:url";'
        f"const plugin=(await import(pathToFileURL({json.dumps(str(plugin))}).href)).default;"
        f"const result=await ({expression});console.log(JSON.stringify(result ?? null));"
    )
    result = subprocess.run(
        [node, "--input-type=module", "-e", code],
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "CLINE_TEST_LOG": str(log)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _pretool_payload() -> dict[str, object]:
    return {
        "hookName": "PreToolUse",
        "tool_call": {"id": "arb-1", "name": "run_command", "input": {"command": "BLOCK_ME"}},
    }


def test_native_hook_is_noop_when_plugin_is_selected(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard, log = _fake_guard(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])

    response = _run_hook(source, tmp_path, _pretool_payload(), log=log)

    assert response["cancel"] is False
    assert not log.exists()


def test_native_hook_fails_closed_when_transport_state_is_missing(tmp_path: Path) -> None:
    context = _context(tmp_path)
    guard, log = _fake_guard(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])

    response = _run_hook(source, tmp_path, _pretool_payload(), log=log)

    assert response["cancel"] is True
    assert "transport state is unavailable" in response["errorMessage"]
    assert not log.exists()


def test_plugin_is_noop_when_native_hooks_are_selected(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    guard, log = _fake_guard(tmp_path)
    source = _plugin_source(context, [sys.executable, str(guard)])

    result = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"arb-2",toolName:"run_command"},input:{command:"BLOCK_ME"}})',
        log=log,
    )

    assert result is None
    assert not log.exists()


def test_plugin_fails_closed_when_transport_state_is_missing(tmp_path: Path) -> None:
    context = _context(tmp_path)
    guard, log = _fake_guard(tmp_path)
    source = _plugin_source(context, [sys.executable, str(guard)])

    result = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"arb-3",toolName:"run_command"},input:{command:"BLOCK_ME"}})',
        log=log,
    )

    assert isinstance(result, dict)
    assert result["skip"] is True
    assert "transport state is unavailable" in result["reason"]
    assert not log.exists()


def test_selected_transport_is_the_only_guard_caller(tmp_path: Path) -> None:
    context = _context(tmp_path)
    guard, log = _fake_guard(tmp_path)
    native = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    plugin = _plugin_source(context, [sys.executable, str(guard)])

    _activate(context, "hooks")
    native_response = _run_hook(native, tmp_path, _pretool_payload(), log=log)
    plugin_response = _run_plugin(
        plugin,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"arb-4",toolName:"run_command"},input:{command:"BLOCK_ME"}})',
        log=log,
    )
    assert native_response["cancel"] is True
    assert plugin_response is None
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1

    log.unlink()
    _activate(context, "plugin")
    native_response = _run_hook(native, tmp_path, _pretool_payload(), log=log)
    plugin_response = _run_plugin(
        plugin,
        tmp_path,
        'plugin.hooks.beforeTool({toolCall:{toolCallId:"arb-5",toolName:"run_command"},input:{command:"BLOCK_ME"}})',
        log=log,
    )
    assert native_response["cancel"] is False
    assert isinstance(plugin_response, dict) and plugin_response["skip"] is True
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1
