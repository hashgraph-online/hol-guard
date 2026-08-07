from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_hooks import (
    _hook_source,
    _posix_wrapper,
    _powershell_wrapper,
    _slot_for_event,
    cline_hook_roots,
)
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


def _fake_guard(tmp_path: Path) -> Path:
    path = tmp_path / "fake_guard.py"
    path.write_text(
        """from __future__ import annotations
import json, os, sys
payload=json.load(sys.stdin)
log=os.environ.get("CLINE_TEST_LOG")
if log:
    with open(log,"a",encoding="utf-8") as handle: handle.write(json.dumps(payload,sort_keys=True)+"\\n")
text=json.dumps(payload,sort_keys=True)
if "BLOCK_ME" in text or "SECRET_OUTPUT" in text: print(json.dumps({"decision":"block","reason":"blocked by test"}))
else: print(json.dumps({"decision":"allow"}))
""",
        encoding="utf-8",
    )
    return path


def _run_hook(source: str, tmp_path: Path, payload: dict[str, object], *, env=None) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "PreToolUse"
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return subprocess.run(
        [sys.executable, str(path)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
        check=False,
    )


def _run_plugin(source: str, tmp_path: Path, expression: str) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for the generated Cline plugin contract")
    path = tmp_path / "plugin.mjs"
    path.write_text(source, encoding="utf-8")
    code = (
        'import { pathToFileURL } from "node:url";'
        f"const plugin=(await import(pathToFileURL({json.dumps(str(path))}).href)).default;"
        f"const result=await ({expression});console.log(JSON.stringify(result));"
    )
    return subprocess.run(
        [node, "--input-type=module", "-e", code], capture_output=True, text=True, timeout=10, check=False
    )


def test_native_hook_root_matches_vscode_and_core_global_directory(tmp_path: Path) -> None:
    context = _context(tmp_path)
    roots = cline_hook_roots(context)
    assert roots[0] == context.home_dir / "Documents" / "Cline" / "Hooks"
    assert roots[1] == context.home_dir / ".cline" / "hooks"


def test_native_hook_slots_are_platform_canonical_and_non_destructive(tmp_path: Path) -> None:
    root = tmp_path / "hooks"
    root.mkdir()
    assert _slot_for_event(root, "PreToolUse", windows=False).name == "PreToolUse"
    assert _slot_for_event(root, "PreToolUse", windows=True).name == "PreToolUse.ps1"
    (root / "PreToolUse").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        _slot_for_event(root, "PreToolUse", windows=False)


def test_posix_wrapper_pins_python_and_isolation_flags() -> None:
    source = _posix_wrapper(worker=Path("/guard/worker.py"), python="/runtime/python")
    assert source.startswith("#!/bin/sh\n")
    assert "exec /runtime/python -I -s /guard/worker.py" in source
    assert "/usr/bin/env python" not in source


def test_windows_wrapper_uses_isolated_python_and_fails_closed() -> None:
    source = _powershell_wrapper(worker=Path("C:/Guard/worker.py"), python="C:/Python/python.exe", blocking=True)
    assert '"-I", "-s"' in source
    assert "ConvertTo-Json -Compress" in source
    assert "cancel=$true" in source


def test_native_pretool_fails_closed_when_guard_is_unavailable(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[str(tmp_path / "missing")])
    result = _run_hook(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "read_files", "input": {"paths": ["README.md"]}}},
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["cancel"] is True


def test_native_pretool_fans_out_cline_parallel_commands(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    guard = _fake_guard(tmp_path)
    log = tmp_path / "guard.jsonl"
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    result = _run_hook(
        source,
        tmp_path,
        {
            "hookName": "PreToolUse",
            "tool_call": {"id": "1", "name": "run_commands", "input": {"commands": ["echo safe", "BLOCK_ME"]}},
        },
        env={**os.environ, "CLINE_TEST_LOG": str(log)},
    )
    assert json.loads(result.stdout)["cancel"] is True
    values = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [value["tool_call"]["input"]["command"] for value in values] == ["echo safe", "BLOCK_ME"]


def test_native_pretool_rejects_oversized_input_before_guard(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "hooks")
    guard = _fake_guard(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(guard)])
    result = _run_hook(
        source,
        tmp_path,
        {"hookName": "PreToolUse", "tool_call": {"name": "read_files", "input": {"x": "a" * (1024 * 1024)}}},
    )
    assert json.loads(result.stdout)["cancel"] is True


def test_generated_plugin_syntax_pretool_block_and_posttool_replacement(tmp_path: Path) -> None:
    context = _context(tmp_path)
    _activate(context, "plugin")
    guard = _fake_guard(tmp_path)
    source = _plugin_source(context, [sys.executable, str(guard)])
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required")
    syntax_path = tmp_path / "syntax.mjs"
    syntax_path.write_text(source, encoding="utf-8")
    syntax = subprocess.run([node, "--check", str(syntax_path)], capture_output=True, text=True, check=False)
    assert syntax.returncode == 0, syntax.stderr

    before = _run_plugin(
        source,
        tmp_path,
        (
            'plugin.hooks.beforeTool({toolCall:{toolCallId:"1",toolName:"run_commands"},'
            'input:{commands:["echo safe","BLOCK_ME"]}})'
        ),
    )
    assert before.returncode == 0, before.stderr
    assert json.loads(before.stdout) == {"skip": True, "reason": "blocked by test"}

    after = _run_plugin(
        source,
        tmp_path,
        'plugin.hooks.afterTool({toolCall:{toolCallId:"2",toolName:"read_files"},input:{paths:["README.md"]},result:{output:"SECRET_OUTPUT",isError:false,metadata:{source:"test"}}})',
    )
    assert after.returncode == 0, after.stderr
    output = json.loads(after.stdout)["result"]
    assert output["isError"] is True
    assert output["output"] == "blocked by test"
    assert output["metadata"] == {"source": "test"}
