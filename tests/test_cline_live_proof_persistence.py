from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_hooks import _hook_source


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    state = guard_home / "managed" / "cline" / "adapter-state.json"
    state.parent.mkdir(parents=True)
    state.write_text('{"schema_version":1,"active_transport":"hooks"}\n', encoding="utf-8")
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def _guard(tmp_path: Path) -> Path:
    path = tmp_path / "guard.py"
    path.write_text(
        """import json, sys
payload=json.load(sys.stdin)
if 'BLOCK_ME' in json.dumps(payload):
    print(json.dumps({'decision':'block','reason':'blocked'}))
else:
    print(json.dumps({'decision':'allow'}))
""",
        encoding="utf-8",
    )
    return path


def _run(worker: Path, payload: dict[str, object], *, canary: bool = False) -> dict[str, object]:
    env = dict(os.environ)
    if canary:
        env["HOL_GUARD_CLINE_CANARY"] = "1"
    result = subprocess.run(
        [sys.executable, str(worker)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_synthetic_canary_does_not_overwrite_live_block_proof(tmp_path: Path) -> None:
    context = _context(tmp_path)
    source = _hook_source(context, event_name="PreToolUse", guard_cli=[sys.executable, str(_guard(tmp_path))])
    worker = tmp_path / "PreToolUse.py"
    worker.write_text(source, encoding="utf-8")

    blocked = _run(
        worker,
        {"hookName": "PreToolUse", "tool_call": {"name": "run_command", "input": {"command": "BLOCK_ME"}}},
    )
    assert blocked["cancel"] is True
    proof_path = context.guard_home / "managed" / "cline" / "proofs" / "native-pretooluse.json"
    live_proof = json.loads(proof_path.read_text(encoding="utf-8"))
    assert live_proof["source"] == "cline"
    assert live_proof["outcome"] == "blocked"

    canary = _run(
        worker,
        {"hookName": "PreToolUse", "preToolUse": {"toolName": "read_files", "parameters": {"paths": "[]"}}},
        canary=True,
    )
    assert canary["cancel"] is False
    assert json.loads(proof_path.read_text(encoding="utf-8")) == live_proof
