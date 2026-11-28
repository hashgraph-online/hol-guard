"""The observer reads the hook workspace from the pi-hook-bridge JSON config."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlencode

import pytest

OBSERVER = Path(__file__).resolve().parents[1] / "ci/gauntlet/observer.ts"


def _bridge_row(tmp_path: Path, workspace: Path) -> dict[str, object]:
    bun = shutil.which("bun")
    if bun is None:
        pytest.skip("the real TypeScript observer requires Bun")
    runtime = tmp_path / "runtime"
    runtime.write_text('#!/bin/sh\ncat >/dev/null\nprintf %s \'{"status":200,"body":"{}"}\'\n')
    runtime.chmod(0o755)
    # The extension passes its bridge settings as one JSON argument; the hook
    # query string, workspace included, is that object's `query` field.
    config = json.dumps(
        {
            "harness": "omp",
            "guard_home": "/h",
            "query": urlencode({"guard-home": "/h", "workspace": str(workspace)}),
            "timeout_ms": 400,
        }
    )
    request = {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "rg x"}}
    script = (
        f"import install from {json.dumps(str(OBSERVER))};\n"
        "import { spawn } from 'node:child_process';\n"
        "install({ on: () => {} });\n"
        f"const child = spawn({json.dumps(str(runtime))}, ['pi-hook-bridge', {json.dumps(config)}]);\n"
        f"child.stdin.end({json.dumps(json.dumps(request))} + '\\n');\n"
    )
    log = tmp_path / "hooks.jsonl"
    subprocess.run(
        [bun, "-e", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env={
            "PATH": os.environ["PATH"],
            "HOME": str(tmp_path),
            "GUARD_GAUNTLET_OBSERVER_LOG": str(log),
            "GUARD_GAUNTLET_LINKED_CWD": str(tmp_path / "linked"),
        },
    )
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(rows) == 1
    return rows[0]


def _linked_fixture(tmp_path: Path) -> Path:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "linked").symlink_to(real)
    return real


def test_bridge_workspace_with_the_linked_spelling_counts(tmp_path: Path) -> None:
    _linked_fixture(tmp_path)
    row = _bridge_row(tmp_path, tmp_path / "linked")
    assert row["transport"] == "pi-hook-bridge"
    assert row["linked_fixture_cwd"] is True


@pytest.mark.parametrize("name", ["real", "other"])
def test_bridge_workspace_without_the_linked_spelling_does_not_count(tmp_path: Path, name: str) -> None:
    _linked_fixture(tmp_path)
    (tmp_path / name).mkdir(exist_ok=True)
    assert _bridge_row(tmp_path, tmp_path / name)["linked_fixture_cwd"] is False
