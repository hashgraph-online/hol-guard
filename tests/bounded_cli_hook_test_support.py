from __future__ import annotations

import io
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge


def json_object(text: str) -> dict[str, object]:
    payload = cast(object, json.loads(text))
    assert isinstance(payload, dict)
    return {str(key): value for key, value in cast(dict[object, object], payload).items()}


def config(tmp_path: Path, *, harness: str) -> dict[str, object]:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return {
        "python_executable": "python",
        "package_root": str(tmp_path),
        "guard_home": str(guard_home),
        "cli_args": [
            "guard",
            "hook",
            "--guard-home",
            str(guard_home),
            "--harness",
            harness,
        ],
        "harness": harness,
        "timeout_seconds": 3,
    }


def run_hook(monkeypatch: pytest.MonkeyPatch, hook_config: Mapping[str, object], input_text: str) -> int:
    """Run an installed launcher's hook with ``input_text`` on its stdin.

    The launcher hands its own stdin to the native runtime, so the hook goes
    on descriptor 0 and the answer comes back on descriptor 1 (read it with
    ``capfd``).
    """
    read, write = os.pipe()
    os.write(write, input_text.encode("utf-8", "surrogatepass"))
    os.close(write)
    saved = os.dup(0)
    os.dup2(read, 0)
    os.close(read)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.FileIO(0, closefd=False), encoding="utf-8"))
    try:
        return bounded_cli_hook_bridge.main_from_argv([json.dumps(dict(hook_config))])
    finally:
        os.dup2(saved, 0)
        os.close(saved)
