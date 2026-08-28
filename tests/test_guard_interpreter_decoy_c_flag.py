"""Interpreter -c payloads after a positional script are not observers."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def _prefer_guard_interpreter_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    interpreter = shutil.which("python") or sys.executable
    monkeypatch.setattr(sys, "executable", interpreter)
    current_path = os.environ.get("PATH", "")
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join(part for part in (str(Path(interpreter).parent), current_path) if part),
    )


def test_classifier_does_not_treat_decoy_c_after_script_as_observer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prefer_guard_interpreter_on_path(monkeypatch)
    decoy = "python attacker.py -c 'print(1)'"
    inline = "python -c 'print(1)'"
    unbuffered = "python -u -c 'print(1)'"

    assert not is_explicitly_benign_tool_action_request("bash", {"command": decoy}, cwd=tmp_path)
    assert is_explicitly_benign_tool_action_request("bash", {"command": inline}, cwd=tmp_path)
    assert is_explicitly_benign_tool_action_request("bash", {"command": unbuffered}, cwd=tmp_path)
    assert extract_sensitive_tool_action_request("bash", {"command": inline}, cwd=tmp_path) is None
