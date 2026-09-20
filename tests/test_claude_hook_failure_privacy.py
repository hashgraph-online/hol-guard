"""Exercise the original hook assertion through the actual pytest renderer."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CANARIES = ("synthetic-command-marker-93", "synthetic-output-marker-93", "synthetic-error-marker-93")
_DRIVER = """from tests import test_guard_claude_adapter as target

def test_original_target(tmp_path):
    target.test_claude_daemon_hook_command_falls_back_to_native_ask_on_daemon_miss(tmp_path)
"""
_FIXTURE = """import json
import subprocess
from pathlib import Path
import pytest

@pytest.fixture(autouse=True)
def completed_process(monkeypatch):
    from tests import test_guard_claude_adapter as target
    data = json.loads(Path(__file__).with_name('fixture.json').read_text())
    def completed(*args, **kwargs):
        return subprocess.CompletedProcess(data['args'], data['returncode'], data['stdout'], data['stderr'])
    monkeypatch.setattr(target.subprocess, 'run', completed)
"""


@pytest.mark.parametrize("failure", (None, "returncode", "stderr", "event", "decision", "json"))
def test_original_ask_assertions_do_not_render_raw_process_fields(tmp_path: Path, failure: str | None) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "Other" if failure == "event" else "PreToolUse",
            "permissionDecision": "allow" if failure == "decision" else "ask",
            "permissionDecisionReason": _CANARIES[1],
        }
    }
    data = {
        "args": [_CANARIES[0]],
        "returncode": 1 if failure == "returncode" else 0,
        "stdout": _CANARIES[1] if failure == "json" else json.dumps(payload),
        "stderr": _CANARIES[2] if failure == "stderr" else "",
    }
    _ = (tmp_path / "fixture.json").write_text(json.dumps(data), encoding="utf-8")
    _ = (tmp_path / "conftest.py").write_text(_FIXTURE, encoding="utf-8")
    driver = tmp_path / "test_original_target.py"
    _ = driver.write_text(_DRIVER, encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(_ROOT), str(_ROOT / "src")))
    environment["PYTEST_ADDOPTS"] = ""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=long", f"--confcutdir={tmp_path}", str(driver)],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    expected_outcome = result.returncode == (0 if failure is None else 1)
    assert expected_outcome, "The original assertion did not produce the expected outcome."
    rendered = result.stdout + result.stderr
    raw_fields_absent = all(canary not in rendered for canary in _CANARIES)
    assert raw_fields_absent, "The pytest traceback exposed a raw process field."
    if failure not in (None, "json"):
        finite_diagnostic_present = "reason_category" in rendered and "returncode" in rendered
        assert finite_diagnostic_present, "The finite hook diagnostic was not rendered."
