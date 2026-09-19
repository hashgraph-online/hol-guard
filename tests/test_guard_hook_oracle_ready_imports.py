"""Fresh-process proof of the real evaluator readiness boundary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_CHILD = r"""
import inspect
import json
import sqlite3
import sys
from pathlib import Path

from codex_plugin_scanner.guard import adapters
from codex_plugin_scanner.guard.adapters.base import HarnessAdapter
from codex_plugin_scanner.guard.cli import commands_hook, commands_support_interaction
from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as entry
from codex_plugin_scanner.guard.store import GuardStore

expected_warm = sys.argv[1] == "1"
guard_home = Path(sys.argv[2])
cold_names = (
    "codex_plugin_scanner.guard.cli.commands_hook_claude",
    "codex_plugin_scanner.guard.cli.commands_hook_generic",
    "codex_plugin_scanner.guard.cli.render",
)
assert all(name not in sys.modules for name in cold_names), "child did not start with cold optional imports"
assert adapters._adapters.cache_info().currsize == 0, "adapter registry was already initialized"
assert entry.python_oracle_surface_enabled() is expected_warm
forbidden_calls = []


def forbidden(name):
    def fail(*args, **kwargs):
        forbidden_calls.append(name)
        raise AssertionError("readiness invoked " + name)
    return fail


GuardStore.__init__ = forbidden("store construction")
sqlite3.connect = forbidden("database connection")
entry._run_resident_hook_request = forbidden("request evaluation")
commands_hook._run_guard_hook_command = forbidden("hook action")
commands_support_interaction._emit = forbidden("output")
original_getattribute = HarnessAdapter.__getattribute__


def guarded_adapter_attribute(self, name):
    if name in {"detect", "inventory_snapshot", "install", "uninstall"}:
        forbidden_calls.append("adapter action")
        raise AssertionError("readiness invoked adapter action")
    return original_getattribute(self, name)


HarnessAdapter.__getattribute__ = guarded_adapter_attribute
events = []


class Connection:
    def send(self, value):
        assert value == ("ready", None), "unexpected readiness message"
        assert not events, "readiness was emitted twice"
        assert all((name in sys.modules) is expected_warm for name in cold_names)
        assert (adapters._adapters.cache_info().currsize == 1) is expected_warm
        if expected_warm:
            registered = adapters.list_adapters()
            assert len(registered) == 16
            for item in registered:
                for method in ("__init__", "__new__"):
                    assert inspect.getattr_static(type(item), method) is inspect.getattr_static(object, method)
        assert forbidden_calls == []
        assert not guard_home.exists(), "readiness created Guard state"
        events.append("ready")

    def recv(self):
        assert events == ["ready"]
        return ("stop", None)


try:
    entry._hook_evaluator_main(Connection(), str(guard_home))
except BaseException as error:
    terminal = error.__traceback__
    while terminal is not None and terminal.tb_next is not None:
        terminal = terminal.tb_next
    expected_origin = (
        type(error) is AssertionError
        and terminal is not None
        and terminal.tb_frame.f_code is Connection.send.__code__
        and terminal.tb_lineno == Connection.send.__code__.co_firstlineno + 3
    )
    print("ORACLE_READY_CHILD_FAILURE " + json.dumps({
        "stage": "optional_imports_not_ready" if expected_origin else "other_child_failure",
        "exceptionClass": "AssertionError" if type(error) is AssertionError else "OtherException",
    }), file=sys.stderr)
    raise
assert events == ["ready"]
assert forbidden_calls == []
assert not guard_home.exists()
print(json.dumps({"ready": True, "warm": expected_warm, "forbiddenCalls": 0}))
"""


@pytest.mark.parametrize(
    ("mode", "oracle", "test_mode", "diagnostic", "expected_warm"),
    [
        ("off", "1", "1", "0", True),
        ("shadow", "1", "1", "1", True),
        ("auto", "1", "1", "1", False),
        ("force", "1", "1", "1", False),
        ("off", "0", "1", "0", False),
        ("off", "1", "0", "0", False),
        ("shadow", "1", "1", "0", False),
    ],
    ids=["off-oracle", "shadow-oracle", "auto", "force", "oracle-disabled", "not-test-mode", "shadow-disabled"],
)
def test_evaluator_ready_prepares_only_explicit_oracle_imports(
    tmp_path: Path,
    mode: str,
    oracle: str,
    test_mode: str,
    diagnostic: str,
    expected_warm: bool,
) -> None:
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment.pop("PYTEST_CURRENT_TEST", None)
    environment.update(
        {
            "HOL_GUARD_NATIVE": mode,
            "HOL_GUARD_PYTHON_ORACLE": oracle,
            "HOL_GUARD_TEST_MODE": test_mode,
            "HOL_GUARD_NATIVE_DIAGNOSTIC": diagnostic,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(root / "src"),
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", _CHILD, "1" if expected_warm else "0", str(tmp_path / "uncreated-guard")],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"ready": True, "warm": expected_warm, "forbiddenCalls": 0}
