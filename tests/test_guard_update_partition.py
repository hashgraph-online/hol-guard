"""Cold import and live facade contracts for the update module partition."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy

_IMPORT_ORDERS = (
    "update_commands",
    "update_driver",
    "update_execution",
    "update_harness_repair",
    "update_install_sources",
    "update_installer_commands",
    "update_output",
    "update_receipt_results",
    "update_runtime_refresh",
    "update_status",
    "update_version_selection",
)


@pytest.mark.parametrize("first", _IMPORT_ORDERS)
def test_fresh_update_import_orders_preserve_facade_bindings(tmp_path: Path, first: str) -> None:
    root = Path(__file__).resolve().parents[1]
    script = """
import importlib
import inspect
import json
from pathlib import Path
import sys
from typing import get_type_hints

root = Path(sys.argv[1]).resolve(strict=True)
sys.path[:0] = [str(root / "src"), str(root)]
import codex_plugin_scanner.guard.cli

prefix = "codex_plugin_scanner.guard.cli."
names = json.loads(sys.argv[3])
assert all(prefix + name not in sys.modules for name in names), "Parent imports preloaded an update target"
importlib.import_module(prefix + sys.argv[2])
facade = importlib.import_module(prefix + "update_commands")
assert Path(facade.__file__).resolve() == root / "src/codex_plugin_scanner/guard/cli/update_commands.py"
assert facade._runtime_package_path() == Path(facade.__file__).resolve()
assert facade.__all__ == [
    "build_guard_install_surface_payload", "build_guard_update_status_payload", "run_guard_update"
]
bound_functions = 0
for name in names:
    if name == "update_commands":
        continue
    helper = importlib.import_module(prefix + name)
    assert Path(helper.__file__).resolve() == root / "src/codex_plugin_scanner/guard/cli" / (name + ".py")
    assert helper._update is facade
    for function_name, function in vars(helper).items():
        if inspect.isfunction(function) and function.__module__ == helper.__name__:
            assert getattr(facade, function_name) is function
            get_type_hints(function)
            bound_functions += 1
assert bound_functions == 92
print(json.dumps({"first": sys.argv[2], "bound_functions": bound_functions, "cold": True}))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(root), first, json.dumps(_IMPORT_ORDERS)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout) == {"first": first, "bound_functions": 92, "cold": True}


def test_update_helpers_resolve_rebound_facade_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    notes = object()
    payload: dict[str, object] = {"notes": notes}
    observed: list[object] = []
    first = ["first"]
    second = ["second"]

    def first_provider(value: object) -> list[str]:
        observed.append(value)
        return first

    def second_provider(value: object) -> list[str]:
        observed.append(value)
        return second

    monkeypatch.setattr(update_commands, "_string_list", first_provider)
    assert update_commands._payload_notes(payload) is first
    monkeypatch.setattr(update_commands, "_string_list", second_provider)
    assert update_commands._payload_notes(payload) is second
    assert len(observed) == 2 and all(value is notes for value in observed)


@pytest.mark.parametrize("provider_raises", [False, True])
def test_update_version_policy_restores_same_context_variable(
    monkeypatch: pytest.MonkeyPatch,
    provider_raises: bool,
) -> None:
    policy_variable = update_commands._version_network_policy
    outer_policy = ManagedNetworkPolicy(proxy_mode="none")
    requested_policy = ManagedNetworkPolicy()
    observed: list[ManagedNetworkPolicy | None] = []

    def latest_version() -> None:
        observed.append(policy_variable.get())
        if provider_raises:
            raise LookupError("version provider failed")

    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", latest_version)
    token = policy_variable.set(outer_policy)
    try:
        if provider_raises:
            with pytest.raises(LookupError, match="version provider failed"):
                update_commands._version_check_payload("1.0.0", network_policy=requested_policy)
        else:
            result = update_commands._version_check_payload("1.0.0", network_policy=requested_policy)
            assert result["status"] == "unavailable"
        assert update_commands._version_network_policy is policy_variable
        assert policy_variable.get() is outer_policy
        assert len(observed) == 1 and observed[0] is requested_policy
    finally:
        policy_variable.reset(token)
