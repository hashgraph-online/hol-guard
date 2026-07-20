from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _module() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "mdm" / "run-local-lab.py"
    spec = importlib.util.spec_from_file_location("guard_mdm_local_lab", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_local_lab_covers_portable_contract_and_keeps_native_gates_explicit() -> None:
    module = _module()
    suite_names = {suite.name for suite in module.SUITES}
    capabilities = {capability for suite in module.SUITES for capability in suite.capabilities}

    assert suite_names == {
        "adapter-contract",
        "enterprise-network",
        "health-lease",
        "machine-integrity",
        "user-lifecycle",
    }
    assert {"observer", "remediation", "tamper", "multi-user", "offline", "proxy"} <= capabilities
    assert "apple-apns-enrollment" in module.NATIVE_GATES
    assert "windows-system-context" in module.NATIVE_GATES


def test_summary_is_bounded_and_prefers_pytest_result() -> None:
    module = _module()
    summary = module._summary("noise\n12 passed, 2 skipped in 1.20s\n")
    assert summary == "12 passed, 2 skipped in 1.20s"
    assert len(module._summary("x" * 500)) == 240


def test_suite_commands_disable_cache_writes(monkeypatch) -> None:
    module = _module()
    recorded = {}

    class Completed:
        returncode = 0
        stdout = "1 passed in 0.01s"
        stderr = ""

    def fake_run(command, **kwargs):
        recorded["command"] = command
        recorded["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    result = module.run_suite(module.SUITES[0])

    assert result.outcome == "passed"
    assert result.command[:5] == ("pytest", "-p", "no:cacheprovider", "--tb=short", "-q")
    assert recorded["kwargs"]["cwd"] == module.ROOT
