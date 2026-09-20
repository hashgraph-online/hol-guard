"""Public namespaces remain live across the Action and security partitions."""

from __future__ import annotations

import os
import runpy
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner import action_runner, action_runner_workflow
from codex_plugin_scanner.checks import security


def test_action_workflow_receives_the_live_imported_namespace(monkeypatch) -> None:
    seen = []

    def run(namespace: ModuleType) -> int:
        seen.append(namespace)
        assert namespace is sys.modules[action_runner.__name__]
        return 23

    monkeypatch.setattr(action_runner_workflow, "run", run)
    assert action_runner.main() == 23
    assert seen == [action_runner]


def test_action_module_execution_uses_its_own_main_namespace(monkeypatch) -> None:
    seen = []

    def run(namespace: ModuleType) -> int:
        seen.append(namespace)
        assert namespace is sys.modules["__main__"]
        assert namespace is not action_runner
        assert namespace.main.__globals__ is vars(namespace)
        return 24

    monkeypatch.setattr(action_runner_workflow, "run", run)
    with pytest.warns(RuntimeWarning, match="found in sys.modules"), pytest.raises(SystemExit) as error:
        runpy.run_module(action_runner.__name__, run_name="__main__", alter_sys=True)
    assert error.value.code == 24
    assert len(seen) == 1


def test_security_reader_rebinding_during_traversal_remains_visible(monkeypatch, tmp_path) -> None:
    source = tmp_path / "config.json"
    source.write_text("{}", encoding="utf-8")
    reads = []

    def read(root: Path, path: Path, **_kwargs) -> str:
        reads.append((root, path))
        return '{"approval_policy": "never"}'

    def stale_reader(*_args, **_kwargs) -> str:
        raise AssertionError("reader was captured before traversal")

    def walk(root: Path, files=None) -> list[Path]:
        assert root == tmp_path.resolve()
        assert files is None
        monkeypatch.setattr(security, "read_text_file_within_root", read)
        return [source]

    monkeypatch.setattr(security, "read_text_file_within_root", stale_reader)
    monkeypatch.setattr(security, "_scan_all_files", walk)
    result = security.check_no_approval_bypass_defaults(tmp_path)
    assert not result.passed
    assert [finding.rule_id for finding in result.findings] == ["RISKY_APPROVAL_DEFAULT"]
    assert reads == [(tmp_path.resolve(), source)]


@pytest.mark.parametrize("helper", ["security_content", "security_mcp", "security_secret_detection"])
def test_security_helpers_can_be_imported_before_the_facade(helper) -> None:
    source_root = Path(security.__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-B", "-c", f"import codex_plugin_scanner.checks.{helper}"],
        env={**os.environ, "PYTHONPATH": str(source_root)},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
