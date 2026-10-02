"""The shard entry point must never regenerate or restore tracked fixtures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci import run_projection_shard as runner


@pytest.mark.parametrize("node", [runner.FRESHNESS_NODE, "tests/test_other.py::test_case"])
@pytest.mark.parametrize("exit_code", [0, 1, 2, 3, 4, 5])
def test_shard_runs_once_and_preserves_fixture_bytes(tmp_path: Path, monkeypatch, node, exit_code):
    report = tmp_path / "decision-diff-report.json"
    report.write_bytes(b"historical bytes are not today's expected implementation")
    shard = tmp_path / "shard.txt"
    shard.write_text(node + "\n")
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        assert kwargs == {"cwd": runner.ROOT, "check": False}
        return subprocess.CompletedProcess(command, exit_code)

    monkeypatch.setattr(runner.subprocess, "run", execute)
    assert runner.main([str(shard), "--", "@" + str(shard), "--cov-branch"]) == exit_code
    assert len(calls) == 1
    assert calls[0][1:] == ["-m", "pytest", "@" + str(shard), "--cov-branch"]
    assert report.read_bytes() == b"historical bytes are not today's expected implementation"


def test_missing_shard_is_not_treated_as_success(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: pytest.fail("missing plan must not execute"))
    with pytest.raises(FileNotFoundError):
        runner.main([str(tmp_path / "missing.txt")])
