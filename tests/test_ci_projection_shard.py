"""Source preparation failures must stop shard execution."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci import run_projection_shard as runner


def test_source_preparation_failure_stops_shard(tmp_path: Path, monkeypatch):
    """Never run directory consumers against incomplete or invalid projections."""
    shard = tmp_path / "shard.txt"
    shard.write_text("tests/test_other.py::test_case\n")
    monkeypatch.setenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", "/native/guard-command-source")

    def execute(command, **kwargs):
        if "-m" in command:
            pytest.fail("pytest must not execute after source preparation fails")
        return subprocess.CompletedProcess(command, 2)

    monkeypatch.setattr(runner.subprocess, "run", execute)
    assert runner.main([str(shard), "--", "@" + str(shard)]) == 2


def test_missing_shard_is_not_treated_as_success(tmp_path: Path, monkeypatch):
    """Verify missing shard is not treated as success."""
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: pytest.fail("missing plan must not execute"))
    with pytest.raises(FileNotFoundError):
        runner.main([str(tmp_path / "missing.txt")])
