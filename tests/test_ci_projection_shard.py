"""Source preparation failures must stop shard execution."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci import run_projection_shard as runner


def test_source_preparation_failure_stops_shard(tmp_path: Path, monkeypatch, capsys):
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
    assert "Starting pytest" not in capsys.readouterr().out


def test_missing_shard_is_not_treated_as_success(tmp_path: Path, monkeypatch):
    """Verify missing shard is not treated as success."""
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: pytest.fail("missing plan must not execute"))
    with pytest.raises(FileNotFoundError):
        runner.main([str(tmp_path / "missing.txt")])


def test_combined_preparation_timeout_stops_shard(tmp_path, monkeypatch, capsys):
    shard = tmp_path / "shard.txt"
    shard.write_text("tests/test_other.py::test_case\n")
    monkeypatch.setenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", "/native/guard-command-source")

    def execute(command, **kwargs):
        assert "-m" not in command, "pytest must not execute after preparation times out"
        assert command[-1] == "--prepare-directory"
        assert kwargs["timeout"] == 300
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(runner.subprocess, "run", execute)
    assert runner.main([str(shard)]) == 124
    output = capsys.readouterr()
    assert "Projection preparation timed out after 300s" in output.err
    assert "Starting pytest" not in output.out


def test_pytest_start_marker_is_flushed_before_launch(tmp_path, monkeypatch, capsys):
    shard = tmp_path / "shard.txt"
    shard.write_text("tests/test_other.py::test_case\n")
    monkeypatch.setenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", "/native/guard-command-source")
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if "-m" in command:
            assert capsys.readouterr().out == "Starting pytest\n"
        else:
            assert "Starting pytest" not in capsys.readouterr().out
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runner.subprocess, "run", execute)
    assert runner.main([str(shard), "--", "@" + str(shard)]) == 0
    assert len(calls) == 2


def test_preparation_pins_the_runtime_binary_in_force_mode(tmp_path, monkeypatch):
    shard = tmp_path / "shard.txt"
    shard.write_text("tests/test_other.py::test_case\n")
    monkeypatch.setenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", "/native/guard-command-source")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", "/native/hol-guard-runtime")
    monkeypatch.delenv("HOL_GUARD_NATIVE", raising=False)
    environments = []

    def execute(command, **kwargs):
        if "-m" not in command:
            environments.append(kwargs["env"])
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(runner.subprocess, "run", execute)
    assert runner.main([str(shard)]) == 0
    assert environments[0]["HOL_GUARD_NATIVE"] == "force"
    assert environments[0]["HOL_GUARD_NATIVE_BINARY"] == "/native/hol-guard-runtime"
