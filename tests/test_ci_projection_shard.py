"""CI projection freshness preserves committed bytes and fails closed."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci import run_projection_shard as runner
from tests import guard_command_decision_diff as generator


@pytest.fixture
def projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, bytes, bytes]:
    report_path = tmp_path / "decision-diff-report.json"
    digest_path = report_path.with_name("decision-diff-report.framed-sha256")
    report = {"schema": "fixture"}
    report_bytes = generator.canonical_json_bytes(report)
    digest_bytes = (generator.report_framed_sha256(report) + "\n").encode("ascii")
    report_path.write_bytes(report_bytes)
    digest_path.write_bytes(digest_bytes)
    monkeypatch.setattr(generator, "REPORT_PATH", report_path)
    return report_path, digest_path, report_bytes, digest_bytes


def test_other_shard_runs_unchanged_without_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    shard = tmp_path / "shard.txt"
    shard.write_text("tests/test_other.py::test_case\n", encoding="utf-8")
    calls: list[list[str]] = []

    def run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(runner.subprocess, "run", run)
    assert runner.main([str(shard), "--", "@" + str(shard), "--cov-branch"]) == 7
    assert len(calls) == 1
    assert calls[0][1:] == ["-m", "pytest", "@" + str(shard), "--cov-branch"]


def test_selected_shard_restores_original_pair_after_test_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, projection
) -> None:
    report_path, digest_path, report_bytes, digest_bytes = projection
    shard = tmp_path / "shard.txt"
    shard.write_text(runner.FRESHNESS_NODE + "\n", encoding="utf-8")
    calls: list[list[str]] = []

    def run(command, **_kwargs):
        calls.append(command)
        if command[-1] == "--write":
            report_path.write_bytes(b"generated report")
            digest_path.write_bytes(b"generated digest")
            return subprocess.CompletedProcess(command, 0)
        assert report_path.read_bytes() == b"generated report"
        assert digest_path.read_bytes() == b"generated digest"
        return subprocess.CompletedProcess(command, 3)

    monkeypatch.setattr(runner.subprocess, "run", run)
    assert runner.main([str(shard), "--", "@" + str(shard), "--cov"]) == 3
    assert len(calls) == 2
    assert report_path.read_bytes() == report_bytes
    assert digest_path.read_bytes() == digest_bytes


def test_generator_failure_restores_both_original_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, projection
) -> None:
    report_path, digest_path, report_bytes, digest_bytes = projection
    shard = tmp_path / "shard.txt"
    shard.write_text(runner.FRESHNESS_NODE + "\n", encoding="utf-8")

    def run(command, **_kwargs):
        report_path.write_bytes(b"partial write")
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(runner.subprocess, "run", run)
    with pytest.raises(subprocess.CalledProcessError):
        runner.main([str(shard), "--", "@" + str(shard)])
    assert report_path.read_bytes() == report_bytes
    assert digest_path.read_bytes() == digest_bytes


def test_corrupt_original_digest_blocks_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, projection) -> None:
    _, digest_path, _, _ = projection
    digest_path.write_bytes(b"0" * 64 + b"\n")
    shard = tmp_path / "shard.txt"
    shard.write_text(runner.FRESHNESS_NODE + "\n", encoding="utf-8")

    def run(*_args, **_kwargs):
        pytest.fail("generation must not run for a corrupt original pair")

    monkeypatch.setattr(runner.subprocess, "run", run)
    with pytest.raises(ValueError, match="framed digest does not match"):
        runner.main([str(shard), "--", "@" + str(shard)])
