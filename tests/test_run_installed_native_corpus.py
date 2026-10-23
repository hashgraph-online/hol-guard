"""Installed native corpus worker errors retain their worker context."""

from __future__ import annotations

import subprocess

import pytest

from scripts import run_installed_canary, run_installed_native_corpus


def test_timeout_detail_keeps_recent_frames_when_later_progress_is_noisy() -> None:
    blocked = 'Thread 0x123 (most recent call first):\n  File "worker.py", line 10 in blocked_native_batch'
    stderr = "corpus_phase native-batch batch=1 started\n" + blocked
    stderr += "\n" + ('  File "caller.py", line 20 in older_frame\n' * 100)
    stderr += "\n" + ("corpus_phase native-batch batch=99 elapsed=0.1\n" * 100)
    detail = run_installed_native_corpus._failure_detail(stderr)
    assert "blocked_native_batch" in detail
    assert detail.startswith("corpus_phase native-batch batch=99 elapsed=0.1\nThread 0x123")
    assert len(detail) < 1400


def test_invalid_worker_report_identifies_the_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        run_installed_native_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "not-json", ""),
    )

    with pytest.raises(ValueError, match="worker 3 emitted an invalid report"):
        run_installed_native_corpus._run_installed_worker(3)


def test_outer_canary_error_retains_phase_totals_after_clipping_nested_traceback() -> None:
    native = "corpus_phase native-batch batch=88 elapsed=0.2 total=17.6"
    projection = "corpus_phase resident-projection batch=88 started total=30.4"
    stderr = f"ValueError: worker 2 timed out: {native}\n{projection}\n" + ("older frame\n" * 200)
    detail = run_installed_canary._corpus_failure_detail(stderr)
    assert native in detail and projection in detail
    assert len(detail) < 1600
    assert run_installed_canary._corpus_failure_detail("x" * 2000) == "x" * 1200


def test_worker_error_preserves_both_phases_and_the_most_recent_stack() -> None:
    native = "corpus_phase native-batch batch=50 elapsed=0.2 total=10.0"
    projection = "corpus_phase resident-projection batch=50 started total=22.0"
    stderr = f"{native}\n{projection}\nThread 0x123 (most recent call first):\nblocked_frame\n"
    detail = run_installed_native_corpus._failure_detail(stderr)
    assert detail.startswith(f"{native}\n{projection}\nThread 0x123")


def test_phase_timer_accumulates_cost_without_logging_case_material(monkeypatch, capsys) -> None:
    from tests import guard_command_corpus_native as native

    monkeypatch.setattr(native, "real_native_review_fixtures", lambda *_args, **_kwargs: "answer")
    monkeypatch.setattr(native, "project_native_review_fixtures_batch", lambda *_args, **_kwargs: "projection")
    samples = iter([100.0, 100.25, 101.0, 101.5])
    monkeypatch.setattr(run_installed_native_corpus.time, "perf_counter", lambda: next(samples))
    run_installed_native_corpus._install_worker_diagnostics()
    assert native.real_native_review_fixtures("private-case-material") == "answer"
    assert native.real_native_review_fixtures("private-case-material") == "answer"
    output = capsys.readouterr()
    assert output.out == ""
    assert "private-case-material" not in output.err
    assert "batch=2 elapsed=0.500 total=0.750" in output.err


@pytest.mark.parametrize("platform,expected_timeout", [("win32", 180), ("linux", 60)])
def test_installed_worker_keeps_platform_specific_hard_timeout(monkeypatch, platform, expected_timeout):
    monkeypatch.setattr(run_installed_native_corpus.sys, "platform", platform)
    captured = []

    def launch(*args, **kwargs):
        captured.append(kwargs["timeout"])
        return subprocess.CompletedProcess([], 0, "not-json", "")

    monkeypatch.setattr(run_installed_native_corpus.subprocess, "run", launch)
    with pytest.raises(ValueError, match="invalid report"):
        run_installed_native_corpus._run_installed_worker(0)
    assert captured == [expected_timeout]
