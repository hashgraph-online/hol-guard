"""Installed native corpus worker errors retain their worker context."""

from __future__ import annotations

import subprocess

import pytest

from scripts import run_installed_native_corpus


def test_invalid_worker_report_identifies_the_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        run_installed_native_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "not-json", ""),
    )

    with pytest.raises(ValueError, match="worker 3 emitted an invalid report"):
        run_installed_native_corpus._run_installed_worker(3)


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
