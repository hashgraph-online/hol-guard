"""Process-origin fallback remains bounded and separate from authorization."""

import subprocess

import pytest

from codex_plugin_scanner.guard.runtime import harness_attribution as attribution


@pytest.mark.parametrize(
    "executable,harness",
    [("codex", "codex"), ("pi", "pi"), ("omp", "omp"), ("zcode", "zcode"), ("zcode-cli", "zcode"), ("grok", "grok")],
)
def test_nearest_harness_ancestor_without_reading_arguments(monkeypatch, executable, harness):
    monkeypatch.setattr(attribution.os, "name", "posix")
    monkeypatch.setattr(attribution.os, "getppid", lambda: 42)
    rows = f"42 41 /bin/zsh\n41 40 /opt/apps/{executable}\n40 1 /opt/apps/cursor"
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert command[-1] == "pid=,ppid=,comm="
        assert 0 < kwargs["timeout"] <= 0.5
        return subprocess.CompletedProcess(command, 0, rows, "")

    monkeypatch.setattr(attribution.subprocess, "run", run)
    assert attribution.resolve_parent_process_harness() == harness
    assert len(calls) == 1


@pytest.mark.parametrize(
    "row",
    [
        "42 1 /bin/zsh",
        "42 42 /bin/zsh",
        "malformed",
        "42 1 /opt/codex-helper",
        "42 1 /opt/grok-helper",
        "42 1 /opt/node",
        "42 1 /opt/python",
    ],
)
def test_unknown_malformed_and_cyclic_ancestry_stays_unknown(monkeypatch, row):
    monkeypatch.setattr(attribution.os, "name", "posix")
    monkeypatch.setattr(attribution.os, "getppid", lambda: 42)
    monkeypatch.setattr(attribution.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, row, ""))
    assert attribution.resolve_parent_process_harness() is None


def test_timeout_does_not_break_package_review(monkeypatch):
    monkeypatch.setattr(attribution.os, "name", "posix")
    monkeypatch.setattr(attribution.os, "getppid", lambda: 42)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("ps", 0.5)

    monkeypatch.setattr(attribution.subprocess, "run", timeout)
    assert attribution.resolve_parent_process_harness() is None
