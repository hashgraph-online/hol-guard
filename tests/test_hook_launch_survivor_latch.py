"""An unsettled hook survivor stays tracked until its process is confirmed gone."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch

_ANSWER = {
    "returncode": 0,
    "stdout": "",
    "stderr": "",
    "output_limit_exceeded": False,
    "timed_out": False,
    "containment_failed": False,
    "capture_incomplete": False,
    "quarantine_settled": True,
    "survivors": [],
}


@pytest.fixture(autouse=True)
def _clean_latch():
    launch._HOOK_PROCESS_SURVIVORS.clear()
    yield
    launch._HOOK_PROCESS_SURVIVORS.clear()


def _run(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> launch.BoundedHookProcessResult:
    def exchange(*args: object, **kwargs: object) -> tuple[dict[str, object], bool]:
        return answer, True

    monkeypatch.setattr(launch, "_exchange", exchange)
    return launch.run_isolated_hook_process(
        ["true"],
        input_text="",
        cwd=Path.cwd(),
        environment={},
        timeout_seconds=5.0,
        launcher="native-launcher",
    )


def test_a_later_contained_launch_does_not_clear_an_unsettled_survivor(monkeypatch: pytest.MonkeyPatch) -> None:
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        unsettled = {
            **_ANSWER,
            "containment_failed": True,
            "quarantine_settled": False,
            "survivors": [holder.pid],
        }
        assert _run(monkeypatch, unsettled).containment_failed
        assert launch.hook_processes_contained() is False
        # A launch that contained its own child says nothing about the survivor.
        refused = _run(monkeypatch, dict(_ANSWER))
        assert refused.containment_failed
        assert launch.hook_processes_contained() is False
    finally:
        holder.kill()
        holder.wait()


@pytest.mark.skipif(os.name == "nt", reason="the stop probe is POSIX only")
def test_the_latch_clears_once_the_survivor_is_confirmed_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    unsettled = {**_ANSWER, "containment_failed": True, "quarantine_settled": False, "survivors": [holder.pid]}
    _run(monkeypatch, unsettled)
    assert launch.hook_processes_contained() is False
    holder.kill()
    holder.wait()
    deadline = time.monotonic() + 5
    while not launch.hook_processes_contained() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert launch.hook_processes_contained() is True
    assert _run(monkeypatch, dict(_ANSWER)).containment_failed is False


def test_a_survivor_the_launcher_cannot_name_is_never_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    unsettled = {**_ANSWER, "containment_failed": True, "quarantine_settled": False}
    _run(monkeypatch, unsettled)
    assert launch.hook_processes_contained() is False
    assert _run(monkeypatch, dict(_ANSWER)).containment_failed
    assert launch.hook_processes_contained() is False
