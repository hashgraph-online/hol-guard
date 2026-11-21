"""Signal ownership guards for the real-process installed fault fixture."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from tests import context_process_fault as faults


@pytest.fixture
def processes(monkeypatch):
    root = os.getpid()
    rows = {
        101: faults.Row(root, 101, ("native-start",), "hol-guard-runtime", "S"),
        102: faults.Row(101, 102, ("python-start",), "Python", "S"),
        103: faults.Row(102, 102, ("worker-one",), "cigar-context-worker", "S"),
        104: faults.Row(102, 102, ("worker-two",), "cigar-context-worker", "S"),
    }
    images = {
        101: Path("/qualified-native"),
        102: Path("/qualified-python"),
        103: Path("/qualified-worker"),
        104: Path("/qualified-worker"),
    }
    digests = {
        Path("/selected-native"): "native",
        Path("/qualified-native"): "native",
        Path("/qualified-worker"): "worker",
        Path("/wrong-worker"): "wrong",
        Path("/wrong-native"): "wrong",
    }
    monkeypatch.setattr(faults, "_snapshot", lambda: dict(rows))
    monkeypatch.setattr(faults, "kernel_image", images.get)
    monkeypatch.setattr(faults, "_python_image", lambda *_: Path("/qualified-python"))
    monkeypatch.setattr(faults, "_digest", digests.__getitem__)
    signals = []
    monkeypatch.setattr(faults.os, "kill", lambda pid, value: signals.append((pid, value)))
    return rows, images, signals


def capture():
    return faults.OwnedOptionalProcesses.capture(
        Path("/selected-native"),
        {"python": "/selected-python"},
        {"python_sha256": "python", "worker_sha256": "worker"},
    )


@pytest.mark.parametrize("mismatch", ["ancestry", "worker", "python", "native", "group"])
def test_capture_refuses_unowned_or_wrong_artifact_processes_before_signalling(processes, mismatch):
    rows, images, signals = processes
    if mismatch == "ancestry":
        rows[101] = replace(rows[101], parent=1)
    elif mismatch == "group":
        rows[104] = replace(rows[104], group=999)
    else:
        images[{"worker": 104, "python": 102, "native": 101}[mismatch]] = Path(f"/wrong-{mismatch}")
    with pytest.raises(AssertionError, match="expected one qualified optional process group"):
        capture()
    assert signals == []


@pytest.mark.parametrize("change", ["PID-reuse", "exec", "reparent"])
def test_changed_identity_after_capture_refuses_every_signal(processes, change):
    rows, images, signals = processes
    owned = capture()
    if change == "PID-reuse":
        rows[103] = replace(rows[103], start=("new-worker",))
    elif change == "reparent":
        rows[102] = replace(rows[102], parent=999)
    else:
        images[103] = Path("/wrong-worker")
    with pytest.raises(AssertionError, match="changed before fault injection"):
        owned.interrupt("sdk-crash")
    assert signals == []


def test_failed_fixture_fallback_never_signals_a_reused_pid(processes):
    rows, _images, signals = processes
    owned = capture()
    for pid in (102, 103, 104):
        rows[pid] = replace(rows[pid], start=("unrelated-new-lifetime",))
    owned.cleanup_owned()
    assert signals == []
    assert owned.metrics["fallback_signals"] == 0
