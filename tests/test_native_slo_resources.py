from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.native_slo_resources import sample_process_tree


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux proc collector")
def test_resource_snapshot_includes_live_grandchildren_and_private_memory() -> None:
    program = """
import subprocess, sys
memory = bytearray(2 * 1024 * 1024)
child = subprocess.Popen([sys.executable, "-c", "import time; memory=bytearray(4*1024*1024); time.sleep(30)"])
print("ready", flush=True)
try:
    sys.stdin.read(1)
finally:
    child.terminate()
    child.wait()
"""
    process = subprocess.Popen([sys.executable, "-c", program], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        assert process.stdout is not None and process.stdout.readline() == b"ready\n"
        snapshot = sample_process_tree(process.pid)
        assert snapshot is not None
        assert snapshot.processes == 2
        assert snapshot.threads >= 2
        assert snapshot.descriptors >= 6
        assert snapshot.rss_bytes >= snapshot.private_bytes > 2 * 1024 * 1024
        assert snapshot.cpu_seconds >= 0
    finally:
        process.communicate(b"x", timeout=5)


def test_missing_process_tree_is_unavailable(tmp_path: Path) -> None:
    assert sample_process_tree(123, proc=tmp_path) is None


def test_windows_handles_and_denied_uss_remain_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from scripts import native_slo_resources as resources

    class AccessDeniedError(Exception):
        pass

    class Process:
        pid = 42

        def create_time(self) -> float:
            return 123.0

        def children(self, **_kwargs: object) -> list[object]:
            return []

        def memory_info(self) -> object:
            return SimpleNamespace(rss=8192)

        def memory_full_info(self) -> object:
            raise AccessDeniedError

        def cpu_times(self) -> object:
            return SimpleNamespace(user=0.2, system=0.1)

        def num_threads(self) -> int:
            return 3

        def num_handles(self) -> int:
            return 7

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(
        resources,
        "_psutil",
        lambda: SimpleNamespace(
            Process=lambda _pid: Process(), AccessDenied=AccessDeniedError, NoSuchProcess=ProcessLookupError
        ),
    )
    snapshot = resources.sample_process_tree(42)
    assert snapshot is not None
    assert snapshot.rss_bytes == 8192
    assert snapshot.private_bytes is None
    assert snapshot.unavailable["private_bytes"] == "permission_denied"
    assert snapshot.descriptors is None
    assert snapshot.handles == 7
    assert snapshot.cpu_includes_reaped is False


def test_non_linux_cpu_retains_observed_exited_processes_without_claiming_complete_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import native_slo_resources as resources

    snapshots = iter(
        [
            resources.TreeResources(100, 50, 1.0, 1, 1, 3, process_cpu={(10, 1.0): 1.0}),
            resources.TreeResources(200, 100, 1.9, 2, 2, 6, process_cpu={(10, 1.0): 1.4, (20, 2.0): 0.5}),
            resources.TreeResources(100, 50, 1.5, 1, 1, 3, process_cpu={(10, 1.0): 1.5}),
        ]
    )
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid: next(snapshots))
    sampler = resources.ResourceSampler(pid=10)
    for _ in range(3):
        sampler._sample()
    result = sampler.report(attempted=10)
    assert result["cpu_seconds"] == 1.0
    assert result["cpu_includes_reaped_descendants"] is False
    assert result["short_exited_descendants_cpu_complete"] is False
    assert result["includes_load_generator"] is False


def test_missing_psutil_is_an_explicit_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import native_slo_resources as resources

    monkeypatch.setitem(sys.modules, "psutil", None)
    with pytest.raises(RuntimeError, match="pinned psutil"):
        resources.ResourceSampler()
