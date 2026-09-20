from __future__ import annotations

import subprocess
import sys
from collections import Counter
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
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid, **_kwargs: next(snapshots))
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


@pytest.fixture
def controlled_tree(monkeypatch):
    from types import SimpleNamespace

    from scripts import native_slo_resources as resources

    root = SimpleNamespace(
        pid=42,
        create_time=lambda: 1.0,
        children=lambda **_kwargs: [],
        memory_info=lambda: SimpleNamespace(rss=100),
        memory_full_info=lambda: SimpleNamespace(uss=50),
        cpu_times=lambda: SimpleNamespace(user=1.0, system=0.0),
        num_threads=lambda: 1,
        num_fds=lambda: 3,
    )
    psutil = resources._psutil()
    monkeypatch.setattr(psutil, "Process", lambda _pid: root)
    monkeypatch.setattr(resources.sys, "platform", "linux")
    monkeypatch.setattr(resources, "_stat", lambda _pid, _proc: (1, 1, 100))
    return resources, root


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("missing", "process_lookup_failed"),
        ("denied", "permission_denied"),
        ("os", "os_error"),
        ("value", "invalid_process_data"),
        ("index", "invalid_process_data"),
        ("bound", "process_tree_bound"),
    ],
)
def test_exhausted_sample_retains_fixed_reason_after_exactly_two_attempts(
    controlled_tree, monkeypatch, failure, reason
):
    resources, _root = controlled_tree
    psutil = resources._psutil()
    errors = {
        "missing": psutil.NoSuchProcess(42),
        "denied": psutil.AccessDenied(42),
        "os": OSError("private /home/example/error"),
        "value": ValueError("private malformed process data"),
        "index": IndexError("private field"),
        "bound": resources._ProcessTreeBoundError("private bound"),
    }
    calls = []

    def unavailable(_root):
        calls.append(None)
        raise errors[failure]

    monkeypatch.setattr(resources, "_inventory", unavailable)
    sampler = resources.ResourceSampler(pid=42)
    sampler._sample()
    report = sampler.report(attempted=600)
    assert len(calls) == 2
    assert report["samples"] == 0 and report["unavailable_samples"] == 1
    assert report["unavailable_sample_reasons"] == {reason: 1}
    assert report["unavailable_sample_reason_scope"] == "last_failed_attempt_after_two_attempts"
    assert report["sample_minimum_met"] is False
    assert "private" not in repr(report["unavailable_sample_reasons"])
    role = "root" if failure in {"missing", "denied"} else "unknown"
    assert report["unavailable_sample_operations"] == {f"inventory_before:{role}": 1}
    assert report["unavailable_sample_operation_scope"] == "last_failed_attempt_after_two_attempts"


def test_changed_inventory_twice_is_one_missing_sample(controlled_tree, monkeypatch):
    resources, root = controlled_tree
    inventories = iter([{(42, 1.0): root}, {}, {(42, 1.0): root}, {}])
    calls = []

    def inventory(_root):
        calls.append(None)
        return next(inventories)

    monkeypatch.setattr(resources, "_inventory", inventory)
    sampler = resources.ResourceSampler(pid=42)
    sampler._sample()
    assert len(calls) == 4
    assert sampler.samples == 0 and sampler.missing == 1
    assert sampler.missing_reasons == Counter(inventory_changed=1)
    assert sampler.missing_operations == Counter({"inventory_after:unknown": 1})


def test_retry_success_does_not_count_as_a_missing_sample(controlled_tree, monkeypatch):
    resources, root = controlled_tree
    calls = []

    def inventory(_root):
        calls.append(None)
        if len(calls) == 1:
            raise OSError("first attempt only")
        return {(42, 1.0): root}

    monkeypatch.setattr(resources, "_inventory", inventory)
    sampler = resources.ResourceSampler(pid=42)
    sampler._sample()
    assert len(calls) == 3
    assert sampler.samples == 1 and sampler.missing == 0
    assert sampler.missing_reasons == Counter()
    assert sampler.missing_operations == Counter()


def test_terminal_reason_does_not_claim_to_explain_both_attempts(controlled_tree, monkeypatch):
    resources, _root = controlled_tree
    errors = iter([resources._psutil().AccessDenied(42), ValueError("second attempt")])

    def inventory(_root):
        raise next(errors)

    monkeypatch.setattr(resources, "_inventory", inventory)
    reasons = Counter()
    assert resources.sample_process_tree(42, unavailable_reasons=reasons) is None
    assert reasons == Counter(invalid_process_data=1)


@pytest.mark.parametrize("last_cpu", [9.0, float("nan"), float("inf")])
def test_invalid_linux_cpu_delta_fails_cpu_coverage_with_thirty_valid_snapshots(monkeypatch, last_cpu):
    from scripts import native_slo_resources as resources

    snapshots = iter(
        resources.TreeResources(100, 50, value, 1, 1, 3, process_cpu={(42, 1.0): value}, cpu_includes_reaped=True)
        for value in [10.0] * 29 + [last_cpu]
    )
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid, **_kwargs: next(snapshots))
    sampler = resources.ResourceSampler(pid=42)
    for _ in range(30):
        sampler._sample()
    sampler.started, sampler.stopped = 1.0, 31.0
    report = sampler.report(attempted=600)
    assert report["samples"] == 30 and report["unavailable_samples"] == 0
    assert report["metric_samples"]["cpu_seconds"] == 30
    assert report["cpu_seconds"] is report["cpu_ms_per_attempt"] is None
    assert report["unavailable_metrics"] == {"cpu_seconds": {"invalid_cumulative_delta": 1}}
    assert report["metric_minimum_met"]["cpu_seconds"] is False
    assert report["metric_minimum_met"]["rss_bytes"] is True
    assert report["sample_minimum_met"] is False
    assert sampler.report(attempted=600) == report
    assert sampler.unavailable == {}


def test_one_missing_sample_still_fails_every_required_metric_after_250_valid(monkeypatch):
    from scripts import native_slo_resources as resources

    values = iter(range(251))

    def sample(_pid, *, unavailable_reasons, unavailable_operations):
        value = next(values)
        if value == 125:
            unavailable_reasons["inventory_changed"] += 1
            unavailable_operations["inventory_after:unknown"] += 1
            return None
        return resources.TreeResources(
            100, 50, float(value), 1, 1, 3, process_cpu={(42, 1.0): float(value)}, cpu_includes_reaped=True
        )

    monkeypatch.setattr(resources, "sample_process_tree", sample)
    sampler = resources.ResourceSampler(pid=42)
    for _ in range(251):
        sampler._sample()
    report = sampler.report(attempted=600)
    assert sampler.interval == 0.1
    assert report["samples"] == 250 and report["unavailable_samples"] == 1
    assert report["unavailable_sample_reasons"] == {"inventory_changed": 1}
    assert report["unavailable_sample_operations"] == {"inventory_after:unknown": 1}
    assert all(count == 250 for count in report["metric_samples"].values() if count)
    assert all(value is False for value in report["metric_minimum_met"].values())
    assert report["sample_minimum_met"] is False
    assert report["cpu_seconds"] == 250.0
    assert report["cpu_ms_per_attempt"] == round(250_000 / 600, 6)


def test_linux_waited_child_cpu_does_not_qualify_all_short_lived_descendants(controlled_tree, monkeypatch):
    from scripts.native_slo_acceptance import resource_comparisons

    resources, _root = controlled_tree
    ticks = iter(range(100, 130))
    monkeypatch.setattr(resources, "_stat", lambda _pid, _proc: (1, 1, next(ticks)))
    sampler = resources.ResourceSampler(pid=42)
    for _ in range(30):
        sampler._sample()
    report = sampler.report(attempted=600)
    assert report["sample_minimum_met"] is True
    assert report["cpu_ms_per_attempt"] > 0
    assert report["cpu_includes_reaped_descendants"] is True
    assert report["short_exited_descendants_cpu_complete"] is False
    assert report["short_exited_descendants_cpu_scope"] == "current_tree_and_waited_children_only"
    arm = [{"resources": report}] * 5
    comparison = resource_comparisons(arm, arm)
    assert comparison["cpu_ms_per_attempt"] == {"qualified": False}
    assert comparison["rss_bytes"]["qualified"] is True
    assert comparison["private_bytes"]["qualified"] is True


@pytest.mark.parametrize("role", ["root", "descendant"])
@pytest.mark.parametrize("operation", ["memory_info", "num_fds", "cpu_times"])
def test_exited_process_records_exact_operation_without_identifiers(controlled_tree, role, operation):
    from types import SimpleNamespace

    resources, root = controlled_tree
    target = root if role == "root" else SimpleNamespace(**{**vars(root), "pid": 987654321})
    if role == "descendant":
        root.children = lambda **_kwargs: [target]
    calls = []

    def exited():
        calls.append(None)
        raise resources._psutil().NoSuchProcess(target.pid, name="private-process-name")

    setattr(target, operation, exited)
    sampler = resources.ResourceSampler(pid=42)
    sampler._sample()
    report = sampler.report(attempted=600)
    expected = {"memory_info": "rss_bytes", "num_fds": "descriptors", "cpu_times": "cpu_times"}[operation]
    assert len(calls) == 2
    assert report["unavailable_sample_operations"] == {f"{expected}:{role}": 1}
    assert report["unavailable_sample_reasons"] == {"process_lookup_failed": 1}
    assert report["sample_minimum_met"] is False
    assert "987654321" not in repr(report) and "private-process-name" not in repr(report)


@pytest.mark.parametrize("role", ["root", "descendant"])
def test_denied_descriptors_record_role_and_keep_the_metric_unavailable(controlled_tree, role):
    from types import SimpleNamespace

    resources, root = controlled_tree
    target = root if role == "root" else SimpleNamespace(**{**vars(root), "pid": 987654321})
    if role == "descendant":
        root.children = lambda **_kwargs: [target]
    calls = []

    def denied():
        calls.append(None)
        raise resources._psutil().AccessDenied(target.pid, name="private-process-name")

    target.num_fds = denied
    sampler = resources.ResourceSampler(pid=42)
    for _ in range(30):
        sampler._sample()
    report = sampler.report(attempted=600)
    assert len(calls) == report["samples"] == 30
    assert report["unavailable_samples"] == 0
    assert report["unavailable_sample_operations"] == {}
    assert report["unavailable_metrics"]["descriptors"] == {"permission_denied": 30}
    assert report["unavailable_metric_roles"] == {"descriptors": {role: 30}}
    assert report["unavailable_metric_role_scope"] == "last_permission_denial_per_metric_in_each_returned_sample"
    assert report["peak"]["descriptors"] is None
    assert report["metric_minimum_met"]["rss_bytes"] is True
    assert report["metric_minimum_met"]["descriptors"] is report["sample_minimum_met"] is False
    assert "987654321" not in repr(report) and "private-process-name" not in repr(report)
