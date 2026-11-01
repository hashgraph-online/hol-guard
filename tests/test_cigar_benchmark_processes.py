"""The benchmark must retain owned children without counting unrelated PIDs."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import cigar_benchmark_processes as processes


def row(pid: int, parent: int, kib: int, name: str, second: int = 0, state: str = "S") -> str:
    return f"{pid} {parent} {kib} {state} Sat Oct 24 05:40:{second:02d} 2026 {name}"


def frame(monkeypatch, rows: list[str]) -> None:
    class Process:
        pid = 999_999_991
        returncode = 0

        def __init__(self, arguments, **_kwargs):
            assert arguments == ["/bin/ps", "-axo", "pid=,ppid=,rss=,stat=,lstart=,comm="]

        def communicate(self, *, timeout):
            assert timeout == 1
            return "\n".join(rows), ""

    monkeypatch.setattr(processes, "_system_ps_path", lambda: Path("/bin/ps"))
    monkeypatch.setattr(processes.subprocess, "Popen", Process)


def test_framework_bridge_and_reparented_workers_keep_complete_owned_rss(monkeypatch):
    sampler = processes.ProcessSampler(Path(processes.sys.executable))
    root = sampler.root
    frame(
        monkeypatch,
        [
            row(root, 1, 100, "host-python"),
            row(501, root, 200, "hol-guard-runtime"),
            row(502, 501, 300, "Python"),  # Framework comm differs from bin/python3.14.
            row(503, 502, 400, "cigar-context-worker"),
            row(504, 502, 500, "cigar-context-worker"),
            row(505, 1, 900, "cigar-context-worker"),  # Another application.
            row(999_999_991, root, 700, "ps"),  # The measurement itself.
        ],
    )
    first = sampler.sample()
    assert first["rss_bytes"] == 1500 * 1024
    assert first["counts"] == {"benchmark_daemon_host": 1, "native_runtime": 1, "python_bridge": 1, "sdk_worker": 2}
    # Native owner exited. The still-live original SDK tree is now adopted by
    # init; an unrelated process reuses the old native PID with a new start.
    frame(
        monkeypatch,
        [
            row(root, 1, 100, "host-python"),
            row(501, 1, 5000, "hol-guard-runtime", second=1),
            row(502, 1, 300, "Python"),
            row(503, 502, 400, "cigar-context-worker"),
            row(504, 502, 500, "cigar-context-worker"),
            row(505, 1, 900, "cigar-context-worker"),
        ],
    )
    second = sampler.sample()
    assert second["rss_bytes"] == 1300 * 1024
    assert second["counts"] == {"benchmark_daemon_host": 1, "python_bridge": 1, "sdk_worker": 2}
    summary = sampler.summary()
    assert summary["peak_rss_bytes"] == 1500 * 1024
    assert summary["at_peak_rss_by_kind"]["sdk_worker"] == 900 * 1024


def test_exited_host_python_child_is_reported_separately_from_live_optional_workers(monkeypatch):
    sampler = processes.ProcessSampler(Path(processes.sys.executable))
    frame(monkeypatch, [row(sampler.root, 1, 100, "host-python"), row(601, sampler.root, 0, "(python3.12)", state="Z")])
    observed = sampler.sample()
    assert observed["rss_bytes"] == 100 * 1024
    assert observed["counts"] == {"benchmark_daemon_host": 1, "terminated_child": 1}


def test_live_host_framework_child_uses_kernel_image_instead_of_ambiguous_comm(monkeypatch):
    monkeypatch.setattr(processes, "kernel_image", lambda _pid: Path("/trusted/host/Python"))
    sampler = processes.ProcessSampler(Path(processes.sys.executable))
    frame(monkeypatch, [row(sampler.root, 1, 100, "host-python"), row(602, sampler.root, 50, "Python")])
    observed = sampler.sample()
    assert observed["counts"] == {"benchmark_daemon_host": 1, "guard_python_worker": 1}
    assert observed["rss_bytes"] == 150 * 1024


def test_host_exit_name_is_not_mistaken_for_an_optional_interpreter_between_ps_and_image_lookup(monkeypatch):
    monkeypatch.setattr(processes, "kernel_image", lambda _pid: None)
    sampler = processes.ProcessSampler(Path(processes.sys.executable))
    frame(
        monkeypatch,
        [
            row(sampler.root, 1, 100, "host-python"),
            row(603, sampler.root, 0, f"({sampler.host_python.name})", state="R"),
        ],
    )
    assert sampler.sample()["counts"] == {"benchmark_daemon_host": 1, "exiting_host_python_child": 1}


@pytest.mark.parametrize("rows", [[], ["123 1 200 malformed"]])
def test_missing_owner_or_malformed_metadata_cannot_establish_coverage(monkeypatch, rows):
    sampler = processes.ProcessSampler(Path(processes.sys.executable))
    frame(monkeypatch, rows)
    with pytest.raises((RuntimeError, ValueError)):
        sampler.sample()
    assert sampler.samples == []


def test_fixture_identity_baseline_keeps_existing_rss_and_detects_pid_reuse(monkeypatch):
    sampler = processes.ProcessSampler(Path(processes.sys.executable))
    frame(monkeypatch, [row(sampler.root, 1, 100, "host-python"), row(701, sampler.root, 200, "hol-guard-runtime")])
    before, baseline = sampler.sample_with_identities()
    assert before["rss_bytes"] == 300 * 1024 and len(baseline) == 1
    frame(
        monkeypatch,
        [
            row(sampler.root, 1, 100, "host-python"),
            row(701, sampler.root, 200, "hol-guard-runtime", second=1),
            row(702, sampler.root, 0, "hol-guard-runtime", state="Z"),
        ],
    )
    after, current = sampler.sample_with_identities()
    assert after["rss_bytes"] == 300 * 1024
    assert len(current) == 1 and len(current.keys() - baseline.keys()) == 1
    assert all("pid" not in key and "identity" not in key for key in sampler.summary())
