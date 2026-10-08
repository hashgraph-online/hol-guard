"""Scheduler, isolation and cancellation tests for ``--jobs``. No live inference is started."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet import case_worker, host_process, parallel, runner
from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import scenario_fixture_name


class FakeWorker:
    def __init__(self, name: str, log: list[str], ticks: int, fail: bool = False):
        self.name, self.log, self.ticks, self.fail = name, log, ticks, fail
        self.state = "running"

    def poll(self) -> int | None:
        if self.state == "running":
            self.ticks -= 1
            if self.ticks <= 0:
                self.state = "done"
        return None if self.state == "running" else 0

    def collect(self) -> str:
        if self.fail:
            raise RuntimeError("worker failed")
        return self.name

    def terminate(self) -> None:
        self.log.append(f"terminate:{self.name}")

    def kill(self) -> None:
        self.log.append(f"kill:{self.name}")
        self.state = "done"


def _no_sleep(_seconds: float) -> None:
    return None


def test_results_follow_input_order_not_completion_order() -> None:
    ticks = {"a": 5, "b": 1, "c": 3, "d": 2}
    completed: list[int] = []
    results = parallel.run_scheduled(
        list(ticks),
        jobs=4,
        spawn=lambda name: FakeWorker(name, [], ticks[name]),
        on_complete=lambda index, _result: completed.append(index),
        sleep=_no_sleep,
    )
    assert results == ["a", "b", "c", "d"]
    assert completed != sorted(completed)


def test_concurrency_never_exceeds_jobs() -> None:
    live: list[FakeWorker] = []
    peak = 0

    def spawn(name: str) -> FakeWorker:
        nonlocal peak
        worker = FakeWorker(name, [], 3)
        live.append(worker)
        peak = max(peak, sum(w.state == "running" for w in live))
        return worker

    parallel.run_scheduled(list("abcdefg"), jobs=3, spawn=spawn, sleep=_no_sleep)
    assert peak == 3


def test_jobs_one_runs_strictly_one_at_a_time() -> None:
    events: list[str] = []

    class Serial(FakeWorker):
        def __init__(self, name: str):
            super().__init__(name, events, 2)
            events.append(f"start:{name}")

        def collect(self) -> str:
            events.append(f"end:{self.name}")
            return self.name

    parallel.run_scheduled(["a", "b"], jobs=1, spawn=Serial, sleep=_no_sleep)
    assert events == ["start:a", "end:a", "start:b", "end:b"]


@pytest.mark.parametrize("jobs", [0, -1, parallel.MAX_JOBS + 1, True])
def test_jobs_are_bounded(jobs: Any) -> None:
    with pytest.raises(ValueError):
        parallel.validate_jobs(jobs)


def test_worker_failure_cancels_and_reaps_every_inflight_worker() -> None:
    log: list[str] = []
    workers = {"a": FakeWorker("a", log, 1, fail=True), "b": FakeWorker("b", log, 99), "c": FakeWorker("c", log, 99)}
    with pytest.raises(RuntimeError):
        parallel.run_scheduled(list(workers), jobs=3, spawn=lambda n: workers[n], sleep=_no_sleep, grace=0.0)
    assert {"terminate:b", "terminate:c", "kill:b", "kill:c"} <= set(log)
    assert "terminate:a" not in log


def test_spawn_failure_and_interrupt_reap_started_workers() -> None:
    log: list[str] = []

    def spawn(name: str) -> FakeWorker:
        if name == "c":
            raise OSError("cannot start")
        return FakeWorker(name, log, 99)

    with pytest.raises(OSError):
        parallel.run_scheduled(["a", "b", "c"], jobs=3, spawn=spawn, sleep=_no_sleep, grace=0.0)
    assert {"kill:a", "kill:b"} <= set(log)

    log.clear()
    with pytest.raises(KeyboardInterrupt):
        parallel.run_scheduled(
            ["a", "b"],
            jobs=2,
            spawn=lambda n: FakeWorker(n, log, 99),
            sleep=lambda _s: (_ for _ in ()).throw(KeyboardInterrupt()),
            grace=0.0,
        )
    assert {"kill:a", "kill:b"} <= set(log)


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals and process groups")
def test_sigterm_becomes_system_exit_and_reaps() -> None:
    log: list[str] = []
    calls = {"n": 0}

    def sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            os.kill(os.getpid(), signal.SIGTERM)

    previous = signal.getsignal(signal.SIGTERM)
    with pytest.raises(SystemExit) as raised:
        parallel.run_scheduled(["a", "b"], jobs=2, spawn=lambda n: FakeWorker(n, log, 99), sleep=sleep, grace=0.0)
    assert raised.value.code == 128 + signal.SIGTERM
    assert {"kill:a", "kill:b"} <= set(log)
    assert signal.getsignal(signal.SIGTERM) is previous


def test_per_case_fixture_paths_are_distinct_and_private_to_the_case() -> None:
    names = [scenario_fixture_name(s.id) for s in load_catalog()]
    assert len(set(names)) == len(names)


def _script(path: Path, body: str) -> list[str]:
    path.write_text(body, encoding="utf-8")
    return [sys.executable, str(path)]


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals and process groups")
def test_subprocess_worker_group_is_reaped_after_cancel(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    command = _script(
        tmp_path / "w.py",
        "import subprocess,sys,time\n"
        "sys.stdin.read()\n"
        f"c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(300)'])\n"
        f"open({str(pid_file)!r},'w').write(str(c.pid))\n"
        "time.sleep(300)\n",
    )
    worker = case_worker.SubprocessCaseWorker("case", {}, tmp_path, command=command)
    deadline = time.monotonic() + 15
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    child = int(pid_file.read_text())
    assert worker.poll() is None
    parallel.cancel_all([worker], grace=0.2)
    assert worker.poll() is not None
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_subprocess_worker_collects_result_and_fails_closed(tmp_path: Path) -> None:
    ok = case_worker.SubprocessCaseWorker(
        "ok",
        {},
        tmp_path,
        command=_script(
            tmp_path / "ok.py",
            "import json,sys\nspec=json.load(sys.stdin)\n"
            "open(spec['result'],'w').write(json.dumps({'assessment':{}}))\n",
        ),
    )
    bad = case_worker.SubprocessCaseWorker(
        "bad", {}, tmp_path, command=_script(tmp_path / "bad.py", "import sys\nsys.stdin.read()\nsys.exit(3)\n")
    )
    assert parallel.run_scheduled(["x"], jobs=1, spawn=lambda _i: ok, sleep=time.sleep, poll_interval=0.05) == [
        {"assessment": {}}
    ]
    with pytest.raises(RuntimeError):
        parallel.run_scheduled(["x"], jobs=1, spawn=lambda _i: bad, poll_interval=0.05)


def _fake_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    package = json.loads((runner.REPO / "ci/pi-exact-continuation/package.json").read_text())
    version = "omp/" + package["dependencies"]["@oh-my-pi/pi-coding-agent"]
    sha = "a" * 40
    capabilities = type("C", (), {"build_sha": sha, "rule_digest": "r", "runtime_version": "v"})()
    identity = type("I", (), {"sha256": "i" * 64, "path": Path(__file__)})()
    monkeypatch.setattr(runner.probe, "_probe_native_identity", lambda: (None, identity, capabilities))
    monkeypatch.setattr(runner.shutil, "which", lambda name: sys.executable)
    monkeypatch.setattr(runner.subprocess, "check_output", lambda *a, **k: version)
    binding = {
        "candidate_sha": sha,
        "tested_source_sha": sha,
        "source_dirty": False,
    }
    monkeypatch.setattr(runner, "source_identity", lambda *a, **k: dict(binding))


def _fake_result(scenario_id: str, public: Path) -> dict[str, Any]:
    public.mkdir(parents=True, exist_ok=True)
    (public / f"{scenario_id}.json").write_text(json.dumps({"id": scenario_id}), encoding="utf-8")
    observation = {"event": "PreToolUse", "hook_http_ms": len(scenario_id)}
    return {
        "assessment": {"outcome": "pass", "reason": "ok", "tool_calls": len(scenario_id)},
        "guard_observations": [observation],
        "id": scenario_id,
    }


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, jobs: int, name: str) -> dict[str, Any]:
    _fake_environment(monkeypatch)
    out = tmp_path / name / "evidence"

    def fake_run_case(scenario: Any, *, public: Path, **_kw: Any) -> dict[str, Any]:
        return _fake_result(scenario.id, public)

    class Handle:
        def __init__(self, scenario_id: str, spec: dict[str, Any], _workdir: Path):
            self.scenario_id = scenario_id
            self.result = _fake_result(scenario_id, Path(spec["public"]))
            self.ticks = len(scenario_id) % 4

        def poll(self) -> int | None:
            self.ticks -= 1
            return 0 if self.ticks <= 0 else None

        def collect(self) -> dict[str, Any]:
            return self.result

        def terminate(self) -> None: ...

        def kill(self) -> None: ...

    monkeypatch.setattr(runner, "run_case", fake_run_case)
    monkeypatch.setattr(runner, "SubprocessCaseWorker", Handle)
    monkeypatch.setattr(parallel.time, "sleep", _no_sleep)
    report = runner.run_suite(
        expected_source_sha="a" * 40,
        output=out,
        provider={},
        work_root=tmp_path / name / "work",
        jobs=jobs,
    )
    assert json.loads((out / "summary.json").read_text()) == report
    return report


def test_parallel_summary_matches_sequential_except_jobs_and_time(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sequential = _run(monkeypatch, tmp_path, 1, "seq")
    concurrent = _run(monkeypatch, tmp_path, 4, "par")
    assert sequential["jobs"] == 1 and concurrent["jobs"] == 4
    ids = [s.id for s in load_catalog()]
    assert [c["id"] for c in concurrent["cases"]] == ids == sequential["expected_scenarios"]
    assert concurrent["full_profile"] is True and concurrent["pass"] is True

    def judged(report: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in report.items() if k not in {"jobs", "started_at", "finished_at"}}

    assert judged(concurrent) == judged(sequential)
    for case in concurrent["cases"]:
        assert case["evidence_sha256"]


def test_partial_selection_stays_non_full_profile_with_jobs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake_environment(monkeypatch)
    ids = [s.id for s in load_catalog()][:2]
    monkeypatch.setattr(runner, "run_case", lambda s, *, public, **_k: _fake_result(s.id, public))
    report = runner.run_suite(
        expected_source_sha="a" * 40, output=tmp_path / "o", provider={}, selected_ids=ids, jobs=1
    )
    assert report["full_profile"] is False and report["merge_qualified"] is False


def test_ledger_reports_only_groups_without_a_reap_record(tmp_path: Path) -> None:
    ledger = tmp_path / "case.groups"
    assert host_process.live_ledger_groups(ledger) == []
    ledger.write_text("start 10\nstart 11\nend 10\nbogus\nstart x\nend 99\nstart 12\n", encoding="utf-8")
    assert host_process.live_ledger_groups(ledger) == [11, 12]


@pytest.mark.skipif(os.name != "posix", reason="POSIX process sessions")
def test_host_process_records_agent_session_start_and_reap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = tmp_path / "case.groups"
    monkeypatch.setattr(host_process, "group_ledger", ledger)
    host_process.run_process(
        [sys.executable, "-c", "pass"],
        cwd=tmp_path,
        env=dict(os.environ),
        output=tmp_path / "out.txt",
        error_output=tmp_path / "err.txt",
        timeout=30,
    )
    events = ledger.read_text(encoding="utf-8").split()
    assert events[0::2] == ["start", "end"] and events[1] == events[3]
    assert host_process.live_ledger_groups(ledger) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX process sessions")
def test_forced_cancel_reaps_agent_session_the_worker_left_behind(tmp_path: Path) -> None:
    pid_file = tmp_path / "agent.pid"
    command = _script(
        tmp_path / "w.py",
        "import json,signal,subprocess,sys,time\n"
        "spec=json.load(sys.stdin)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(300)'],start_new_session=True)\n"
        "open(spec['groups'],'a').write(f'start {c.pid}\\n')\n"
        f"open({str(pid_file)!r},'w').write(str(c.pid))\n"
        "time.sleep(300)\n",
    )
    worker = case_worker.SubprocessCaseWorker("case", {}, tmp_path, command=command)
    deadline = time.monotonic() + 15
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    agent = int(pid_file.read_text())
    assert os.getpgid(agent) != os.getpgid(worker.process.pid)
    parallel.cancel_all([worker], grace=0.2)
    assert worker.poll() is not None
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(agent, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    with pytest.raises(ProcessLookupError):
        os.kill(agent, 0)


def test_windows_reap_kills_the_worker_without_process_groups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[str] = []

    class Process:
        pid = 4242

        def kill(self) -> None:
            killed.append("worker")

    worker = object.__new__(case_worker.SubprocessCaseWorker)
    worker.process = Process()  # type: ignore[assignment]
    worker._groups = tmp_path / "case.groups"
    (tmp_path / "case.groups").write_text("start 77\n", encoding="utf-8")

    def no_process_groups(*_args: Any) -> None:
        raise AssertionError("os.killpg is POSIX-only")

    monkeypatch.setattr(case_worker.os, "name", "nt")
    monkeypatch.setattr(case_worker.os, "killpg", no_process_groups, raising=False)
    worker._reap_group()
    assert killed == ["worker"]


@pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX signal masks")
def test_interrupt_during_spawn_still_reaps_the_started_worker() -> None:
    log: list[str] = []

    def spawn(name: str) -> FakeWorker:
        worker = FakeWorker(name, log, 99)
        # The subprocess is already running when the signal lands.
        os.kill(os.getpid(), signal.SIGTERM)
        return worker

    with pytest.raises(SystemExit):
        parallel.run_scheduled(["a"], jobs=1, spawn=spawn, sleep=_no_sleep, grace=0.0)
    assert "kill:a" in log


@pytest.mark.skipif(os.name != "posix", reason="POSIX signals")
def test_signal_during_cleanup_grace_still_force_kills() -> None:
    log: list[str] = []
    calls = {"n": 0}

    def sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] in (2, 3):
            os.kill(os.getpid(), signal.SIGTERM)

    previous = signal.getsignal(signal.SIGTERM)
    with pytest.raises(SystemExit):
        parallel.run_scheduled(["a", "b"], jobs=2, spawn=lambda n: FakeWorker(n, log, 99), sleep=sleep, grace=60.0)
    assert calls["n"] == 3
    assert {"kill:a", "kill:b"} <= set(log)
    assert signal.getsignal(signal.SIGTERM) is previous


def test_interrupt_during_cancel_grace_still_kills() -> None:
    log: list[str] = []
    workers = [FakeWorker("a", log, 99), FakeWorker("b", log, 99)]
    with pytest.raises(KeyboardInterrupt):
        parallel.cancel_all(workers, grace=60.0, sleep=lambda _s: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert {"kill:a", "kill:b"} <= set(log)


@pytest.mark.skipif(not hasattr(signal, "pthread_sigmask"), reason="POSIX signal masks")
@pytest.mark.parametrize("restore", [True, False])
def test_worker_spawned_under_deferred_signals_honors_terminate(tmp_path: Path, restore: bool) -> None:
    ready = tmp_path / "ready"
    root = Path(__file__).resolve().parents[1]
    body = "import signal,sys,time\n"
    if restore:
        body += f"sys.path.insert(0,{str(root)!r})\nfrom ci.gauntlet.case_worker import restore_signal_delivery\n"
        body += "restore_signal_delivery()\n"
    body += f"open({str(ready)!r},'w').close()\ntime.sleep(60)\n"
    script = tmp_path / "w.py"
    script.write_text(body, encoding="utf-8")
    with parallel.deferred_signals():
        process = subprocess.Popen([sys.executable, str(script)], start_new_session=True)
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        process.terminate()
        try:
            process.wait(timeout=5)
            exited = True
        except subprocess.TimeoutExpired:
            exited = False
        assert exited is restore
    finally:
        process.kill()
        process.wait()
