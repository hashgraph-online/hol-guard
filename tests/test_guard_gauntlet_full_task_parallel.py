from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from ci.gauntlet import case_worker, full_task_parallel, full_task_runner, parallel
from ci.gauntlet.full_tasks import load_full_tasks

LOCAL = [t.id for t in load_full_tasks() if t.id not in full_task_runner.REMOTE_TASKS]


def _case(task_id: str) -> dict[str, Any]:
    return {
        "id": task_id,
        "assessment": {"outcome": "discovered", "reason": "ok"},
        "elapsed_seconds": 1.0,
        "would_have_stopped": [],
    }


class _Handle:
    specs: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, scenario_id: str, spec: dict[str, Any], _workdir: Path, **_kw: Any):
        _Handle.specs.append(spec)
        self.result = {"assessment": _case(scenario_id)["assessment"], "case": _case(scenario_id)}
        self.ticks = 3 - len(_Handle.specs) % 3

    def poll(self) -> int | None:
        self.ticks -= 1
        return 0 if self.ticks <= 0 else None

    def collect(self) -> dict[str, Any]:
        return self.result

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


def _environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    probe = full_task_runner.probe
    monkeypatch.setattr(
        probe,
        "_probe_native_identity",
        lambda: (None, SimpleNamespace(sha256="s"), SimpleNamespace(build_sha="a" * 40)),
    )
    pinned = json.loads((full_task_runner.REPO / "ci/pi-exact-continuation/package.json").read_text())
    version = "omp/" + pinned["dependencies"]["@oh-my-pi/pi-coding-agent"]
    monkeypatch.setattr(full_task_runner.subprocess, "check_output", lambda *_a, **_k: version)
    exe = tmp_path / "omp"
    exe.write_text("")
    monkeypatch.setattr(full_task_runner, "source_identity", lambda *_a: {})
    monkeypatch.setattr(full_task_parallel, "SubprocessCaseWorker", _Handle)
    monkeypatch.setattr(parallel.time, "sleep", lambda _s: None)
    _Handle.specs = []


def test_parallel_full_tasks_use_numbered_fixtures_and_a_provider_per_case(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _environment(monkeypatch, tmp_path)
    provider = {"identity": "p", "max_rounds": 7}
    report = full_task_runner.run_full_tasks(
        expected_source_sha="a" * 40,
        output=tmp_path / "out",
        provider=provider,
        mode="discover",
        selected_ids=LOCAL[:4],
        omp=str(tmp_path / "omp"),
        work_root=tmp_path / "work",
        jobs=3,
    )
    assert report["jobs"] == 3 and report["pass"] is True
    assert [row["id"] for row in report["cases"]] == LOCAL[:4]
    assert sorted(s["full_task"]["index"] for s in _Handle.specs) == [1, 2, 3, 4]
    # Every worker gets the whole provider config, so each case's relay has its own round budget.
    assert all(s["provider"] == provider and s["full_task"]["mode"] == "discover" for s in _Handle.specs)
    assert json.loads(tmp_path.joinpath("out", "summary.json").read_text())["cases"] == report["cases"]
    assert (tmp_path / "out" / "false-positives.json").is_file()


def test_real_github_world_stays_serial(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="one task at a time"):
        full_task_runner.run_full_tasks(
            expected_source_sha="a" * 40,
            output=tmp_path / "o",
            provider={},
            mode="discover",
            world=full_task_runner.RemoteWorld("owner"),
            jobs=2,
        )


def test_worker_runs_one_full_task_and_returns_its_case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def fake(task: Any, **kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs, task=task.id)
        return _case(task.id)

    monkeypatch.setattr(full_task_runner, "run_full_task", fake)
    spec = {
        "scenario_id": LOCAL[0],
        "root": str(tmp_path),
        "public": str(tmp_path / "cases"),
        "executable": "omp",
        "timeout": 60,
        "provider": {"identity": "p"},
    }
    case = full_task_parallel.run_worker_full_task(spec, {"mode": "enforce", "index": 5}, "identity")
    assert case["id"] == LOCAL[0] and seen["index"] == 5 and seen["mode"] == "enforce"
    assert seen["provider"] == {"identity": "p"} and seen["timeout"] == 60.0


def test_case_worker_module_exposes_full_task_hook() -> None:
    assert callable(case_worker.main)
