"""Run full-task cases concurrently, each in its own worker process.

A full task already owns everything it touches: a numbered fixture directory, a Guard
home and daemon on an ephemeral port, its own inference relay (so the inference-round
budget stays per case) and collector, and a per-fixture scratch checkout. What the
tasks cannot share is the interpreter: the in-process Guard daemon and the native
resident client carry process-global state. So ``--jobs N`` reuses the core profile's
isolated case workers, one interpreter per task, and the scheduler's bounds.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .case_worker import SubprocessCaseWorker
from .catalog import Scenario
from .parallel import Lease, run_scheduled


def schedule_full_tasks(
    selected: Sequence[Scenario],
    *,
    jobs: int,
    root: Path,
    public: Path,
    executable: str,
    identity: Any,
    build_sha: str,
    timeout: float,
    mode: str,
    spec_extra: dict[str, Any],
    on_case: Callable[[Scenario, dict[str, Any]], None],
) -> list[dict[str, Any]]:
    """Run every task with at most ``jobs`` workers; ``on_case`` fires as each one finishes.

    Task fixtures are numbered by position in ``selected``, exactly as in a serial run,
    so no two workers ever share a directory. Returned cases follow ``selected`` order.
    """
    workdir = root / "workers"
    workdir.mkdir(mode=0o700)
    public.mkdir(parents=True, exist_ok=True)

    def spawn(task: Scenario, lease: Lease | None = None) -> SubprocessCaseWorker:
        return SubprocessCaseWorker(
            task.id,
            {
                "scenario_id": task.id,
                "root": str(root),
                "public": str(public),
                "executable": executable,
                "timeout": timeout,
                "identity_sha256": identity.sha256,
                "build_sha": build_sha,
                "full_task": {"mode": mode, "index": selected.index(task) + 1},
                **spec_extra,
            },
            workdir,
        )

    results = run_scheduled(
        selected,
        jobs=jobs,
        spawn=spawn,
        on_complete=lambda index, result: on_case(selected[index], result["case"]),
    )
    return [row["case"] for row in results]


def run_worker_full_task(spec: dict[str, Any], full_task: dict[str, Any], identity: Any) -> dict[str, Any]:
    """Worker side: run the one task named by ``spec`` and return its judged case."""
    from .full_tasks import load_full_tasks

    task = next(t for t in load_full_tasks() if t.id == spec["scenario_id"])
    common = {
        "root": Path(spec["root"]),
        "public": Path(spec["public"]),
        "executable": spec["executable"],
        "identity": identity,
        "timeout": float(spec["timeout"]),
        "mode": full_task["mode"],
        "index": int(full_task["index"]),
    }
    if spec.get("harness", "omp") != "omp":
        from .full_task_harness import run_harness_full_task

        return run_harness_full_task(task, harness=spec["harness"], model=spec.get("harness_model"), **common)
    from .full_task_runner import run_full_task

    return run_full_task(task, provider=spec["provider"], **common)
