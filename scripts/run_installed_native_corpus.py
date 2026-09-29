"""Run the frozen native corpus against the verified installed Guard wheel."""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests import guard_command_corpus_runner as runner  # noqa: E402


def _require_installed_evaluator() -> None:
    from codex_plugin_scanner.guard.runtime import command_evaluation

    package_root = Path(distribution("hol-guard").locate_file("codex_plugin_scanner")).resolve()
    module_location = command_evaluation.__file__
    if module_location is None or not Path(module_location).resolve().is_relative_to(package_root):
        raise RuntimeError("native corpus evaluator did not load from the installed Guard package")


def _run_installed_worker(worker_index: int) -> runner.WorkerReport:
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker", str(worker_index)],
        check=False,
        capture_output=True,
        text=True,
        timeout=runner.WORKER_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise ValueError(f"installed native corpus worker {worker_index} failed: {completed.stderr[-1200:]}")
    try:
        return runner._decode_worker(completed.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"installed native corpus worker {worker_index} emitted an invalid report") from exc


def main() -> int:
    # The corpus runner is source-bound by a frozen contract. Verify its two
    # integration points before adapting them; the canary runs the full corpus.
    if not callable(getattr(runner, "_install_evaluator_packages", None)) or not callable(
        getattr(runner, "_run_worker", None)
    ):
        raise RuntimeError("frozen corpus runner no longer exposes its installed-wheel integration points")
    runner._install_evaluator_packages = _require_installed_evaluator
    runner._run_worker = _run_installed_worker
    if len(sys.argv) == 1:
        report = runner._coordinator_report()
    elif len(sys.argv) == 3 and sys.argv[1] == "--worker":
        report = runner._worker_report(int(sys.argv[2]), runner.EVALUATION_SHARD_COUNT)
    else:
        raise SystemExit("usage: run_installed_native_corpus.py [--worker INDEX]")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
