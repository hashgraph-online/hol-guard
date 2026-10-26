"""Run the frozen native corpus against the verified installed Guard wheel."""

from __future__ import annotations

import faulthandler
import json
import subprocess
import sys
import time
from functools import wraps
from importlib.metadata import distribution
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests import guard_command_corpus_runner as runner  # noqa: E402


def _install_worker_diagnostics() -> None:
    from tests import guard_command_corpus_native as native

    def observe(function, phase):
        count = 0
        total = 0.0

        @wraps(function)
        def call(*args, **kwargs):
            nonlocal count, total
            count += 1
            started = time.perf_counter()
            print(f"corpus_phase {phase} batch={count} started total={total:.3f}", file=sys.stderr, flush=True)
            try:
                return function(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - started
                total += elapsed
                print(
                    f"corpus_phase {phase} batch={count} elapsed={elapsed:.3f} total={total:.3f}",
                    file=sys.stderr,
                    flush=True,
                )

        return call

    native.real_native_review_fixtures = observe(native.real_native_review_fixtures, "native-batch")
    native.project_native_review_fixtures_batch = observe(
        native.project_native_review_fixtures_batch, "resident-projection"
    )


def _failure_detail(stderr: str) -> str:
    lines = stderr.splitlines()
    progress = {}
    for line in lines:
        if line.startswith("corpus_phase "):
            progress[line.split()[1]] = line
    traceback = "\n".join(line for line in lines if not line.startswith("corpus_phase "))
    # Faulthandler prints the most recent frame first. Later progress must
    # neither displace that frame nor fill the bounded traceback excerpt.
    summary = "\n".join(progress.values()) if progress else "no corpus phase completed"
    return f"{summary}\n{traceback[:1200]}"


def _require_installed_evaluator() -> None:
    from codex_plugin_scanner.guard.runtime import command_evaluation

    package_root = Path(distribution("hol-guard").locate_file("codex_plugin_scanner")).resolve()
    module_location = command_evaluation.__file__
    if module_location is None or not Path(module_location).resolve().is_relative_to(package_root):
        raise RuntimeError("native corpus evaluator did not load from the installed Guard package")


def _run_installed_worker(worker_index: int) -> runner.WorkerReport:
    try:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--worker", str(worker_index)],
            check=False,
            capture_output=True,
            text=True,
            # Installed Windows batches include process/ACL overhead absent from
            # the source runner's POSIX budget; keep the full corpus and a hard cap.
            timeout=180 if sys.platform == "win32" else runner.WORKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        tail = error.stderr or b""
        if isinstance(tail, bytes):
            tail = tail.decode("utf-8", errors="replace")
        raise ValueError(f"installed native corpus worker {worker_index} timed out: {_failure_detail(tail)}") from error
    if completed.returncode != 0:
        raise ValueError(f"installed native corpus worker {worker_index} failed: {_failure_detail(completed.stderr)}")
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
        # Stack frames contain no command payloads. Preserve where a worker is
        # waiting before the unchanged parent deadline terminates it.
        timeout = 180 if sys.platform == "win32" else runner.WORKER_TIMEOUT_SECONDS
        _install_worker_diagnostics()
        faulthandler.dump_traceback_later(max(1, timeout - 10))
        try:
            report = runner._worker_report(int(sys.argv[2]), runner.EVALUATION_SHARD_COUNT)
        finally:
            faulthandler.cancel_dump_traceback_later()
    else:
        raise SystemExit("usage: run_installed_native_corpus.py [--worker INDEX]")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
