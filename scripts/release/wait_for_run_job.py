"""Wait for another job in this workflow run attempt to finish before continuing.

Overlapping release jobs still depend on a sibling job's outcome; this polls the
run's job list so dependent preparation can start while the sibling still runs.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from collections.abc import Callable

MAX_CONSECUTIVE_ERRORS = 10
EARLY_INTERVAL_SECONDS = 10
EARLY_INTERVAL_UNTIL = 900
LATE_INTERVAL_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 7200

Job = dict
Fetcher = Callable[[], list[Job]]


def gh_job_fetcher(repository: str, run_id: str, run_attempt: str) -> Fetcher:
    """Return a fetcher that lists {name, status, conclusion} records for the run attempt."""
    url = f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}/jobs?per_page=100"

    def fetch() -> list[Job]:
        completed = subprocess.run(
            [
                "gh",
                "api",
                "--paginate",
                url,
                "--jq",
                ".jobs[] | {name, status, conclusion}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"gh api failed: {completed.stderr.strip()}")
        return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]

    return fetch


def wait_for_job(
    job_name: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    fetch_jobs: Fetcher,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Poll until the named job reaches a terminal state; return a process exit code."""
    started = clock()
    consecutive_errors = 0
    while True:
        try:
            jobs = fetch_jobs()
        except Exception as error:  # any fetch failure is a transient poll error
            consecutive_errors += 1
            print(f"Transient error listing run jobs ({consecutive_errors}/{MAX_CONSECUTIVE_ERRORS}): {error}")
            if consecutive_errors > MAX_CONSECUTIVE_ERRORS:
                print("Too many consecutive errors listing run jobs; giving up.")
                return 1
        else:
            consecutive_errors = 0
            matches = [job for job in jobs if job.get("name") == job_name]
            if len(matches) > 1:
                print(f'Ambiguous job name "{job_name}": {len(matches)} jobs matched in this run attempt.')
                return 1
            if matches and matches[0].get("status") == "completed":
                conclusion = matches[0].get("conclusion")
                if conclusion == "success":
                    print(f'"{job_name}" succeeded in this run attempt; continuing.')
                    return 0
                print(
                    f'"{job_name}" finished with conclusion "{conclusion}"; the alpha prerelease will not be created.'
                )
                return 1
            print(f'"{job_name}" has not finished; waiting.')

        elapsed = clock() - started
        if elapsed >= timeout_seconds:
            print(f'Timed out after {int(elapsed)}s waiting for "{job_name}".')
            return 1
        sleep(EARLY_INTERVAL_SECONDS if elapsed < EARLY_INTERVAL_UNTIL else LATE_INTERVAL_SECONDS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)

    required = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        parser.error("missing required environment: " + ", ".join(missing))
    fetch_jobs = gh_job_fetcher(
        os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    )
    return wait_for_job(args.job_name, timeout_seconds=args.timeout_seconds, fetch_jobs=fetch_jobs)


if __name__ == "__main__":
    raise SystemExit(main())
