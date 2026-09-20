"""Wait for all Python coverage producers in this workflow run attempt."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime

SHARD_COUNT = 192
# The planner and each dependent shard have separate five-minute watchdogs.
# Include one minute for polling and scheduling overhead; this bound does not
# delay successful producers or define the CI performance target.
_DEFAULT_TIMEOUT_SECONDS = 660.0
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHARD_NAME = re.compile(r"coverage \(3\.12, (0|[1-9][0-9]*)\)")
_PENDING_STATUSES = frozenset({"queued", "in_progress", "waiting", "pending", "requested"})
_MAX_JOBS = 1000
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
FetchJson = Callable[[str, float], object]


def _progress(message: str) -> None:
    print(message, flush=True)


class ShardWaitError(ValueError):
    """The current attempt cannot safely supply complete coverage."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ShardWaitError("Unexpected GitHub API redirect")


def github_json(path: str, timeout_seconds: float) -> object:
    """Read bounded JSON without forwarding or printing the workflow token."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token or any(character.isspace() for character in token):
        raise ShardWaitError("GITHUB_TOKEN must contain an Actions read token")
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hol-guard-pytest-shard-waiter",
        },
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout_seconds) as response:
            if response.status != 200:
                raise ShardWaitError("GitHub jobs API returned an unexpected status")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ShardWaitError("GitHub jobs API response exceeded its size limit")
        return json.loads(raw)
    except urllib.error.HTTPError as error:
        raise ShardWaitError(f"GitHub jobs API returned HTTP {error.code}") from None
    except (OSError, urllib.error.URLError):
        raise ShardWaitError("GitHub jobs API request failed") from None
    except (UnicodeError, json.JSONDecodeError):
        raise ShardWaitError("GitHub jobs API returned invalid JSON") from None


def _job_state(job: Mapping[str, object], label: str) -> str:
    status = job.get("status")
    conclusion = job.get("conclusion")
    if status == "completed":
        if conclusion != "success":
            # Only print a known status, never an arbitrary API response body.
            reason = (
                conclusion
                if isinstance(conclusion, str) and conclusion in {"failure", "cancelled", "skipped", "timed_out"}
                else "non-success"
            )
            raise ShardWaitError(f"{label} completed with {reason}")
        return "success"
    if isinstance(status, str) and status in _PENDING_STATUSES and conclusion is None:
        return "running" if status == "in_progress" else "queued"
    raise ShardWaitError(f"{label} has an invalid job state")


def _require_current_execution(job: Mapping[str, object], label: str) -> None:
    """Reject prior-attempt successes cloned into GitHub's current jobs list."""

    timestamps: list[datetime] = []
    for field in ("created_at", "started_at", "completed_at"):
        value = job.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}Z", value):
            raise ShardWaitError(f"{label} has invalid execution timestamps")
        try:
            timestamps.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            raise ShardWaitError(f"{label} has invalid execution timestamps") from None
    created, started, completed = timestamps
    if completed < started:
        raise ShardWaitError(f"{label} has invalid execution timestamps")
    # A partial rerun creates a new job ID/run_attempt for each inherited
    # success, but preserves its old execution times. Attempt-qualified
    # coverage artifacts cannot come from that earlier execution.
    if started < created:
        raise ShardWaitError(f"{label} inherited execution from an earlier attempt; rerun all Python coverage shards")


def _snapshot(
    repository: str,
    run_id: int,
    attempt: int,
    *,
    fetch_json: FetchJson,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[str, ...]:
    states = ["absent"] * SHARD_COUNT
    job_ids: set[int] = set()
    seen_shards: set[int] = set()
    plan_seen = False
    total_count = 0
    for page in range(1, _MAX_JOBS // 100 + 1):
        remaining = deadline - clock()
        if remaining <= 0:
            raise ShardWaitError("Timed out waiting for Python coverage shard jobs")
        path = f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}"
        payload = fetch_json(path, min(10.0, remaining))
        if not isinstance(payload, dict):
            raise ShardWaitError("GitHub jobs API returned an invalid object")
        count, jobs = payload.get("total_count"), payload.get("jobs")
        if type(count) is not int or not total_count <= count <= _MAX_JOBS or not isinstance(jobs, list):
            raise ShardWaitError("GitHub jobs API returned an invalid job list")
        total_count = count
        if len(jobs) > 100:
            raise ShardWaitError("GitHub jobs API exceeded its page size")
        for job in jobs:
            if not isinstance(job, dict):
                raise ShardWaitError("GitHub jobs API returned an invalid job")
            job_id, name = job.get("id"), job.get("name")
            if type(job_id) is not int or job_id <= 0 or not isinstance(name, str):
                raise ShardWaitError("GitHub jobs API returned an invalid job identity")
            if job_id in job_ids:
                raise ShardWaitError("GitHub jobs API returned a duplicate job")
            job_ids.add(job_id)
            if type(job.get("run_id")) is not int or job["run_id"] != run_id:
                raise ShardWaitError("GitHub jobs API returned a job from another run")
            if "run_attempt" in job and (type(job["run_attempt"]) is not int or job["run_attempt"] != attempt):
                raise ShardWaitError("GitHub jobs API returned a job from another attempt")
            if name == "coverage-plan":
                if plan_seen:
                    raise ShardWaitError("GitHub jobs API returned duplicate coverage-plan jobs")
                plan_seen = True
                _job_state(job, "Python coverage-plan")
            if not name.startswith("coverage (3.12,"):
                continue
            match = _SHARD_NAME.fullmatch(name)
            if match is None or int(match[1]) >= SHARD_COUNT:
                raise ShardWaitError("GitHub jobs API returned an invalid Python coverage shard index")
            index = int(match[1])
            if index in seen_shards:
                raise ShardWaitError(f"GitHub jobs API returned duplicate Python coverage shard {index}")
            seen_shards.add(index)
            label = f"Python coverage shard {index}"
            states[index] = _job_state(job, label)
            if states[index] == "success":
                _require_current_execution(job, label)
        if len(job_ids) == total_count:
            return tuple(states)
        if len(jobs) != 100 or len(job_ids) > total_count:
            raise ShardWaitError("GitHub jobs API returned an incomplete job list")
    raise ShardWaitError("GitHub jobs API exceeded its pagination limit")


def wait_for_shards(
    repository: str,
    run_id: int,
    attempt: int,
    *,
    fetch_json: FetchJson = github_json,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    poll_seconds: float = 5.0,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = _progress,
) -> None:
    """Accept every expected successful shard, scoped to the current run attempt."""
    if _REPOSITORY.fullmatch(repository) is None or any(part in {".", ".."} for part in repository.split("/")):
        raise ShardWaitError("Invalid GITHUB_REPOSITORY")
    if any(type(value) is not int or value <= 0 for value in (run_id, attempt)):
        raise ShardWaitError("Workflow run and attempt IDs must be positive integers")
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= _DEFAULT_TIMEOUT_SECONDS:
        raise ShardWaitError(f"Wait timeout must be between 0 and {_DEFAULT_TIMEOUT_SECONDS:g} seconds")
    if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 30:
        raise ShardWaitError("Poll interval must be between 0 and 30 seconds")
    deadline = clock() + timeout_seconds
    previous: tuple[str, ...] | None = None
    log(f"Waiting for {SHARD_COUNT} Python coverage shards in run {run_id}, attempt {attempt}")
    while True:
        states = _snapshot(repository, run_id, attempt, fetch_json=fetch_json, deadline=deadline, clock=clock)
        if clock() >= deadline:
            raise ShardWaitError("Timed out waiting for Python coverage shard jobs")
        if states != previous:
            counts = Counter(states)
            log(
                f"Python coverage shards: {counts['success']}/{SHARD_COUNT} succeeded, "
                f"{counts['running']} running, {counts['queued']} queued, {counts['absent']} not yet scheduled"
            )
            previous = states
        if all(state == "success" for state in states):
            log(f"All {SHARD_COUNT} Python coverage shards succeeded in run {run_id}, attempt {attempt}")
            return
        sleep(min(poll_seconds, max(0.0, deadline - clock())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout-seconds", type=float, default=_DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        run_id = os.environ.get("GITHUB_RUN_ID", "")
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
        if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[1-9][0-9]*", attempt):
            raise ShardWaitError("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT must be positive integers")
        wait_for_shards(
            os.environ.get("GITHUB_REPOSITORY", ""),
            int(run_id),
            int(attempt),
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
    except (ShardWaitError, OSError, urllib.error.URLError) as error:
        print(f"Python coverage shard barrier failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
