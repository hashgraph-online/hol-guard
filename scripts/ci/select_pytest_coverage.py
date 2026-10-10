#!/usr/bin/env python3
"""Select complete coverage from proven executions of one unchanged workflow run."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci import wait_for_pytest_shards as barrier

SCHEMA = "hol-guard.pytest-coverage-selection.v1"
MAX_ATTEMPTS = 51
# This is a provenance boundary, not a user-configurable workflow selector.
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
Fetch = Callable[[str, float], object]


class _InventoryPendingError(ValueError):
    """Retry a bounded API snapshot, never a test or its failure result."""


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}Z", value):
        raise ValueError("Invalid coverage execution timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _pages(path: str, field: str, fetch: Fetch) -> list[dict]:
    result: list[dict] = []
    seen: set[int] = set()
    maximum = 20_000 if field == "artifacts" else 1000
    expected_total: int | None = None
    for page in range(1, maximum // 100 + 1):
        payload = fetch(f"{path}?per_page=100&page={page}", 10.0)
        if not isinstance(payload, dict) or type(payload.get("total_count")) is not int:
            raise ValueError("Invalid coverage API inventory")
        total, entries = payload["total_count"], payload.get(field)
        if not 0 <= total <= maximum or not isinstance(entries, list) or len(entries) > 100:
            raise ValueError("Coverage API inventory exceeds its bound")
        if expected_total is not None and total != expected_total:
            raise _InventoryPendingError("Coverage API inventory changed during pagination")
        expected_total = total
        for item in entries:
            if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] <= 0:
                raise ValueError("Invalid coverage API identity")
            if item["id"] in seen:
                raise _InventoryPendingError("Duplicate coverage API identity")
            seen.add(item["id"])
            result.append(item)
        if len(result) == total:
            return result
        if len(result) > total or len(entries) != 100:
            raise _InventoryPendingError("Incomplete coverage API inventory")
    raise ValueError("Coverage API inventory exceeds pagination bound")


def _execution(job: dict, run_id: int, attempt: int, head_sha: str) -> tuple[datetime, datetime, bool]:
    if type(job.get("run_id")) is not int or job["run_id"] != run_id or job.get("head_sha") != head_sha:
        raise ValueError("Coverage job belongs to another run or commit")
    if type(job.get("run_attempt")) is not int or job["run_attempt"] != attempt:
        raise ValueError("Coverage job belongs to another attempt")
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        raise ValueError("Coverage producer did not succeed")
    created, started, completed = (_time(job.get(key)) for key in ("created_at", "started_at", "completed_at"))
    if completed < started:
        raise ValueError("Invalid coverage execution interval")
    return started, completed, started >= created


def _original_executions(base: str, run_id: int, attempt: int, head_sha: str, fetch: Fetch) -> dict:
    """Prove inherited jobs against their real source attempts, not cloned IDs."""
    shard_names = [f"coverage (3.12, {index})" for index in range(barrier.SHARD_COUNT)]
    required = {*shard_names, "coverage-plan", "native-command-evaluators"}
    current: dict[str, dict] = {}
    intervals: dict[str, tuple[datetime, datetime]] = {}
    origins: dict[str, tuple[int, dict]] = {}
    for job in _pages(f"{base}/attempts/{attempt}/jobs", "jobs", fetch):
        name = job.get("name")
        if name not in required:
            continue
        if name in current:
            raise ValueError("Duplicate coverage producer name")
        started, completed, executed = _execution(job, run_id, attempt, head_sha)
        current[name] = job
        intervals[name] = (started, completed)
        if executed:
            origins[name] = (attempt, job)
    if current.keys() != required:
        raise ValueError("Missing coverage producer or prerequisite")
    for earlier in range(attempt - 1, 0, -1):
        if origins.keys() == required:
            break
        candidates: dict[str, dict] = {}
        for job in _pages(f"{base}/attempts/{earlier}/jobs", "jobs", fetch):
            name = job.get("name")
            if name not in required or name in origins:
                continue
            # An older failure is never evidence for a cloned success.
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                continue
            started, completed, executed = _execution(job, run_id, earlier, head_sha)
            if not executed or (started, completed) != intervals[name]:
                continue
            if name in candidates:
                raise ValueError("Ambiguous original coverage execution")
            candidates[name] = job
        origins.update({name: (earlier, job) for name, job in candidates.items()})
    if origins.keys() != required:
        raise ValueError("Inherited success has no matching original execution")
    return origins


def _coverage_artifacts(base: str, run_id: int, head_sha: str, origins: dict, fetch: Fetch) -> list[dict]:
    """Bind one immutable coverage artifact to each successful producer."""
    shard_names = [f"coverage (3.12, {index})" for index in range(barrier.SHARD_COUNT)]
    prerequisite_finished = max(
        _time(origins[name][1]["completed_at"]) for name in ("coverage-plan", "native-command-evaluators")
    )
    artifacts = _pages(f"{base}/artifacts", "artifacts", fetch)
    selected = []
    for index, name in enumerate(shard_names):
        source_attempt, job = origins[name]
        started, completed = _time(job["started_at"]), _time(job["completed_at"])
        if started < prerequisite_finished:
            raise ValueError("Coverage predates the current native build or shard plan; rerun dependent shards")
        artifact_name = f"pytest-coverage-{source_attempt}-{index}"
        matches = [item for item in artifacts if item.get("name") == artifact_name]
        if not matches:
            raise _InventoryPendingError(f"Missing or ambiguous coverage artifact for shard {index}")
        if len(matches) != 1:
            raise ValueError(f"Missing or ambiguous coverage artifact for shard {index}")
        artifact = matches[0]
        source = artifact.get("workflow_run")
        if (
            artifact.get("expired") is not False
            or not isinstance(source, dict)
            or source.get("id") != run_id
            or source.get("head_sha") != head_sha
            or not isinstance(artifact.get("digest"), str)
            or DIGEST.fullmatch(artifact["digest"]) is None
            or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] <= 64 * 1024 * 1024
            or not started <= _time(artifact.get("created_at")) <= completed
        ):
            raise ValueError(f"Unbound, expired or invalid coverage artifact for shard {index}")
        selected.append(
            {
                "shard": index,
                "attempt": source_attempt,
                "job_id": job["id"],
                "artifact_id": artifact["id"],
                "name": artifact_name,
                "digest": artifact["digest"],
            }
        )
    return selected


def select_coverage(repository: str, run_id: int, attempt: int, *, fetch: Fetch = barrier.github_json) -> dict:
    """Reuse only exact inherited successes; never fall back from a newer failure."""
    if barrier.REPOSITORY_PATTERN.fullmatch(repository) is None or any(p in {".", ".."} for p in repository.split("/")):
        raise ValueError("Invalid coverage repository")
    if type(run_id) is not int or run_id <= 0 or type(attempt) is not int or not 1 <= attempt <= MAX_ATTEMPTS:
        raise ValueError("Invalid coverage run or attempt")
    base = f"/repos/{repository}/actions/runs/{run_id}"
    run = fetch(base, 10.0)
    if (
        not isinstance(run, dict)
        or run.get("id") != run_id
        or run.get("run_attempt") != attempt
        or run.get("path") != CI_WORKFLOW_PATH
        or not isinstance(run.get("head_sha"), str)
        or SHA.fullmatch(run["head_sha"]) is None
        or not isinstance(run.get("repository"), dict)
        or run["repository"].get("full_name") != repository
    ):
        raise ValueError("Workflow identity changed or is not the canonical CI run")
    head_sha = run["head_sha"]
    origins = _original_executions(base, run_id, attempt, head_sha, fetch)
    selected = _coverage_artifacts(base, run_id, head_sha, origins, fetch)
    final_run = fetch(base, 10.0)
    if not isinstance(final_run, dict) or any(
        final_run.get(key) != run.get(key) for key in ("id", "run_attempt", "head_sha", "path")
    ):
        raise ValueError("Workflow changed while selecting coverage")
    return {
        "schema": SCHEMA,
        "repository": repository,
        "run_id": run_id,
        "attempt": attempt,
        "head_sha": head_sha,
        "shards": selected,
    }


def select_with_retries(
    repository: str,
    run_id: int,
    attempt: int,
    *,
    fetch: Fetch = barrier.github_json,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Only transient reads or an eventually consistent inventory may be retried."""
    for retry in range(4):
        try:
            return select_coverage(repository, run_id, attempt, fetch=fetch)
        except (_InventoryPendingError, barrier.TransientApiError):
            if retry == 3:
                raise
            sleep(float(2**retry))
    raise AssertionError("unreachable")


def verify_downloads(selection: dict, directory: Path) -> None:
    """Only the selected complete inventory may reach coverage combine."""
    if selection.get("schema") != SCHEMA or not isinstance(selection.get("shards"), list):
        raise ValueError("Invalid coverage selection")
    shards = selection["shards"]
    if len(shards) != barrier.SHARD_COUNT or [item.get("shard") for item in shards] != list(range(barrier.SHARD_COUNT)):
        raise ValueError("Incomplete coverage selection")
    names = {item["name"] for item in shards}
    if len(names) != barrier.SHARD_COUNT or any(
        re.fullmatch(r"pytest-coverage-[1-9][0-9]*-(0|[1-9][0-9]*)", n) is None for n in names
    ):
        raise ValueError("Invalid coverage artifact directory")
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != names:
        raise ValueError("Downloaded coverage inventory does not match selected producers")
    for name in names:
        parent = directory / name
        path = parent / ".coverage"
        if parent.is_symlink() or path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise ValueError("Selected coverage database is missing, linked or empty")


def _positive_integer_env(name: str) -> int:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"{name} environment variable is not set")
    try:
        number = int(value)
    except ValueError:
        raise ValueError(f"{name} must be a positive integer") from None
    if number <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("coverage-selection.json"))
    parser.add_argument("--verify-downloads", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify_downloads:
            verify_downloads(json.loads(args.output.read_text()), args.verify_downloads)
            return 0
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        run_id = _positive_integer_env("GITHUB_RUN_ID")
        attempt = _positive_integer_env("GITHUB_RUN_ATTEMPT")
        # The barrier still requires all latest results to succeed. The selector
        # below then resolves inherited results to their actual source executions.
        # The change planner only runs on pull_request; on push a skipped planner
        # is expected and must not block coverage selection.
        # Each inventory spans several API pages. Polling every second exhausts
        # the repository's shared Actions quota while other shards are running.
        barrier.wait_for_shards(
            repository, run_id, attempt, poll_seconds=30,
            execution_validator=lambda _job, _label: None,
            plan_skippable=os.environ.get("GITHUB_EVENT_NAME", "") != "pull_request",
        )
        selection = select_with_retries(repository, run_id, attempt)
        args.output.write_text(json.dumps(selection, sort_keys=True) + "\n")
        if output := os.environ.get("GITHUB_OUTPUT"):
            with open(output, "a", encoding="utf-8") as stream:
                stream.write("artifact-ids=" + ",".join(str(s["artifact_id"]) for s in selection["shards"]) + "\n")
        reused = sum(s["attempt"] < attempt for s in selection["shards"])
        print(f"Selected {barrier.SHARD_COUNT} successful same-run shards; reused {reused} proven earlier executions")
    except (ValueError, OSError, barrier.ShardWaitError) as error:
        print(f"Coverage selection failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
