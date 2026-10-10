"""Select artifacts from successful jobs in this exact CI run attempt."""

from __future__ import annotations

import time

from scripts.ci import wait_for_pytest_shards as barrier
from scripts.ci.select_pytest_coverage import _InventoryPendingError, _pages, _time


def _select_once(
    repository: str,
    run_id: int,
    attempt: int,
    producers: dict[str, str],
    fetch,
) -> dict | None:
    """Return the qualified selection, or None while a producer is still pending."""
    base = f"/repos/{repository}/actions/runs/{run_id}"
    run = fetch(base, 10.0)
    if (
        not isinstance(run, dict)
        or run.get("id") != run_id
        or run.get("run_attempt") != attempt
        or run.get("path") != ".github/workflows/ci.yml"
        or not isinstance(run.get("repository"), dict)
        or run["repository"].get("full_name") != repository
    ):
        raise ValueError("Workflow run identity changed")
    inventory = _pages(f"{base}/attempts/{attempt}/jobs", "jobs", fetch)
    current = {}
    pending = False
    for job_name in producers:
        jobs = [job for job in inventory if job.get("name") == job_name]
        if len(jobs) > 1:
            raise ValueError(f"Ambiguous {job_name} producer")
        if not jobs:
            if run.get("status") == "completed":
                raise ValueError(f"Current attempt has no {job_name} producer")
            pending = True
            continue
        job = jobs[0]
        if (
            job.get("run_id") != run_id
            or job.get("run_attempt") != attempt
            or job.get("head_sha") != run.get("head_sha")
        ):
            raise ValueError(f"{job_name} producer identity mismatch")
        if barrier._job_state(job, job_name) != "success":
            pending = True
            continue
        barrier._require_current_execution(job, job_name)
        current[job_name] = job
    if pending:
        return None
    inventory = _pages(f"{base}/artifacts", "artifacts", fetch)
    selected = {}
    for job_name, name in producers.items():
        artifacts = [item for item in inventory if item.get("name") == name]
        if not artifacts:
            pending = True
            continue
        if len(artifacts) != 1:
            raise ValueError(f"Ambiguous {name} artifact")
        artifact = artifacts[0]
        source = artifact.get("workflow_run")
        job = current[job_name]
        if (
            not isinstance(source, dict)
            or source.get("id") != run_id
            or source.get("head_sha") != run.get("head_sha")
            or artifact.get("expired") is not False
            or not _time(job["started_at"]) <= _time(artifact.get("created_at")) <= _time(job["completed_at"])
        ):
            raise ValueError(f"{name} artifact is not bound to the successful execution")
        selected[job_name] = {"artifact": artifact, "job_id": job["id"]}
    return None if pending else selected


def select_many(
    repository: str,
    run_id: int,
    attempt: int,
    *,
    producers: dict[str, str],
    fetch=barrier.github_json,
    clock=time.monotonic,
    sleep=time.sleep,
    timeout=960.0,
) -> dict:
    if barrier.REPOSITORY_PATTERN.fullmatch(repository) is None or any(p in {".", ".."} for p in repository.split("/")):
        raise ValueError("Invalid repository")
    if run_id <= 0 or attempt <= 0:
        raise ValueError("Invalid run identity")
    deadline = clock() + timeout
    while clock() < deadline:
        try:
            selected = _select_once(repository, run_id, attempt, producers, fetch)
        except (_InventoryPendingError, barrier.TransientApiError):
            # Only an inventory that changed mid-read or a transient API failure may be
            # retried; identity and provenance violations above stay fatal.
            sleep(5.0)
            continue
        if selected is not None:
            return selected
        sleep(5.0)
    raise ValueError("Timed out waiting for current-attempt successful reports")


def select(
    repository: str,
    run_id: int,
    attempt: int,
    *,
    job_name: str,
    artifact_prefix: str,
    fetch=barrier.github_json,
    clock=time.monotonic,
    sleep=time.sleep,
    timeout=960.0,
) -> dict:
    selected = select_many(
        repository,
        run_id,
        attempt,
        producers={job_name: f"{artifact_prefix}-{attempt}"},
        fetch=fetch,
        clock=clock,
        sleep=sleep,
        timeout=timeout,
    )
    return selected[job_name]["artifact"]
