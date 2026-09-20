"""Bind PR-only installed validation to one completed publication attempt."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

Fetch = Callable[[str], Mapping[str, Any]]
_WORKFLOW = ".github/workflows/publish.yml"
_ARTIFACTS = {"distributions-native": "distribution_artifact_id", "installed-canary-subject": "subject_artifact_id"}


def _positive(value: object) -> int:
    if type(value) is not int or not 0 < value < 1 << 53:
        raise ValueError("canary_identity_invalid")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("canary_timestamp_invalid")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _matching_run(run: Mapping[str, Any], repository: str, source_sha: str, pull_request: int) -> bool:
    return (
        run.get("event") == "pull_request"
        and run.get("path") == _WORKFLOW
        and run.get("head_sha") == source_sha
        and run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
        and any(
            pr.get("number") == pull_request and pr.get("head", {}).get("sha") == source_sha
            for pr in run.get("pull_requests", [])
        )
    )


def bind_attempt(
    run: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
    *,
    repository: str,
    source_sha: str,
    pull_request: int,
    base_version: str,
) -> dict[str, str]:
    if not _matching_run(run, repository, source_sha, pull_request):
        raise ValueError("canary_run_identity_mismatch")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("canary_publication_not_successful")
    run_id = _positive(run.get("id"))
    number, attempt = _positive(run.get("run_number")), _positive(run.get("run_attempt"))
    started = _timestamp(run.get("run_started_at"))
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", base_version) is None:
        raise ValueError("canary_base_version_invalid")
    selected: dict[str, str] = {}
    for name, output in _ARTIFACTS.items():
        candidates = [
            item
            for item in artifacts
            if item.get("name") == name
            and item.get("expired") is False
            and _timestamp(item.get("created_at")) >= started
        ]
        if len(candidates) != 1:
            raise ValueError("canary_artifact_attempt_ambiguous")
        artifact = candidates[0]
        if artifact.get("workflow_run", {}).get("id") != run_id:
            raise ValueError("canary_artifact_run_mismatch")
        selected[output] = str(_positive(artifact.get("id")))

    def pair(left: int, right: int) -> int:
        total = left + right
        return total * (total + 1) // 2 + right

    return dict(
        selected,
        run_id=str(run_id),
        run_attempt=str(attempt),
        source_sha=source_sha,
        version=f"{base_version}.dev{pair(pair(pull_request, number), attempt)}",
    )


def resolve(
    fetch: Fetch,
    *,
    repository: str,
    source_sha: str,
    pull_request: int,
    base_version: str,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
    pause: Callable[[float], None] = time.sleep,
) -> dict[str, str]:
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise ValueError("canary_repository_invalid")
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("canary_source_invalid")
    _positive(pull_request)
    prefix = f"/repos/{repository}"
    frozen_run: int | None = None
    while clock() < deadline:
        pr = fetch(f"{prefix}/pulls/{pull_request}")
        if (
            pr.get("head", {}).get("sha") != source_sha
            or pr.get("head", {}).get("repo", {}).get("full_name") != repository
        ):
            raise ValueError("canary_pull_request_changed")
        if frozen_run is None:
            listing = fetch(
                f"{prefix}/actions/workflows/publish.yml/runs?event=pull_request&head_sha={source_sha}&per_page=100"
            )
            candidates = [
                run
                for run in listing.get("workflow_runs", [])
                if _matching_run(run, repository, source_sha, pull_request)
            ]
            if candidates:
                frozen_run = max(_positive(run.get("id")) for run in candidates)
        if frozen_run is not None:
            run = fetch(f"{prefix}/actions/runs/{frozen_run}")
            if not _matching_run(run, repository, source_sha, pull_request):
                raise ValueError("canary_run_identity_changed")
            if run.get("status") == "completed":
                if run.get("conclusion") != "success":
                    raise ValueError("canary_publication_not_successful")
                jobs = fetch(
                    f"{prefix}/actions/runs/{frozen_run}/attempts/{_positive(run.get('run_attempt'))}/jobs?per_page=100"
                )
                publications = [
                    job for job in jobs.get("jobs", []) if job.get("name") == "Publish PR canary to TestPyPI"
                ]
                if len(publications) != 1 or publications[0].get("conclusion") != "success":
                    raise ValueError("canary_publication_missing")
                artifacts = fetch(f"{prefix}/actions/runs/{frozen_run}/artifacts?per_page=100")
                if type(artifacts.get("total_count")) is not int or artifacts["total_count"] > 100:
                    raise ValueError("canary_artifact_listing_incomplete")
                binding = bind_attempt(
                    run,
                    artifacts.get("artifacts", []),
                    repository=repository,
                    source_sha=source_sha,
                    pull_request=pull_request,
                    base_version=base_version,
                )
                current = fetch(f"{prefix}/actions/runs/{frozen_run}")
                if any(current.get(key) != run.get(key) for key in ("run_attempt", "status", "conclusion", "head_sha")):
                    raise ValueError("canary_attempt_changed")
                return binding
        pause(min(15.0, max(0.0, deadline - clock())))
    raise TimeoutError("canary_publication_wait_expired")


def _github_json(path: str) -> Mapping[str, Any]:
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"canary_api_http_{error.code}") from None
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("canary_api_response_too_large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("canary_api_response_invalid")
    return value


def main() -> None:
    import tomllib  # The workflow pins Python 3.12.

    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    binding = resolve(
        _github_json,
        repository=os.environ["GITHUB_REPOSITORY"],
        source_sha=os.environ["SOURCE_SHA"],
        pull_request=int(os.environ["PR_NUMBER"]),
        base_version=project["project"]["version"],
        deadline=time.monotonic() + 5400,
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        for key, value in binding.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":
    main()
