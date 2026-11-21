"""Verify release provenance before a workflow_run consumer checks out source."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

_WORKFLOW_PATH = ".github/workflows/publish.yml"
_RELEASE_BRANCHES = frozenset({"main", "release/3.0"})
# Release Please dispatches each stable publication on its tag, so GitHub reports
# the tag name as the run's head_branch. The tagged commit must still be on main.
_STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
_SHA = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_PUBLICATION_JOBS = {
    "main": frozenset({"Publish main release to PyPI", "Create main GitHub release"}),
    "release/3.0": frozenset({"Publish alpha to PyPI", "Create alpha GitHub prerelease"}),
}


def _mapping(value: object, label: str) -> dict:
    """Reject missing or malformed API objects instead of guessing defaults."""
    if not isinstance(value, dict):
        raise ValueError(f"Missing or invalid {label}")
    return value


def _positive_id(value: object, label: str) -> int:
    """Require a real numeric GitHub ID, not a boolean or an API path fragment."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"Invalid {label}")
    return value


def _same_repository(value: object, repository: str, repository_id: int) -> None:
    """Bind repository names to numeric identity, rejecting fork-name lookalikes."""
    metadata = _mapping(value, "repository identity")
    if metadata.get("full_name") != repository or metadata.get("id") != repository_id:
        raise ValueError("Release source does not belong to the expected repository")


def _validate_run(run: dict, repository: str, repository_id: int, workflow_id: int) -> tuple[str, str, str | None]:
    """Accept only first-attempt successful canonical releases on allowed branches or stable tags."""
    _same_repository(run.get("head_repository"), repository, repository_id)
    if run.get("workflow_id") != workflow_id or run.get("path") != _WORKFLOW_PATH:
        raise ValueError("The run did not execute the canonical publishing workflow")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("The publishing workflow did not complete successfully")
    if not isinstance(run.get("event"), str) or run["event"] not in {"push", "workflow_dispatch"}:
        raise ValueError("Pull-request and indirect workflow events cannot authorize publication")
    if type(run.get("run_attempt")) is not int or run["run_attempt"] != 1:
        raise ValueError("Rerun attempts cannot authorize publication")
    branch = run.get("head_branch")
    sha = run.get("head_sha")
    tag = None
    if isinstance(branch, str) and run["event"] == "workflow_dispatch" and _STABLE_TAG.fullmatch(branch):
        tag, branch = branch, "main"
    elif not isinstance(branch, str) or branch not in _RELEASE_BRANCHES:
        raise ValueError("The publishing branch is not allowed")
    if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
        raise ValueError("Invalid release source SHA")
    commit = _mapping(run.get("head_commit"), "release commit")
    if commit.get("id") != sha or not isinstance(commit.get("message"), str):
        raise ValueError("Release commit metadata does not match the source SHA")
    if "[skip release publish]" in commit["message"]:
        raise ValueError("Release publication was explicitly skipped")
    return sha, branch, tag


def _verify_tag_target(prefix: str, tag: str, sha: str, fetch_json: Callable[[str], object]) -> None:
    """Require the dispatched stable tag to name the exact commit the run built."""
    target = _mapping(_mapping(fetch_json(f"{prefix}/git/ref/tags/{tag}"), "release tag").get("object"), "tag target")
    if target.get("type") == "tag" and isinstance(target.get("sha"), str) and _SHA.fullmatch(target["sha"]):
        annotated = _mapping(fetch_json(f"{prefix}/git/tags/{target['sha']}"), "annotated release tag")
        target = _mapping(annotated.get("object"), "annotated tag target")
    if target.get("type") != "commit" or target.get("sha") != sha:
        raise ValueError("The release tag does not point at the published source SHA")


def verify_release_source(
    event: object, *, event_name: str, repository: str, fetch_json: Callable[[str], object]
) -> tuple[str, str]:
    """Recheck the run through GitHub and prove its SHA is on a trusted release branch."""
    if event_name != "workflow_run" or _REPOSITORY.fullmatch(repository) is None:
        raise ValueError("Expected a workflow_run in a canonical GitHub repository")
    payload = _mapping(event, "event")
    event_repository = _mapping(payload.get("repository"), "event repository")
    repository_id = _positive_id(event_repository.get("id"), "repository ID")
    _same_repository(event_repository, repository, repository_id)
    event_run = _mapping(payload.get("workflow_run"), "workflow run event")
    run_id = _positive_id(event_run.get("id"), "workflow run ID")
    prefix = f"/repos/{repository}"
    workflow = _mapping(fetch_json(f"{prefix}/actions/workflows/publish.yml"), "canonical workflow")
    workflow_id = _positive_id(workflow.get("id"), "workflow ID")
    if workflow.get("path") != _WORKFLOW_PATH or workflow.get("state") != "active":
        raise ValueError("The canonical publishing workflow is not active")
    expected = _validate_run(event_run, repository, repository_id, workflow_id)
    run = _mapping(fetch_json(f"{prefix}/actions/runs/{run_id}"), "live workflow run")
    if run.get("id") != run_id:
        raise ValueError("GitHub returned a different workflow run")
    _same_repository(run.get("repository"), repository, repository_id)
    verified = _validate_run(run, repository, repository_id, workflow_id)
    if verified != expected or run.get("event") != event_run.get("event"):
        raise ValueError("The event and live publishing run disagree")
    sha, branch, tag = verified
    if tag is not None:
        _verify_tag_target(prefix, tag, sha, fetch_json)
    head = urllib.parse.quote(f"refs/heads/{branch}", safe="")
    comparison = _mapping(fetch_json(f"{prefix}/compare/{sha}...{head}?per_page=1"), "branch comparison")
    base = _mapping(comparison.get("base_commit"), "comparison base")
    merge_base = _mapping(comparison.get("merge_base_commit"), "comparison merge base")
    if comparison.get("status") not in {"ahead", "identical"} or base.get("sha") != sha or merge_base.get("sha") != sha:
        raise ValueError("The release SHA is not reachable from its trusted release branch")
    return sha, branch


def dispatched_release_event(run_id: str, *, repository: str, fetch_json: Callable[[str], object]) -> dict:
    """Rebuild a workflow_run payload from GitHub for a maintainer's repair dispatch.

    Nothing in the result comes from the dispatcher except the run ID, so the
    repair passes exactly the checks an automatic workflow_run would. Only the
    current latest stable release qualifies, which keeps a dispatch from moving
    the MCP Registry back to an older version.
    """
    if _RUN_ID.fullmatch(run_id) is None or _REPOSITORY.fullmatch(repository) is None:
        raise ValueError("A numeric publishing run ID is required")
    prefix = f"/repos/{repository}"
    identity = _mapping(fetch_json(prefix), "repository")
    run = _mapping(fetch_json(f"{prefix}/actions/runs/{run_id}"), "publishing run")
    latest = _mapping(fetch_json(f"{prefix}/releases/latest"), "latest release")
    if latest.get("tag_name") != run.get("head_branch") or latest.get("draft") or latest.get("prerelease"):
        raise ValueError("Only the latest stable release can be republished by dispatch")
    return {"repository": {"id": identity.get("id"), "full_name": identity.get("full_name")}, "workflow_run": run}


def released_tag(event: dict) -> str:
    """Name the stable tag a verified tag-dispatched run released, or "" for a branch run.

    Consumers publish exactly this tag. Picking the highest tag at the SHA instead
    could publish a different version when two stable tags share a commit.
    """
    run = _mapping(event.get("workflow_run"), "workflow run event")
    branch = run.get("head_branch")
    if run.get("event") == "workflow_dispatch" and isinstance(branch, str) and _STABLE_TAG.fullmatch(branch):
        return branch
    return ""


def publication_completed(
    event: dict, *, repository: str, sha: str, branch: str, fetch_json: Callable[[str], object]
) -> bool:
    """Distinguish a completed release from successful build-only publishing runs."""
    run_id = _positive_id(_mapping(event.get("workflow_run"), "workflow run event").get("id"), "workflow run ID")
    expected_names = _PUBLICATION_JOBS[branch]
    # A main-ref dispatch can publish an alpha instead of a stable release. Those
    # jobs never authorize the main-release consumers, whatever their conclusion.
    alpha_names = _PUBLICATION_JOBS["release/3.0"]
    alpha_job_seen = False
    publication_jobs: dict[str, dict] = {}
    # Read the original attempt, never a later rerun's jobs, and bound pagination.
    for page in range(1, 11):
        payload = _mapping(
            fetch_json(f"/repos/{repository}/actions/runs/{run_id}/attempts/1/jobs?per_page=100&page={page}"),
            "publishing jobs",
        )
        total_count = payload.get("total_count")
        jobs = payload.get("jobs")
        if type(total_count) is not int or not 0 <= total_count <= 1000 or not isinstance(jobs, list):
            raise ValueError("Invalid publishing job list")
        for raw_job in jobs:
            job = _mapping(raw_job, "publishing job")
            name = job.get("name")
            if not isinstance(name, str):
                raise ValueError("Invalid publishing job name")
            if name not in expected_names:
                alpha_job_seen = alpha_job_seen or (branch == "main" and name in alpha_names)
                continue
            if name in publication_jobs:
                raise ValueError("Duplicate canonical publishing job")
            if (
                job.get("run_id") != run_id
                or job.get("head_sha") != sha
                or job.get("status") != "completed"
                or not isinstance(job.get("conclusion"), str)
            ):
                raise ValueError("Publishing job does not match the completed release run")
            publication_jobs[name] = job
        if page * 100 >= total_count:
            break
        if len(jobs) != 100:
            raise ValueError("Incomplete publishing job list")
    if not publication_jobs and alpha_job_seen:
        return False
    if publication_jobs.keys() != expected_names:
        raise ValueError("Canonical publishing jobs are missing from the completed run")
    conclusions = {job.get("conclusion") for job in publication_jobs.values()}
    if conclusions == {"skipped"}:
        return False
    if conclusions != {"success"}:
        raise ValueError("Canonical package and release publication did not both succeed")
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward the workflow token to a redirected API location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Reject redirects, including repository renames, until identity is reconfigured."""
        raise ValueError("Unexpected GitHub API redirect")


def github_json(path: str) -> object:
    """Read bounded JSON from the fixed GitHub API without logging credentials."""
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise ValueError("A read-only GitHub token is required")
    request = urllib.request.Request(
        "https://api.github.com" + path,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hol-guard-release-source-verifier",
        },
    )
    with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
        content = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(content) > _MAX_RESPONSE_BYTES:
        raise ValueError("GitHub API response exceeded the verification limit")
    return json.loads(content)


def main() -> int:
    """Emit checkout inputs only after all provenance and ancestry checks pass."""
    try:
        event_name = os.environ["GITHUB_EVENT_NAME"]
        if event_name == "workflow_dispatch":
            event = dispatched_release_event(
                os.environ.get("PUBLICATION_RUN_ID", ""),
                repository=os.environ["GITHUB_REPOSITORY"],
                fetch_json=github_json,
            )
            # Every field was just read from GitHub, so it is checked as an automatic run would be.
            event_name = "workflow_run"
        else:
            event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        sha, branch = verify_release_source(
            event,
            event_name=event_name,
            repository=os.environ["GITHUB_REPOSITORY"],
            fetch_json=github_json,
        )
        if not publication_completed(
            event, repository=os.environ["GITHUB_REPOSITORY"], sha=sha, branch=branch, fetch_json=github_json
        ):
            print("Publishing workflow completed without a release; downstream publication is skipped")
            return 0
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"sha={sha}\nbranch={branch}\ntag={released_tag(event)}\n")
    except (KeyError, ValueError, OSError, urllib.error.URLError) as error:
        print(f"Release source verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified release source {sha} on {branch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
