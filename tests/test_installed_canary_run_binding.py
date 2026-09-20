"""PR-only canaries require one immutable successful publication attempt."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.resolve_installed_canary_run import bind_attempt, resolve

REPOSITORY = "example/project"
SOURCE = "a" * 40


def _run() -> dict[str, Any]:
    return {
        "id": 100,
        "run_number": 12,
        "run_attempt": 2,
        "status": "completed",
        "conclusion": "success",
        "event": "pull_request",
        "path": ".github/workflows/publish.yml",
        "head_sha": SOURCE,
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "pull_requests": [{"number": 5, "head": {"sha": SOURCE}}],
        "run_started_at": "2026-01-01T12:00:00Z",
    }


def _artifacts() -> list[dict[str, Any]]:
    return [
        {
            "id": 201 + index,
            "name": name,
            "expired": False,
            "created_at": "2026-01-01T12:01:00Z",
            "workflow_run": {"id": 100},
        }
        for index, name in enumerate(("distributions-native", "installed-canary-subject"))
    ]


def _bind(run: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, str]:
    return bind_attempt(run, artifacts, repository=REPOSITORY, source_sha=SOURCE, pull_request=5, base_version="3.0.1")


def test_attempt_binding_uses_immutable_artifact_ids_and_independent_run_version() -> None:
    bound = _bind(_run(), _artifacts())
    assert bound == {
        "distribution_artifact_id": "201",
        "subject_artifact_id": "202",
        "run_id": "100",
        "run_attempt": "2",
        "source_sha": SOURCE,
        "version": "3.0.1.dev14030",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("event", "workflow_dispatch"),
        ("path", ".github/workflows/other.yml"),
        ("head_sha", "b" * 40),
        ("repository", {"full_name": "other/project"}),
        ("head_repository", {"full_name": "fork/project"}),
        ("pull_requests", []),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("id", True),
        ("run_number", 12.0),
        ("run_attempt", 0),
        ("run_started_at", "yesterday"),
    ],
)
def test_run_identity_or_unfinished_attempt_is_rejected(field: str, value: object) -> None:
    run = _run()
    run[field] = value
    with pytest.raises(ValueError):
        _bind(run, _artifacts())


@pytest.mark.parametrize("fault", ["missing", "duplicate", "old-attempt", "expired", "wrong-run", "boolean-id"])
def test_artifacts_cannot_cross_attempt_or_run(fault: str) -> None:
    artifacts = _artifacts()
    if fault == "missing":
        artifacts.pop()
    elif fault == "duplicate":
        artifacts.append(deepcopy(artifacts[0]))
    elif fault == "old-attempt":
        artifacts[0]["created_at"] = "2026-01-01T11:59:59Z"
    elif fault == "expired":
        artifacts[0]["expired"] = True
    elif fault == "wrong-run":
        artifacts[0]["workflow_run"]["id"] = 99
    else:
        artifacts[0]["id"] = True
    with pytest.raises(ValueError):
        _bind(_run(), artifacts)


@pytest.mark.parametrize("fault", [None, "changed-head", "skipped-publish", "changed-attempt", "incomplete-artifacts"])
def test_real_resolver_requires_completed_publication_and_rechecks_attempt(fault: str | None) -> None:
    calls: list[str] = []
    run_reads = 0

    def fetch(path: str) -> dict[str, Any]:
        nonlocal run_reads
        calls.append(path)
        if path.endswith("/pulls/5"):
            return {"head": {"sha": "b" * 40 if fault == "changed-head" else SOURCE, "repo": {"full_name": REPOSITORY}}}
        if "/workflows/publish.yml/runs?" in path:
            return {"workflow_runs": [_run()]}
        if "/jobs?" in path:
            return {
                "jobs": [
                    {
                        "name": "Publish PR canary to TestPyPI",
                        "conclusion": "skipped" if fault == "skipped-publish" else "success",
                    }
                ]
            }
        if "/artifacts?" in path:
            return {"total_count": 101 if fault == "incomplete-artifacts" else 2, "artifacts": _artifacts()}
        assert path.endswith("/runs/100")
        run_reads += 1
        run = _run()
        if run_reads > 1 and fault == "changed-attempt":
            run["run_attempt"] = 3
        return run

    kwargs: dict[str, Any] = dict(
        repository=REPOSITORY, source_sha=SOURCE, pull_request=5, base_version="3.0.1", deadline=1.0, clock=lambda: 0.0
    )
    if fault:
        with pytest.raises(ValueError):
            resolve(fetch, **kwargs)
    else:
        assert resolve(fetch, **kwargs) == _bind(_run(), _artifacts())
        assert run_reads == 2
        assert any("/attempts/2/jobs?" in path for path in calls)


def test_resolver_fails_boundedly_when_no_matching_publication_exists() -> None:
    now = 0.0

    def pause(duration: float) -> None:
        nonlocal now
        now += duration

    def fetch(path: str) -> dict[str, Any]:
        if "/pulls/" in path:
            return {"head": {"sha": SOURCE, "repo": {"full_name": REPOSITORY}}}
        return {"workflow_runs": []}

    with pytest.raises(TimeoutError, match="canary_publication_wait_expired"):
        resolve(
            fetch,
            repository=REPOSITORY,
            source_sha=SOURCE,
            pull_request=5,
            base_version="3.0.1",
            deadline=16.0,
            clock=lambda: now,
            pause=pause,
        )
    assert now == 16.0


def test_installed_workflow_has_no_default_branch_trigger_or_mutable_artifact_selector() -> None:
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/installed-pr-canary.yml").read_text())
    assert set(workflow[True]) == {"pull_request"}
    for job in workflow["jobs"].values():
        assert job["cache-mode"] == "none"
        assert all(value == "read" for value in job["permissions"].values())
    steps = workflow["jobs"]["pr-installed-canary"]["steps"]
    downloads = [step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")]
    assert len(downloads) == 2
    for step in downloads:
        assert "artifact-ids" in step["with"]
        assert "name" not in step["with"]
        assert step["with"]["run-id"] == "${{ needs.resolve-canary.outputs.run_id }}"
    assert workflow["jobs"]["resolve-canary"]["timeout-minutes"] == 95
