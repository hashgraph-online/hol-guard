from __future__ import annotations

import json
import urllib.error
import urllib.request
from copy import deepcopy
from http.client import HTTPMessage
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from scripts.ci import wait_for_pytest_shards as barrier

_RUN_ID = 123456


def _job(index: int, *, status: str = "completed", conclusion: str | None = "success") -> dict[str, object]:
    return {
        "id": index + 100,
        "name": f"tests (3.12, {index})",
        "run_id": _RUN_ID,
        "status": status,
        "conclusion": conclusion,
    }


def _jobs() -> list[dict[str, object]]:
    return [_job(index) for index in range(barrier.SHARD_COUNT)]


def _run(snapshots: list[list[dict[str, object]]], *, timeout_seconds: float = 240) -> tuple[list[str], list[str]]:
    now = [0.0]
    calls: list[str] = []
    logs: list[str] = []

    def fetch(path: str, timeout: float) -> dict[str, object]:
        assert 0 < timeout <= 10
        calls.append(path)
        selected = snapshots[min(int(now[0] // 5), len(snapshots) - 1)]
        page = int(path.rsplit("=", 1)[1])
        return {"total_count": len(selected), "jobs": selected[(page - 1) * 100 : page * 100]}

    def sleep(seconds: float) -> None:
        now[0] += seconds

    barrier.wait_for_shards(
        "hashgraph-online/hol-guard",
        _RUN_ID,
        2,
        fetch_json=fetch,
        clock=lambda: now[0],
        sleep=sleep,
        log=logs.append,
        timeout_seconds=timeout_seconds,
    )
    return calls, logs


def test_waits_through_planning_queue_and_running_then_requires_last_page() -> None:
    other_jobs = [dict(_job(index + 1000), name=f"quality-{index}") for index in range(20)]
    queued = [_job(index, status="queued", conclusion=None) for index in range(barrier.SHARD_COUNT)]
    running = deepcopy(queued)
    running[0].update(status="in_progress")
    calls, logs = _run([[], other_jobs + queued, other_jobs + queued, other_jobs + running, other_jobs + _jobs()])
    assert len(calls) == 9
    assert all(f"/runs/{_RUN_ID}/attempts/2/jobs?per_page=100&page=" in path for path in calls)
    assert calls[-1].endswith("page=2")
    assert len(logs) == 6  # initial identity, four transitions, final success
    assert f"{barrier.SHARD_COUNT} not yet scheduled" in logs[1]
    assert f"{barrier.SHARD_COUNT} queued" in logs[2]
    assert "1 running" in logs[3]
    assert logs[-1] == f"All {barrier.SHARD_COUNT} Python shards succeeded in run {_RUN_ID}, attempt 2"


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out", "neutral", None, {}])
def test_rejects_non_success_on_last_page(conclusion: object) -> None:
    jobs = [dict(_job(index + 1000), name="other") for index in range(20)] + _jobs()
    jobs[-1]["conclusion"] = conclusion
    with pytest.raises(barrier.ShardWaitError, match=f"Python shard {barrier.SHARD_COUNT - 1} completed with"):
        _run([jobs])


@pytest.mark.parametrize("status,conclusion", [("unexpected", None), ("in_progress", "failure"), (None, None)])
def test_rejects_invalid_shard_state(status: object, conclusion: object) -> None:
    jobs = _jobs()
    jobs[0].update(status=status, conclusion=conclusion)
    with pytest.raises(barrier.ShardWaitError, match="invalid job state"):
        _run([jobs])


@pytest.mark.parametrize(
    "index", [str(barrier.SHARD_COUNT), "-1", "00", "1.0", "${{ matrix.shard-index }}", "1) suffix"]
)
def test_rejects_invalid_shard_names(index: str) -> None:
    jobs = [*_jobs(), dict(_job(200), name=f"tests (3.12, {index})")]
    with pytest.raises(barrier.ShardWaitError, match="invalid Python shard index"):
        _run([jobs])


def test_rejects_duplicate_index_with_distinct_job_id() -> None:
    jobs = [*_jobs(), dict(_job(0), id=9000)]
    with pytest.raises(barrier.ShardWaitError, match="duplicate Python shard 0"):
        _run([jobs])


def test_rejects_duplicate_job_id_across_pages() -> None:
    jobs = [dict(_job(index + 1000), name="other") for index in range(20)] + _jobs()
    jobs[-1]["id"] = jobs[0]["id"]
    with pytest.raises(barrier.ShardWaitError, match="duplicate job"):
        _run([jobs])


@pytest.mark.parametrize("field,value", [("run_id", 99), ("run_id", True), ("run_attempt", 1)])
@pytest.mark.parametrize("index", [0, barrier.SHARD_COUNT - 1])
def test_rejects_jobs_from_another_run_or_attempt(field: str, value: object, index: int) -> None:
    jobs = _jobs()
    jobs[index][field] = value
    with pytest.raises(barrier.ShardWaitError, match=r"another (run|attempt)"):
        _run([jobs])


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out"])
def test_stops_immediately_when_planning_failed(conclusion: str) -> None:
    plan = dict(_job(1000), name="test-plan", conclusion=conclusion)
    with pytest.raises(barrier.ShardWaitError, match=f"Python test-plan completed with {conclusion}"):
        _run([[plan]])


@pytest.mark.parametrize("completed_shards", [0, 96, barrier.SHARD_COUNT - 1])
def test_missing_shard_and_partial_reruns_expire_without_accepting_old_coverage(completed_shards: int) -> None:
    with pytest.raises(barrier.ShardWaitError, match="Timed out"):
        _run([_jobs()[:completed_shards]], timeout_seconds=10)


@pytest.mark.parametrize("payload", [None, {}, {"total_count": True, "jobs": []}, {"total_count": 101, "jobs": []}])
def test_rejects_malformed_or_incomplete_api_pages(payload: object) -> None:
    with pytest.raises(barrier.ShardWaitError, match=r"invalid|incomplete"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, fetch_json=lambda *_args: payload)


def test_success_received_after_deadline_cannot_pass() -> None:
    now = [0.0]
    calls: list[str] = []

    def late_response(path: str, _timeout: float) -> object:
        calls.append(path)
        page = int(path.rsplit("=", 1)[1])
        jobs = _jobs()
        if page == 2:
            now[0] = 241
        return {"total_count": len(jobs), "jobs": jobs[(page - 1) * 100 : page * 100]}

    with pytest.raises(barrier.ShardWaitError, match="Timed out"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, fetch_json=late_response, clock=lambda: now[0])
    assert len(calls) == 2


@pytest.mark.parametrize(
    "repository,run_id,attempt", [("owner/../repo", _RUN_ID, 1), ("owner/repo", True, 1), ("a/b", 1, 0)]
)
def test_rejects_invalid_run_inputs_before_network(repository: str, run_id: int, attempt: int) -> None:
    with pytest.raises(barrier.ShardWaitError, match=r"Invalid|positive"):
        barrier.wait_for_shards(
            repository, run_id, attempt, fetch_json=lambda *_args: pytest.fail("unexpected network")
        )


@pytest.mark.parametrize("timeout", [0, -1, 601, float("inf"), float("nan")])
def test_rejects_unbounded_wait(timeout: float) -> None:
    with pytest.raises(barrier.ShardWaitError, match="timeout"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, timeout_seconds=timeout)


def test_api_request_uses_only_fixed_origin_and_read_token(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class Response:
        status = 200

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def read(self, limit: int) -> bytes:
            assert limit == barrier._MAX_RESPONSE_BYTES + 1
            return json.dumps({"total_count": 0, "jobs": []}).encode()

    def open_request(request: Any, *, timeout: float) -> Response:
        seen.update(
            url=request.full_url, method=request.get_method(), authorization=request.get_header("Authorization")
        )
        assert timeout == 4
        return Response()

    monkeypatch.setenv("GITHUB_TOKEN", "test-read-token")
    monkeypatch.setattr(barrier.urllib.request, "build_opener", lambda *_args: SimpleNamespace(open=open_request))
    assert barrier.github_json("/repos/owner/repo/actions/runs/1/attempts/2/jobs", 4) == {"total_count": 0, "jobs": []}
    assert seen == {
        "url": "https://api.github.com/repos/owner/repo/actions/runs/1/attempts/2/jobs",
        "method": "GET",
        "authorization": "Bearer test-read-token",
    }


@pytest.mark.parametrize("code", [403, 404, 429, 500])
def test_http_failures_do_not_leak_response_or_token(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.HTTPError("https://api.github.com", code, "secret-response", HTTPMessage(), None)

    monkeypatch.setenv("GITHUB_TOKEN", "secret-read-token")
    monkeypatch.setattr(barrier.urllib.request, "build_opener", lambda *_args: SimpleNamespace(open=fail))
    with pytest.raises(barrier.ShardWaitError, match=f"HTTP {code}") as captured:
        barrier.github_json("/repos/a/b/actions/runs/1/attempts/1/jobs", 1)
    assert "secret" not in str(captured.value)


def test_api_redirect_is_rejected() -> None:
    request = urllib.request.Request("https://api.github.com/repos/a/b/actions/runs/1/attempts/2/jobs")
    with pytest.raises(barrier.ShardWaitError, match="redirect"):
        barrier._NoRedirect().redirect_request(request, BytesIO(), 302, "", HTTPMessage(), "https://other.example")


def test_sonar_accepts_only_complete_coverage_from_successful_current_attempt() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    jobs = workflow["jobs"]
    assert barrier.SHARD_COUNT == 128
    assert jobs["tests"]["strategy"]["matrix"]["shard-index"] == list(range(barrier.SHARD_COUNT))
    producer = next(
        step for step in jobs["tests"]["steps"] if step.get("name") == "Upload pytest coverage data artifact"
    )
    sonar_steps = jobs["sonar"]["steps"]
    consumer = next(step for step in sonar_steps if step.get("name") == "Download pytest coverage data")
    waiter = next(step for step in sonar_steps if "wait_for_pytest_shards.py" in step.get("run", ""))

    assert producer["with"]["name"] == "pytest-coverage-${{ github.run_attempt }}-${{ matrix.shard-index }}"
    assert producer["with"]["if-no-files-found"] == "error"
    assert consumer["with"]["pattern"] == "pytest-coverage-${{ github.run_attempt }}-*"
    assert "run-id" not in consumer["with"]  # Download remains scoped to the current workflow run.
    assert sonar_steps.index(waiter) < sonar_steps.index(consumer)
    assert waiter["env"] == {"GITHUB_TOKEN": "${{ github.token }}"}
    assert jobs["sonar"]["permissions"] == {"contents": "read", "actions": "read"}
    assert 'test "${#reports[@]}" -eq 128' in (root / "scripts/ci/prepare_sonar_analysis.sh").read_text()
