from __future__ import annotations

import inspect
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
        "name": f"coverage (3.12, {index})",
        "run_id": _RUN_ID,
        "status": status,
        "conclusion": conclusion,
        "created_at": "2026-09-20T16:56:28Z",
        "started_at": "2026-09-20T16:56:31Z",
        "completed_at": "2026-09-20T16:57:35Z",
    }


def _jobs() -> list[dict[str, object]]:
    return [_job(index) for index in range(barrier.SHARD_COUNT)]


def _run(
    snapshots: list[list[dict[str, object]]], *, timeout_seconds: float = barrier._DEFAULT_TIMEOUT_SECONDS
) -> tuple[list[str], list[str]]:
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
    assert len(calls) == 13
    assert all(f"/runs/{_RUN_ID}/attempts/2/jobs?per_page=100&page=" in path for path in calls)
    assert calls[-1].endswith("page=3")
    assert len(logs) == 6  # initial identity, four transitions, final success
    assert f"{barrier.SHARD_COUNT} not yet scheduled" in logs[1]
    assert f"{barrier.SHARD_COUNT} queued" in logs[2]
    assert "1 running" in logs[3]
    assert logs[-1] == f"All {barrier.SHARD_COUNT} Python coverage shards succeeded in run {_RUN_ID}, attempt 2"


def test_default_wait_covers_existing_producer_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    root = Path(__file__).resolve().parents[1]
    jobs = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())["jobs"]
    producer_limit = 60 * (jobs["coverage-plan"]["timeout-minutes"] + jobs["coverage"]["timeout-minutes"])
    default_timeout = inspect.signature(barrier.wait_for_shards).parameters["timeout_seconds"].default
    assert default_timeout == producer_limit + 60
    captured: dict[str, float] = {}

    def capture_wait(_repository: str, _run_id: int, _attempt: int, **kwargs: float) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(barrier, "wait_for_shards", capture_wait)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", str(_RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    assert barrier.main([]) == 0
    assert captured == {"timeout_seconds": default_timeout, "poll_seconds": 5.0}


def test_default_wait_accepts_healthy_shards_after_full_planning_and_execution_limits() -> None:
    running = [_job(index, status="in_progress", conclusion=None) for index in range(barrier.SHARD_COUNT)]
    # Advance only the injected clock: five minutes planning, five minutes
    # execution, and one polling interval for the complete success to appear.
    _, logs = _run([[]] * 60 + [running] * 61 + [_jobs()])
    assert logs[-1] == f"All {barrier.SHARD_COUNT} Python coverage shards succeeded in run {_RUN_ID}, attempt 2"


def test_cli_accepts_one_second_poll_without_changing_producer_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, float] = {}

    def capture_wait(_repository: str, _run_id: int, _attempt: int, **kwargs: float) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(barrier, "wait_for_shards", capture_wait)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", str(_RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    assert barrier.main(["--poll-seconds", "1"]) == 0
    assert captured == {"timeout_seconds": barrier._DEFAULT_TIMEOUT_SECONDS, "poll_seconds": 1.0}


@pytest.mark.parametrize("legacy_shards", [32, 128])
def test_untraced_python312_jobs_cannot_supply_missing_coverage(legacy_shards: int) -> None:
    compatibility_jobs = [
        dict(_job(index), id=index + 10000, name=f"tests (3.12, {index})") for index in range(legacy_shards)
    ]
    with pytest.raises(barrier.ShardWaitError, match="Timed out"):
        _run([compatibility_jobs + _jobs()[:-1]], timeout_seconds=10)


def test_coverage_succeeds_only_after_its_own_complete_suite() -> None:
    compatibility_jobs = [dict(_job(index), id=index + 10000, name=f"tests (3.12, {index})") for index in range(32)]
    coverage_running = [_job(index, status="in_progress", conclusion=None) for index in range(barrier.SHARD_COUNT)]
    _, logs = _run([compatibility_jobs + coverage_running, compatibility_jobs + _jobs()])
    assert f"{barrier.SHARD_COUNT} running" in logs[1]
    assert logs[-1] == f"All {barrier.SHARD_COUNT} Python coverage shards succeeded in run {_RUN_ID}, attempt 2"


def test_other_python_coverage_cannot_supply_missing_python312_producer() -> None:
    other_python_jobs = [
        dict(_job(index), id=index + 10000, name=f"coverage (3.14, {index})") for index in range(barrier.SHARD_COUNT)
    ]
    with pytest.raises(barrier.ShardWaitError, match="Timed out"):
        _run([other_python_jobs + _jobs()[:-1]], timeout_seconds=10)


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out", "neutral", None, {}])
def test_rejects_non_success_on_last_page(conclusion: object) -> None:
    jobs = [dict(_job(index + 1000), name="other") for index in range(20)] + _jobs()
    jobs[-1]["conclusion"] = conclusion
    with pytest.raises(barrier.ShardWaitError, match=f"Python coverage shard {barrier.SHARD_COUNT - 1} completed with"):
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
    jobs = [*_jobs(), dict(_job(200), name=f"coverage (3.12, {index})")]
    with pytest.raises(barrier.ShardWaitError, match="invalid Python coverage shard index"):
        _run([jobs])


def test_rejects_duplicate_index_with_distinct_job_id() -> None:
    jobs = [*_jobs(), dict(_job(0), id=9000)]
    with pytest.raises(barrier.ShardWaitError, match="duplicate Python coverage shard 0"):
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


@pytest.mark.parametrize("index", [0, barrier.SHARD_COUNT - 1])
def test_rejects_inherited_success_with_new_job_id_and_current_attempt(index: int) -> None:
    jobs = _jobs()
    # Actual GitHub partial-rerun behavior: the attempt-2 endpoint returns
    # a new ID and run_attempt=2 while retaining attempt-1 execution times.
    jobs[index].update(
        id=106114322689,
        run_attempt=2,
        created_at="2026-09-20T17:01:44Z",
        started_at="2026-09-20T16:55:15Z",
        completed_at="2026-09-20T16:56:58Z",
    )
    with pytest.raises(barrier.ShardWaitError, match=f"Python coverage shard {index} inherited execution"):
        _run([jobs])


@pytest.mark.parametrize("field", ["created_at", "started_at", "completed_at"])
@pytest.mark.parametrize("value", [None, 123, "2026-09-20", "2026-02-30T16:55:15Z", "secret-response"])
def test_success_requires_valid_complete_execution_timestamps(field: str, value: object) -> None:
    jobs = _jobs()
    jobs[0][field] = value
    with pytest.raises(barrier.ShardWaitError, match="invalid execution timestamps") as captured:
        _run([jobs])
    assert "secret-response" not in str(captured.value)


def test_success_cannot_complete_before_starting() -> None:
    jobs = _jobs()
    jobs[0]["completed_at"] = "2026-09-20T16:56:30Z"
    with pytest.raises(barrier.ShardWaitError, match="invalid execution timestamps"):
        _run([jobs])


def test_pending_shards_need_not_have_execution_timestamps_yet() -> None:
    queued = [_job(index, status="queued", conclusion=None) for index in range(barrier.SHARD_COUNT)]
    for job in queued:
        job.pop("started_at")
        job.pop("completed_at")
    _, logs = _run([queued, _jobs()])
    assert f"{barrier.SHARD_COUNT} queued" in logs[1]
    assert logs[-1].startswith(f"All {barrier.SHARD_COUNT} Python coverage shards succeeded")


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out"])
def test_stops_immediately_when_planning_failed(conclusion: str) -> None:
    plan = dict(_job(1000), name="coverage-plan", conclusion=conclusion)
    with pytest.raises(barrier.ShardWaitError, match=f"Python coverage-plan completed with {conclusion}"):
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
            now[0] = barrier._DEFAULT_TIMEOUT_SECONDS + 1
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


@pytest.mark.parametrize("timeout", [0, -1, barrier._DEFAULT_TIMEOUT_SECONDS + 1, float("inf"), float("nan")])
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
    assert barrier.SHARD_COUNT == 192
    assert jobs["coverage"]["name"] == "coverage (3.12, ${{ matrix.shard-index }})"
    assert jobs["coverage"]["strategy"]["matrix"]["shard-index"] == list(range(barrier.SHARD_COUNT))
    producer = next(
        step for step in jobs["coverage"]["steps"] if step.get("name") == "Upload pytest coverage data artifact"
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
    assert waiter["run"].endswith("--poll-seconds 1")
    assert jobs["sonar"]["permissions"] == {"contents": "read", "actions": "read"}
    assert 'test "${#reports[@]}" -eq 192' in (root / "scripts/ci/prepare_sonar_analysis.sh").read_text()


def test_sonar_installs_same_pinned_scanner_before_wait_without_analysis_credentials() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["sonar"]["steps"]
    installer = next(step for step in steps if step.get("name") == "Install pinned Sonar scanner CLI")
    analysis = next(step for step in steps if step.get("name") == "Analyze with SonarQube Cloud")
    waiter = next(step for step in steps if "wait_for_pytest_shards.py" in step.get("run", ""))
    assert installer["uses"] == analysis["uses"]
    assert installer["with"] == {"args": "--version"}
    assert installer["env"] == {"SONAR_USER_HOME": analysis["env"]["SONAR_USER_HOME"]}
    assert "with" not in analysis
    assert analysis["env"]["SONAR_TOKEN"] == "${{ secrets.SONAR_TOKEN }}"
    assert steps.index(installer) < steps.index(waiter) < steps.index(analysis)
