from __future__ import annotations

import ssl
import urllib.error
from contextlib import nullcontext
from http.client import HTTPMessage, IncompleteRead
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci import wait_for_pytest_shards as barrier
from tests.test_ci_wait_for_pytest_shards import _RUN_ID, _jobs


def _fixture(events: list[object]) -> tuple[dict[str, Any], list[str], list[float], list[str]]:
    now = [0.0]
    calls: list[str] = []
    sleeps: list[float] = []
    logs: list[str] = []

    def fetch(path: str, timeout: float) -> object:
        assert 0 < timeout <= 10
        calls.append(path)
        event = events.pop(0)
        if isinstance(event, Exception):
            raise event
        return event

    def sleep(delay: float) -> None:
        sleeps.append(delay)
        now[0] += delay

    return {"fetch_json": fetch, "clock": lambda: now[0], "sleep": sleep, "log": logs.append}, calls, sleeps, logs


def _pages() -> list[object]:
    jobs = _jobs()
    return [{"total_count": len(jobs), "jobs": jobs[:100]}, {"total_count": len(jobs), "jobs": jobs[100:]}]


def test_transport_recovery_discards_partial_pagination_and_rechecks_every_shard() -> None:
    pages = _pages()
    options, calls, sleeps, logs = _fixture([pages[0], barrier.TransientApiError("private-error"), *pages])
    barrier.wait_for_shards("owner/repo", _RUN_ID, 2, **options)
    assert [path.rsplit("=", 1)[1] for path in calls] == ["1", "2", "1", "2"]
    assert sleeps == [5]
    assert f"All {barrier.SHARD_COUNT} Python coverage shards succeeded" in logs[-1]
    assert "private-error" not in "\n".join(logs)


def test_persistent_transport_failure_stops_after_three_backoffs() -> None:
    options, calls, sleeps, logs = _fixture([barrier.TransientApiError("private-error") for _ in range(4)])
    with pytest.raises(barrier.ShardWaitError, match="three bounded retries"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, **options)
    assert len(calls) == 4
    assert sleeps == [5, 10, 20]
    assert "private-error" not in "\n".join(logs)


def test_underreported_inventory_restarts_pagination_before_accepting_coverage() -> None:
    options, calls, sleeps, logs = _fixture(
        [
            {"total_count": 0, "jobs": _jobs()[:100]},
            *_pages(),
        ]
    )
    barrier.wait_for_shards("owner/repo", _RUN_ID, 2, **options)
    assert [path.rsplit("=", 1)[1] for path in calls] == ["1", "1", "2"]
    assert sleeps == [5]
    assert f"All {barrier.SHARD_COUNT} Python coverage shards succeeded" in logs[-1]


def test_persistently_underreported_inventory_never_accepts_partial_coverage() -> None:
    options, calls, sleeps, _logs = _fixture([{"total_count": 0, "jobs": _jobs()[:100]} for _ in range(4)])
    with pytest.raises(barrier.ShardWaitError, match="three bounded retries"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, **options)
    assert len(calls) == 4
    assert sleeps == [5, 10, 20]


def test_transport_retry_does_not_extend_the_original_deadline() -> None:
    options, calls, sleeps, _logs = _fixture([barrier.TransientApiError("offline")])
    with pytest.raises(barrier.ShardWaitError, match="Timed out"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, timeout_seconds=2, **options)
    assert len(calls) == 1
    assert sleeps == [2]


def test_pending_snapshots_do_not_reset_the_transport_retry_budget() -> None:
    jobs = _jobs()
    jobs[0].update(status="queued", conclusion=None)
    pages = [{"total_count": len(jobs), "jobs": jobs[:100]}, {"total_count": len(jobs), "jobs": jobs[100:]}]
    events = [event for _ in range(3) for event in [barrier.TransientApiError("offline"), *pages]]
    options, calls, sleeps, _logs = _fixture([*events, barrier.TransientApiError("offline")])
    with pytest.raises(barrier.ShardWaitError, match="three bounded retries"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, **options)
    assert len(calls) == 10
    assert sleeps == [5, 5, 10, 5, 20, 5]


def test_recovery_does_not_accept_inherited_coverage() -> None:
    jobs = _jobs()
    jobs[0]["started_at"] = "2026-09-20T16:55:00Z"
    pages = [{"total_count": len(jobs), "jobs": jobs[:100]}, {"total_count": len(jobs), "jobs": jobs[100:]}]
    options, calls, sleeps, _logs = _fixture([barrier.TransientApiError("offline"), *pages])
    with pytest.raises(barrier.ShardWaitError, match="inherited execution"):
        barrier.wait_for_shards("owner/repo", _RUN_ID, 2, **options)
    assert len(calls) == 2
    assert sleeps == [5]


@pytest.mark.parametrize("code", [401, 403, 404, 422, 408, 429, 500, 502, 503, 504])
def test_http_retry_classification_is_explicit_and_keeps_errors_private(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.HTTPError("https://api.github.com", code, "private-response", HTTPMessage(), None)

    monkeypatch.setenv("GITHUB_TOKEN", "test-read-token")
    monkeypatch.setattr(barrier.urllib.request, "build_opener", lambda *_args: SimpleNamespace(open=fail))
    with pytest.raises(barrier.ShardWaitError) as caught:
        barrier.github_json("/repos/owner/repo/actions/runs/1/attempts/1/jobs", 1)
    expected = barrier.TransientApiError if code in {408, 429, 500, 502, 503, 504} else barrier.ShardWaitError
    assert type(caught.value) is expected
    assert str(caught.value) == f"GitHub jobs API returned HTTP {code}"


@pytest.mark.parametrize("wrapped", [False, True])
def test_tls_failures_are_not_retried(monkeypatch: pytest.MonkeyPatch, wrapped: bool) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        error = ssl.SSLCertVerificationError("private-certificate-error")
        raise urllib.error.URLError(error) if wrapped else error

    monkeypatch.setenv("GITHUB_TOKEN", "test-read-token")
    monkeypatch.setattr(barrier.urllib.request, "build_opener", lambda *_args: SimpleNamespace(open=fail))
    with pytest.raises(barrier.ShardWaitError) as caught:
        barrier.github_json("/repos/owner/repo/actions/runs/1/attempts/1/jobs", 1)
    assert type(caught.value) is barrier.ShardWaitError
    assert str(caught.value) == "GitHub jobs API TLS verification failed"


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("error_type", [TimeoutError, ssl.SSLEOFError, ssl.SSLZeroReturnError, ssl.SSLSyscallError])
def test_transport_timeouts_reach_the_bounded_retry_path(
    monkeypatch: pytest.MonkeyPatch, wrapped: bool, error_type: type[OSError]
) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        error = error_type("private-network-error")
        raise urllib.error.URLError(error) if wrapped else error

    monkeypatch.setenv("GITHUB_TOKEN", "test-read-token")
    monkeypatch.setattr(barrier.urllib.request, "build_opener", lambda *_args: SimpleNamespace(open=fail))
    with pytest.raises(barrier.TransientApiError) as caught:
        barrier.github_json("/repos/owner/repo/actions/runs/1/attempts/1/jobs", 1)
    assert str(caught.value) == "GitHub jobs API request failed"


def test_interrupted_response_read_reaches_the_bounded_retry_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def read(_limit: int) -> bytes:
        raise IncompleteRead(b"private-partial-response", 100)

    response = SimpleNamespace(status=200, read=read)
    monkeypatch.setenv("GITHUB_TOKEN", "test-read-token")
    monkeypatch.setattr(
        barrier.urllib.request,
        "build_opener",
        lambda *_args: SimpleNamespace(open=lambda *_a, **_k: nullcontext(response)),
    )
    with pytest.raises(barrier.TransientApiError, match=r"^GitHub jobs API request failed$"):
        barrier.github_json("/repos/owner/repo/actions/runs/1/attempts/1/jobs", 1)
