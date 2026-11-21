"""The in-run PyPI wait tolerates transient states but refuses anything but success."""

from __future__ import annotations

import pytest

from scripts.release.wait_for_run_job import (
    EARLY_INTERVAL_SECONDS,
    EARLY_INTERVAL_UNTIL,
    LATE_INTERVAL_SECONDS,
    MAX_CONSECUTIVE_ERRORS,
    main,
    wait_for_job,
)


class _Clock:
    """Monotonic clock advanced by the injected sleep."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _wait(job_name: str, fetcher, timeout: float = 7200) -> tuple[int, _Clock]:
    clock = _Clock()
    result = wait_for_job(job_name, timeout_seconds=timeout, fetch_jobs=fetcher, sleep=clock.sleep, clock=clock)
    return result, clock


def _job(status: str, conclusion: str | None = None, name: str = "Publish alpha to PyPI") -> dict:
    return {"name": name, "status": status, "conclusion": conclusion}


def test_success_after_pending_polls() -> None:
    responses = iter(
        [
            [_job("in_progress")],
            [_job("queued")],
            [_job("in_progress")],
            [_job("completed", "success")],
        ]
    )
    result, clock = _wait("Publish alpha to PyPI", lambda: next(responses))
    assert result == 0
    assert clock.sleeps == [EARLY_INTERVAL_SECONDS] * 3


def test_missing_job_keeps_polling_then_times_out() -> None:
    result, clock = _wait("Publish alpha to PyPI", lambda: [], timeout=30)
    assert result == 1
    assert all(seconds == EARLY_INTERVAL_SECONDS for seconds in clock.sleeps)


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out"])
def test_failed_conclusions_stop_the_prerelease(conclusion: str) -> None:
    result, _ = _wait("Publish alpha to PyPI", lambda: [_job("completed", conclusion)])
    assert result == 1


def test_ambiguous_job_names_fail() -> None:
    result, _ = _wait("Publish alpha to PyPI", lambda: [_job("in_progress"), _job("in_progress")])
    assert result == 1


def test_poll_interval_grows_after_fifteen_minutes() -> None:
    result, clock = _wait("Publish alpha to PyPI", lambda: [_job("in_progress")], timeout=EARLY_INTERVAL_UNTIL + 130)
    assert result == 1
    early = [s for s in clock.sleeps if s == EARLY_INTERVAL_SECONDS]
    late = [s for s in clock.sleeps if s == LATE_INTERVAL_SECONDS]
    assert early == [EARLY_INTERVAL_SECONDS] * int(EARLY_INTERVAL_UNTIL / EARLY_INTERVAL_SECONDS)
    assert late


def test_transient_fetch_errors_retry_then_fail_closed() -> None:
    calls = {"count": 0}

    def broken() -> list[dict]:
        calls["count"] += 1
        raise RuntimeError("gh api failed")

    result, _ = _wait("Publish alpha to PyPI", broken)
    assert result == 1
    assert calls["count"] == MAX_CONSECUTIVE_ERRORS + 1


def test_fetch_errors_reset_after_a_successful_poll() -> None:
    attempts = {"count": 0}

    def flaky() -> list[dict]:
        attempts["count"] += 1
        if attempts["count"] % 3:
            raise RuntimeError("gh api failed")
        return [_job("completed", "success")]

    result, _ = _wait("Publish alpha to PyPI", flaky)
    assert result == 0


@pytest.mark.parametrize("missing", ["GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"])
def test_missing_run_environment_fails(missing: str, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        monkeypatch.setenv(name, "value")
    monkeypatch.delenv(missing)
    with pytest.raises(SystemExit):
        main(["--job-name", "Publish alpha to PyPI"])
