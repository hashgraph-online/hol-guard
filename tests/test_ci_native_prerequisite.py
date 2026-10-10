"""Keep coverage failures tied to both jobs that create the shard matrix."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.ci import wait_for_pytest_shards as barrier
from tests.support.ci_workflow import expand_ci_job_actions
from tests.test_ci_wait_for_pytest_shards import _RUN_ID, _job, _jobs, _run

ROOT = Path(__file__).resolve().parents[1]


def test_barrier_tracks_every_coverage_prerequisite() -> None:
    """Keep the barrier prerequisite names aligned with the coverage dependency graph."""
    jobs = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text()))["jobs"]
    assert set(barrier._PREREQUISITE_LABELS) == set(jobs["coverage"]["needs"])


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out"])
@pytest.mark.parametrize("prerequisite", ["coverage-plan", "native-command-evaluators"])
@pytest.mark.parametrize("placeholder_position", ["none", "before", "after", "previous-page"])
def test_failed_prerequisite_stops_without_waiting_for_an_unexpanded_matrix(
    conclusion: str, prerequisite: str, placeholder_position: str
) -> None:
    """Report a failed prerequisite regardless of matrix placeholder pagination order."""
    failed = dict(_job(1000), name=prerequisite, conclusion=conclusion)
    placeholder = dict(_job(1001), name="coverage (3.12, ${{ matrix.shard-index }})", conclusion="skipped")
    jobs = [failed]
    if placeholder_position == "before":
        jobs = [placeholder, failed]
    elif placeholder_position == "after":
        jobs = [failed, placeholder]
    elif placeholder_position == "previous-page":
        jobs = [placeholder, *[dict(_job(2000 + i), name=f"other-{i}") for i in range(99)], failed]
    calls: list[str] = []

    def fetch(path: str, _timeout: float) -> object:
        """Return a deterministic API page without using a network connection."""
        calls.append(path)
        page = int(path.rsplit("=", 1)[1])
        return {"total_count": len(jobs), "jobs": jobs[(page - 1) * 100 : page * 100]}

    label = "Python coverage-plan" if prerequisite == "coverage-plan" else "Native command evaluators"
    with pytest.raises(barrier.ShardWaitError, match=f"^{label} completed with {conclusion}$"):
        barrier.wait_for_shards(
            "owner/repo",
            _RUN_ID,
            2,
            fetch_json=fetch,
            clock=lambda: 0.0,
            sleep=lambda _delay: pytest.fail("A failed prerequisite must not be polled again"),
            log=lambda _message: None,
        )
    assert len(calls) == (2 if placeholder_position == "previous-page" else 1)


@pytest.mark.parametrize("status", ["queued", "in_progress"])
def test_pending_native_build_waits_for_complete_successful_coverage(status: str) -> None:
    """Keep polling pending builds until every expected coverage producer succeeds."""
    pending = dict(_job(1000), name="native-command-evaluators", status=status, conclusion=None)
    complete = dict(pending, status="completed", conclusion="success")
    calls, logs = _run([[pending], [complete, *_jobs()]])
    # Page count scales with CI_PYTEST_COVERAGE_SHARDS; require completion.
    assert len(calls) >= 3
    assert logs[-1].startswith(f"All {barrier.SHARD_COUNT} Python coverage shards succeeded")


def test_successful_native_build_cannot_replace_a_missing_shard() -> None:
    """A successful prerequisite never substitutes for a missing coverage result."""
    native = dict(_job(1000), name="native-command-evaluators")
    with pytest.raises(barrier.ShardWaitError, match="Timed out"):
        _run([[native, *_jobs()[:-1]]], timeout_seconds=10)


def test_unrelated_failed_job_does_not_supply_or_invalidate_coverage() -> None:
    """Ignore failures outside the coverage producer dependency chain."""
    other = dict(_job(1000), name="unrelated-job", conclusion="failure")
    _, logs = _run([[other, *_jobs()]])
    assert logs[-1].startswith(f"All {barrier.SHARD_COUNT} Python coverage shards succeeded")


def test_duplicate_native_build_is_rejected() -> None:
    """Reject ambiguous duplicate native prerequisite records."""
    native = dict(_job(1000), name="native-command-evaluators")
    duplicate = dict(native, id=9999)
    with pytest.raises(barrier.ShardWaitError, match="duplicate native-command-evaluators jobs"):
        _run([[native, duplicate, *_jobs()]])


@pytest.mark.parametrize("field,value", [("run_id", _RUN_ID + 1), ("run_attempt", 1)])
def test_native_build_from_another_execution_is_rejected(field: str, value: int) -> None:
    """Reject prerequisite records from another run or attempt."""
    native = dict(_job(1000), name="native-command-evaluators", **{field: value})
    with pytest.raises(barrier.ShardWaitError, match=r"another (run|attempt)"):
        _run([[native, *_jobs()]])


@pytest.mark.parametrize("prerequisite", ["coverage-plan", "both"])
@pytest.mark.parametrize("position", ["before", "after", "previous-page"])
def test_deferred_matrix_classification_uses_the_complete_snapshot(prerequisite: str, position: str) -> None:
    """Prerequisite ordering cannot turn the same invalid matrix into a retry."""
    names = list(barrier._PREREQUISITE_LABELS) if prerequisite == "both" else [prerequisite]
    dependencies = [dict(_job(1000 + i), name=name) for i, name in enumerate(names)]
    placeholder = dict(_job(1100), name="coverage (3.12, ${{ matrix.shard-index }})", conclusion="skipped")
    jobs = [*dependencies, placeholder]
    if position == "after":
        jobs = [placeholder, *dependencies]
    elif position == "previous-page":
        jobs = [placeholder, *[dict(_job(2000 + i), name=f"other-{i}") for i in range(99)], *dependencies]
    calls: list[str] = []

    def fetch(path: str, _timeout: float) -> object:
        """Return the fixed inventory in the requested API order."""
        calls.append(path)
        page = int(path.rsplit("=", 1)[1])
        return {"total_count": len(jobs), "jobs": jobs[(page - 1) * 100 : page * 100]}

    with pytest.raises(barrier.ShardWaitError, match="invalid Python coverage shard index") as caught:
        barrier.wait_for_shards(
            "owner/repo",
            _RUN_ID,
            2,
            fetch_json=fetch,
            clock=lambda: 0.0,
            sleep=lambda _delay: pytest.fail("Final prerequisite state must determine classification"),
            log=lambda _message: None,
        )
    assert type(caught.value) is barrier.ShardWaitError
    assert len(calls) == (2 if position == "previous-page" else 1)


@pytest.mark.parametrize("status", ["queued", "in_progress", "completed"])
@pytest.mark.parametrize("position", ["before", "after", "previous-page"])
def test_native_prerequisite_alone_does_not_require_an_expanded_coverage_matrix(status: str, position: str) -> None:
    """Native work can be visible before planning has expanded the coverage matrix."""
    native = dict(
        _job(1000),
        name="native-command-evaluators",
        status=status,
        conclusion="success" if status == "completed" else None,
    )
    placeholder = dict(_job(1100), name="coverage (3.12, ${{ matrix.shard-index }})", conclusion=None, status="queued")
    early = [native, placeholder]
    if position == "after":
        early = [placeholder, native]
    elif position == "previous-page":
        early = [placeholder, *[dict(_job(2000 + i), name=f"other-{i}") for i in range(99)], native]
    complete_native = dict(native, status="completed", conclusion="success")
    complete_plan = dict(_job(1200), name="coverage-plan")
    calls, logs = _run([early, [complete_native, complete_plan, *_jobs()]])
    # The barrier paginates the jobs API in 100-job pages; the exact call count
    # scales with CI_PYTEST_COVERAGE_SHARDS, so only require that it completed.
    assert len(calls) >= 3
    assert logs[-1].startswith(f"All {barrier.SHARD_COUNT} Python coverage shards succeeded")

