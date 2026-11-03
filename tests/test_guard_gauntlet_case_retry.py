"""Bounded re-execution of a case the model never properly exercised.

An attempt is a round of the whole catalog, so without a per-case budget one
uncooperative case costs a fresh round of everything — and the next round is as
likely to lose a different case. These tests pin what may be re-run, what may
never be, and that a re-run never quietly replaces the evidence it supersedes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ci.gauntlet import parallel
from ci.gauntlet.case_retry import MAX_CASE_RETRIES, CaseRetries, case_fixture_name, interrupted, retryable
from ci.gauntlet.catalog import Scenario
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.fixtures import digest_file, scenario_fixture_name

from .test_guard_gauntlet import observed_case


def _assessment(outcome: str, **extra: Any) -> dict[str, Any]:
    return {"assessment": {"outcome": outcome, "reason": f"{outcome} happened", **extra}}


def _budget(tmp_path: Path, limit: int = 2) -> CaseRetries:
    return CaseRetries(limit, cases=tmp_path / "cases", superseded=tmp_path / "superseded")


@pytest.mark.parametrize("outcome", ["not-exercised", "inference-error", "harness-error"])
def test_outcomes_that_blame_the_model_or_the_host_earn_a_rerun(outcome: str) -> None:
    # None of these says Guard did anything wrong, so the case has not yet been exercised.
    assert retryable({"outcome": outcome})


@pytest.mark.parametrize("outcome", ["pass", "false-positive", "false-negative", "task-incomplete"])
def test_a_product_outcome_is_never_retried(outcome: str) -> None:
    # Retrying a false positive or false negative is how a real defect becomes a pass.
    assert not retryable({"outcome": outcome})


def test_a_case_that_interrupted_ordinary_work_is_never_retried() -> None:
    # An intermittent approval request cannot be retried away; it is the defect.
    stopped = {"benign": True, "events": [{"kind": "approval"}]}
    assert interrupted({"interruptions": stopped})
    assert not retryable({"outcome": "not-exercised", "interruptions": stopped})
    # A protection case's deny is expected and is not benign work being stopped.
    assert not interrupted({"interruptions": {"benign": False, "events": [{"kind": "decision"}]}})
    assert retryable({"outcome": "not-exercised", "interruptions": {"benign": True, "events": []}})


def test_the_budget_is_per_case_not_per_run(tmp_path: Path) -> None:
    budget = _budget(tmp_path, limit=1)
    assert budget.should_retry("a", _assessment("not-exercised"))
    assert not budget.should_retry("a", _assessment("not-exercised"))
    # A second uncooperative case has its own budget; it does not inherit the first's.
    assert budget.should_retry("b", _assessment("inference-error"))


def test_a_zero_budget_retries_nothing(tmp_path: Path) -> None:
    assert not _budget(tmp_path, limit=0).should_retry("a", _assessment("not-exercised"))


def test_a_negative_budget_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        _budget(tmp_path, limit=-1)


def test_attempt_numbers_count_from_one_and_name_their_own_fixture(tmp_path: Path) -> None:
    budget = _budget(tmp_path)
    assert budget.attempt("a") == 1
    budget.should_retry("a", _assessment("not-exercised"))
    assert budget.attempt("a") == 2
    first = case_fixture_name("secret-file-read", 1)
    assert first == scenario_fixture_name("secret-file-read")
    # `create_fixture` refuses an existing directory, so a re-run cannot reuse the name.
    assert case_fixture_name("secret-file-read", 2) == f"{first}r2"
    assert len({case_fixture_name("secret-file-read", n) for n in (1, 2, 3)}) == 3


def test_a_superseded_attempt_keeps_its_evidence(tmp_path: Path) -> None:
    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "a.json").write_text('{"attempt": 1}')
    budget = _budget(tmp_path)
    assert budget.should_retry("a", _assessment("not-exercised"))
    # The published name is free for the next run; the first run is still readable.
    assert not (cases / "a.json").exists()
    kept = tmp_path / "superseded" / "a.attempt-1.json"
    assert json.loads(kept.read_text()) == {"attempt": 1}
    assert budget.history == [
        {
            "id": "a",
            "attempt": 1,
            "outcome": "not-exercised",
            "reason": "not-exercised happened",
            "evidence": "a.attempt-1.json",
            "evidence_sha256": digest_file(kept),
        }
    ]


def test_a_cancelled_retry_gives_the_banked_attempt_back(tmp_path: Path) -> None:
    # The re-run never happened, so the attempt it displaced is this case's only run.
    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "a.json").write_text('{"attempt": 1}')
    budget = _budget(tmp_path)
    assert budget.should_retry("a", _assessment("not-exercised"))
    budget.restore("a")
    assert json.loads((cases / "a.json").read_text()) == {"attempt": 1}
    assert not (tmp_path / "superseded" / "a.attempt-1.json").exists()
    assert budget.history == []
    # The budget is given back too, so a later honest retry still has it.
    assert budget.attempt("a") == 1
    assert budget.should_retry("a", _assessment("not-exercised"))


def test_restoring_a_case_that_never_retried_does_nothing(tmp_path: Path) -> None:
    budget = _budget(tmp_path)
    budget.restore("a")
    assert budget.history == [] and budget.attempt("a") == 1


def test_history_is_empty_when_nothing_was_rerun(tmp_path: Path) -> None:
    budget = _budget(tmp_path)
    assert not budget.should_retry("a", _assessment("pass"))
    assert budget.history == []
    assert not (tmp_path / "superseded").exists()


class _Worker:
    """A worker that yields the next queued result for its item."""

    def __init__(self, results: list[Any]) -> None:
        self._results = results

    def poll(self) -> int | None:
        return 0

    def collect(self) -> Any:
        return self._results.pop(0)

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


def _no_sleep(_seconds: float) -> None:
    return None


def test_the_scheduler_requeues_a_retried_item_and_records_only_its_last_run() -> None:
    queued = {"a": ["a1", "a2"], "b": ["b1"]}
    spawned: list[str] = []
    recorded: list[tuple[int, Any]] = []

    def spawn(name: str) -> _Worker:
        spawned.append(name)
        return _Worker(queued[name])

    results = parallel.run_scheduled(
        ["a", "b"],
        jobs=1,
        spawn=spawn,
        on_complete=lambda index, result: recorded.append((index, result)),
        retry=lambda _index, result: result == "a1",
        sleep=_no_sleep,
    )
    assert spawned == ["a", "b", "a"]
    # The discarded run is not recorded at all, so nothing counts it as a result.
    assert recorded == [(1, "b1"), (0, "a2")]
    assert results == ["a2", "b1"]


def test_a_cancelled_requeue_publishes_the_run_the_item_already_made() -> None:
    # `a` is queued again, then `b` stops the run in the same completion batch. The
    # re-run will never happen, so dropping `a1` would erase a case that did run.
    queued = {"a": ["a1", "a2"], "b": ["stop"]}
    spawned: list[str] = []
    cancelled: list[tuple[int, str]] = []

    results = parallel.run_scheduled(
        ["a", "b"],
        jobs=2,
        spawn=lambda name: (spawned.append(name), _Worker(queued[name]))[1],
        should_stop=lambda _index, result: result == "stop",
        retry=lambda _index, result: result == "a1",
        cancel_retry=lambda index, result: cancelled.append((index, result)),
        sleep=_no_sleep,
    )
    assert spawned == ["a", "b"]
    assert cancelled == [(0, "a1")]
    assert results == ["a1", "stop"]


def _run_argv(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "run",
        "--expected-source-sha",
        "a" * 40,
        "--output",
        str(tmp_path / "evidence"),
        "--provider-url",
        "https://provider.invalid/v1",
        "--model",
        "unit-transport-only",
        "--provider-identity",
        "unit-transport-only",
        *extra,
    ]


@pytest.fixture
def _key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_GAUNTLET_API_KEY", "test-only-key")


@pytest.mark.parametrize("value", ["-1", "6"])
def test_the_cli_refuses_a_budget_outside_its_bounds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], _key: None, value: str
) -> None:
    from ci.gauntlet import __main__ as cli
    from ci.gauntlet.case_retry import MAX_CASE_RETRIES

    assert cli.main(_run_argv(tmp_path, "--case-retries", value)) != 0
    assert f"--case-retries must be an integer from 0 to {MAX_CASE_RETRIES}" in capsys.readouterr().err
    # A rejected budget is refused before anything is built.
    assert not (tmp_path / "evidence").exists()


def test_the_budget_belongs_to_the_core_profile(tmp_path: Path, capsys: pytest.CaptureFixture[str], _key: None) -> None:
    from ci.gauntlet import __main__ as cli

    argv = _run_argv(tmp_path, "--case-retries", "2", "--profile", "full-tasks")
    assert cli.main(argv) != 0
    assert "--case-retries is only supported by the core profile" in capsys.readouterr().err


def _capture_suite(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stand in for the suite so the CLI's own wiring is what the test observes."""
    from ci.gauntlet import runner

    seen: dict[str, Any] = {}

    def fake_run_suite(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"pass": True, "cases": [], "outcomes": {}, "merge_qualified": False}

    monkeypatch.setattr(runner, "run_suite", fake_run_suite)
    return seen


def test_the_cli_hands_the_budget_to_the_suite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _key: None) -> None:
    from ci.gauntlet import __main__ as cli

    seen = _capture_suite(monkeypatch)
    assert cli.main(_run_argv(tmp_path, "--case-retries", "3")) == 0
    assert seen["case_retries"] == 3


def test_the_budget_defaults_to_off_for_an_ordinary_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _key: None
) -> None:
    # A targeted exploratory run should show what happened, not quietly re-run it.
    from ci.gauntlet import __main__ as cli

    seen = _capture_suite(monkeypatch)
    assert cli.main(_run_argv(tmp_path)) == 0
    assert seen["case_retries"] == 0


def _retry_suite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    jobs: int,
    *,
    route_health: Any = None,
    expected_attempts: list[int] | None = None,
) -> dict[str, Any]:
    """Run one case that refuses once and complies on its re-run, over either scheduler."""
    from ci.gauntlet import parallel as scheduler
    from ci.gauntlet import runner
    from ci.gauntlet.catalog import load_catalog

    from .test_guard_gauntlet_parallel import _fake_environment, _fake_result, _no_sleep

    _fake_environment(monkeypatch)
    case_id = load_catalog()[0].id
    attempts: list[int] = []

    def result(public: Path, attempt: int) -> dict[str, Any]:
        case = _fake_result(case_id, public)
        if attempt == 1:
            case["assessment"] = {
                "outcome": "not-exercised",
                "reason": "the model made no tool attempt",
                "tool_calls": 0,
            }
        return case

    def fake_run_case(scenario: Any, *, public: Path, attempt: int = 1, **_kw: Any) -> dict[str, Any]:
        attempts.append(attempt)
        return result(public, attempt)

    class Handle:
        def __init__(self, scenario_id: str, spec: dict[str, Any], _workdir: Path, **_kw: Any):
            attempts.append(int(spec["attempt"]))
            self.result = result(Path(spec["public"]), int(spec["attempt"]))

        def poll(self) -> int | None:
            return 0

        def collect(self) -> dict[str, Any]:
            return self.result

        def terminate(self) -> None: ...

        def kill(self) -> None: ...

    monkeypatch.setattr(runner, "run_case", fake_run_case)
    monkeypatch.setattr(runner, "SubprocessCaseWorker", Handle)
    monkeypatch.setattr(runner, "stale_gaps", lambda _report: [])
    monkeypatch.setattr(scheduler.time, "sleep", _no_sleep)
    report = runner.run_suite(
        expected_source_sha="a" * 40,
        output=tmp_path / f"evidence-{jobs}",
        provider={},
        work_root=tmp_path / f"work-{jobs}",
        selected_ids=[case_id],
        jobs=jobs,
        case_retries=2,
        route_health=route_health,
    )
    assert attempts == (expected_attempts if expected_attempts is not None else [1, 2])
    return report


@pytest.mark.parametrize("jobs", [1, 4])
def test_a_rerun_case_is_recorded_once_with_its_superseded_attempt_kept(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, jobs: int
) -> None:
    report = _retry_suite(monkeypatch, tmp_path, jobs)
    assert report["case_retries_allowed"] == 2
    # One row, holding the run that actually exercised the case.
    assert [(row["id"], row["outcome"]) for row in report["cases"]] == [(report["case_retries"][0]["id"], "pass")]
    assert report["case_coverage"]["unexecuted_cases"] == []
    history = report["case_retries"]
    assert len(history) == 1
    assert history[0]["attempt"] == 1 and history[0]["outcome"] == "not-exercised"
    kept = tmp_path / f"evidence-{jobs}" / "superseded" / history[0]["evidence"]
    # The discarded attempt is still on disk; a pass that took two tries cannot read as one.
    assert kept.is_file() and json.loads(kept.read_text())


@pytest.mark.parametrize("jobs", [1, 4])
def test_a_dead_route_stops_the_run_instead_of_spending_a_budget_against_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, jobs: int
) -> None:
    # A dead route makes every case look retryable. Re-running against it buys no
    # coverage and burns the budget the next live run would need.
    report = _retry_suite(
        monkeypatch,
        tmp_path,
        jobs,
        route_health=lambda: "adapter exited 1: route is gone",
        expected_attempts=[1],
    )
    assert report["provider_route_failure"] == "adapter exited 1: route is gone"
    assert report["case_retries"] == []
    # The one run it made is published, not discarded into `superseded/`.
    assert [row["outcome"] for row in report["cases"]] == ["not-exercised"]
    assert not (tmp_path / f"evidence-{jobs}" / "superseded").exists()


def test_a_superseded_attempt_can_be_exported(tmp_path: Path) -> None:
    from ci.gauntlet.bundle import allowed_name, pack

    assert allowed_name("superseded/secret-file-read.attempt-1.json")
    assert not allowed_name("superseded/secret-file-read.attempt-0.json")
    assert not allowed_name("superseded/secret-file-read.json")
    assert not allowed_name("superseded/../cases/a.json")
    evidence = tmp_path / "evidence"
    (evidence / "cases").mkdir(parents=True)
    (evidence / "superseded").mkdir()
    (evidence / "summary.json").write_text("{}")
    (evidence / "cases" / "a.json").write_text("{}")
    (evidence / "superseded" / "a.attempt-1.json").write_text("{}")
    # Without the superseded entry in the allowlist a retried run cannot be submitted.
    assert pack(evidence, tmp_path / "evidence.zip")


def test_a_superseded_attempt_still_counts_towards_what_the_run_cost(tmp_path: Path) -> None:
    from ci.gauntlet.summary import inference_usage

    cases = tmp_path / "cases"
    superseded = tmp_path / "superseded"
    cases.mkdir()
    superseded.mkdir()

    def _case(path: Path, tokens: int) -> None:
        path.write_text(json.dumps({"inference": {"live_rounds": [{"usage": {"total_tokens": tokens}}]}}))

    _case(cases / "a.json", 30)
    _case(superseded / "a.attempt-1.json", 12)
    usage = inference_usage(cases, ["a"], superseded=superseded)
    # The refused round was billed, so leaving it out understates the run.
    assert usage["rounds"] == 2 and usage["rounds_with_usage"] == 2 and usage["total_tokens"] == 42
    assert inference_usage(cases, ["a"])["total_tokens"] == 30


def _rewrite(kept: Path, report: dict[str, Any], changes: dict[str, Any]) -> None:
    """Edit a banked attempt and re-declare its digest, as a dishonest runner would."""
    kept.write_text(json.dumps({**json.loads(kept.read_text()), **changes}))
    report["case_retries"][0]["evidence_sha256"] = digest_file(kept)


BANKED = Scenario("a", "allow", "commands", "Use the tool", ("echo fixture",))


def _banked(case: dict[str, Any]) -> dict[str, Any]:
    """Name the case this evidence belongs to, as the runner writes it."""
    return {**case, "id": BANKED.id, "expectation": BANKED.expectation}


def _declined() -> dict[str, Any]:
    """A case the model never exercised: no call, no Guard observation, nothing to judge."""
    case = _banked(observed_case())
    case["events"] = [
        {"type": "model_turn", "calls": [], "stop_reason": "stop"},
        {"type": "agent_end", "terminal": True},
    ]
    case["guard_observations"] = []
    case["native_routes"] = {}
    case["assessment"] = assess_case(BANKED, case)
    assert case["assessment"]["outcome"] == "not-exercised"
    return case


def _history(tmp_path: Path, case: dict[str, Any] | None = None) -> tuple[dict[str, Any], Path]:
    kept = tmp_path / "superseded" / "a.attempt-1.json"
    kept.parent.mkdir(parents=True, exist_ok=True)
    case = case if case is not None else _declined()
    kept.write_text(json.dumps(case))
    report = {
        "case_retries": [
            {
                "id": "a",
                "attempt": 1,
                "outcome": case["assessment"]["outcome"],
                "reason": case["assessment"]["reason"],
                "evidence": kept.name,
                "evidence_sha256": digest_file(kept),
            },
        ]
    }
    return report, kept


def test_the_verifier_accepts_a_declared_superseded_attempt(tmp_path: Path) -> None:
    from ci.gauntlet.verify import _reconcile_case_retries

    report, _kept = _history(tmp_path)
    _reconcile_case_retries(report, tmp_path, [BANKED])
    _reconcile_case_retries({}, tmp_path, [BANKED])


def test_the_verifier_rejects_a_banked_attempt_that_was_never_eligible(tmp_path: Path) -> None:
    """A runner that buried a product failure behind a re-run is judged here, not trusted.

    The runner that granted the re-run is candidate code; if a regression lets it
    retry a false negative until it passes, only this side can catch it.
    """
    from ci.gauntlet.verify import _reconcile_case_retries

    passed = _banked(observed_case())
    passed["assessment"] = assess_case(BANKED, passed)
    assert passed["assessment"]["outcome"] == "pass"
    report, _kept = _history(tmp_path, passed)
    with pytest.raises(ValueError, match="never eligible"):
        _reconcile_case_retries(report, tmp_path, [BANKED])


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda report, kept: kept.unlink(), "missing or changed"),
        (lambda report, kept: kept.write_text('{"attempt": 2}'), "missing or changed"),
        (lambda report, kept: report["case_retries"][0].update(id="elsewhere"), "outside this profile"),
        (lambda report, kept: report["case_retries"][0].update(evidence="../cases/a.json"), "does not name"),
        (lambda report, kept: report["case_retries"][0].update(evidence=None), "does not name"),
        (lambda report, kept: report["case_retries"][0].update(attempt=2), "another case's evidence"),
        (lambda report, kept: _rewrite(kept, report, {"id": "elsewhere"}), "another case's evidence"),
        (lambda report, kept: _rewrite(kept, report, {"expectation": "block"}), "another case's evidence"),
        (lambda report, kept: _rewrite(kept, report, {"assessment": {"outcome": "pass"}}), "does not match"),
        (lambda report, kept: report["case_retries"][0].update(outcome="harness-error"), "declared outcome"),
        (lambda report, kept: report["case_retries"][0].update(reason="host crashed"), "declared outcome"),
        (lambda report, kept: report["case_retries"][0].pop("outcome"), "declared outcome"),
    ],
)
def test_the_verifier_rejects_a_superseded_attempt_it_cannot_reconcile(
    tmp_path: Path, mutate: Any, message: str
) -> None:
    from ci.gauntlet.verify import _reconcile_case_retries

    report, kept = _history(tmp_path)
    mutate(report, kept)
    with pytest.raises(ValueError, match=message):
        _reconcile_case_retries(report, tmp_path, [BANKED])


@pytest.mark.parametrize("value", [-1, MAX_CASE_RETRIES + 1])
def test_qualification_rejects_an_out_of_range_budget_before_it_builds_anything(tmp_path: Path, value: int) -> None:
    # The child `run` rejects it too, but only after wheel resolution, SDK setup and
    # worktree creation, leaving qualification to report a missing summary.
    from ci.gauntlet import qualify

    from .test_guard_gauntlet_qualify import _args

    with pytest.raises(ValueError, match="--case-retries must be an integer from 0"):
        qualify.main(_args(tmp_path, case_retries=value))


def test_a_qualification_attempt_record_shows_what_it_re_ran() -> None:
    # Without this a qualified attempt reads the same whether its cases complied
    # on the first try or on the third.
    from ci.gauntlet import qualify

    history = [{"id": "a", "attempt": 1, "outcome": "not-exercised", "reason": "no tool attempt"}]
    record = qualify.summarize_attempt(
        1,
        Path("evidence"),
        0,
        1.0,
        {"cases": [], "case_retries": history, "case_retries_allowed": 2},
    )
    assert record["case_retries"] == history and record["case_retries_allowed"] == 2
    assert qualify.summarize_attempt(1, Path("evidence"), 0, 1.0, {"cases": []})["case_retries"] == []
