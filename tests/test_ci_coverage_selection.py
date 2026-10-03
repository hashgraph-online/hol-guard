from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from scripts.ci import select_pytest_coverage as selection

REPOSITORY = "owner/repo"
RUN = 123456
SHA = "a" * 40
BASE = f"/repos/{REPOSITORY}/actions/runs/{RUN}"


def job(name, number, *, attempt=1):
    return {
        "id": number,
        "name": name,
        "run_id": RUN,
        "run_attempt": attempt,
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-03T12:00:00Z",
        "started_at": "2026-10-03T12:00:10Z",
        "completed_at": "2026-10-03T12:01:00Z",
    }


def fixture():
    old = [job(f"coverage (3.12, {i})", i + 1) for i in range(128)]
    prerequisites = [job("coverage-plan", 1000), job("native-command-evaluators", 1001)]
    for item in prerequisites:
        item["started_at"] = "2026-10-03T11:59:00Z"
        item["created_at"] = "2026-10-03T11:58:00Z"
        item["completed_at"] = "2026-10-03T12:00:00Z"
    old += prerequisites
    current = deepcopy(old)
    for item in current:
        item.update(id=item["id"] + 2000, run_attempt=2, created_at="2026-10-03T13:00:00Z")
    current[51].update(started_at="2026-10-03T13:00:10Z", completed_at="2026-10-03T13:01:00Z")
    artifacts = []
    for i in range(128):
        attempt = 2 if i == 51 else 1
        artifacts.append(
            {
                "id": i + 5000,
                "name": f"pytest-coverage-{attempt}-{i}",
                "expired": False,
                "workflow_run": {"id": RUN, "head_sha": SHA},
                "digest": "sha256:" + "b" * 64,
                "size_in_bytes": 100,
                "created_at": f"2026-10-03T{13 if attempt == 2 else 12}:00:20Z",
            }
        )
    run = {
        "id": RUN,
        "run_attempt": 2,
        "path": ".github/workflows/ci.yml",
        "head_sha": SHA,
        "repository": {"full_name": REPOSITORY},
    }
    return run, current, old, artifacts


def fetcher(data):
    run, current, old, artifacts = data
    calls = []

    def fetch(path, timeout):
        assert 0 < timeout <= 10
        calls.append(path)
        if path == BASE:
            return run
        page = int(path.rsplit("=", 1)[1])
        field = "artifacts" if "/artifacts?" in path else "jobs"
        if field == "artifacts":
            values = artifacts
        elif "/attempts/1/" in path:
            values = old
        else:
            values = current
        return {"total_count": len(values), field: values[(page - 1) * 100 : page * 100]}

    return fetch, calls


def select(data):
    fetch, _ = fetcher(data)
    return selection.select_coverage(REPOSITORY, RUN, 2, fetch=fetch)


def test_partial_retry_selects_127_original_successes_and_the_one_reexecuted_shard():
    data = fixture()
    # A failed first-attempt artifact must not replace the successful retried one.
    stale = deepcopy(data[3][51])
    stale.update(id=9999, name="pytest-coverage-1-51", created_at="2026-10-03T12:00:20Z")
    data[3].append(stale)
    result = select(data)
    assert len(result["shards"]) == 128
    assert sum(s["attempt"] == 1 for s in result["shards"]) == 127
    assert result["shards"][51] == {
        "shard": 51,
        "attempt": 2,
        "job_id": 2052,
        "artifact_id": 5051,
        "name": "pytest-coverage-2-51",
        "digest": "sha256:" + "b" * 64,
    }
    assert result["shards"][127]["job_id"] == 128


@pytest.mark.parametrize(
    "field,value",
    [
        ("conclusion", "failure"),
        ("conclusion", "cancelled"),
        ("conclusion", "skipped"),
        ("status", "in_progress"),
        ("head_sha", "c" * 40),
        ("run_id", 999),
    ],
)
def test_never_falls_back_from_a_newer_bad_result(field, value):
    data = fixture()
    data[1][51][field] = value
    with pytest.raises(ValueError):
        select(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "c" * 40),
        ("run_id", 999),
        ("started_at", "2026-10-03T12:00:11Z"),
        ("completed_at", "2026-10-03T12:00:59Z"),
        ("conclusion", "failure"),
        ("created_at", "2026-10-03T13:00:00Z"),
    ],
)
def test_inherited_result_requires_its_matching_actual_original_execution(field, value):
    data = fixture()
    data[2][127][field] = value
    with pytest.raises(ValueError):
        select(data)


def test_reexecuting_the_plan_invalidates_old_shards():
    data = fixture()
    data[1][-2].update(
        created_at="2026-10-03T12:10:00Z", started_at="2026-10-03T12:10:10Z", completed_at="2026-10-03T12:11:00Z"
    )
    with pytest.raises(ValueError, match="predates"):
        select(data)


def test_reexecuting_native_producer_invalidates_old_shards():
    data = fixture()
    data[1][-1].update(
        created_at="2026-10-03T12:10:00Z", started_at="2026-10-03T12:10:10Z", completed_at="2026-10-03T12:11:00Z"
    )
    with pytest.raises(ValueError, match="predates"):
        select(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("expired", True),
        ("digest", "missing"),
        ("size_in_bytes", 0),
        ("size_in_bytes", True),
        ("size_in_bytes", 100_000_000),
        ("workflow_run", {"id": 999, "head_sha": SHA}),
        ("workflow_run", {"id": RUN, "head_sha": "c" * 40}),
        ("created_at", "2026-10-03T11:00:00Z"),
        ("created_at", "2026-10-03T14:00:00Z"),
    ],
)
def test_rejects_unbound_or_expired_coverage(field, value):
    data = fixture()
    data[3][0][field] = value
    with pytest.raises(ValueError):
        select(data)


def test_missing_or_duplicate_artifacts_are_not_complete():
    data = fixture()
    missing = data[3].pop()
    with pytest.raises(ValueError, match="Missing or ambiguous"):
        select(data)
    data[3].extend([missing, {**missing, "id": 12345}])
    with pytest.raises(ValueError, match="Missing or ambiguous"):
        select(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_attempt", 3),
        ("path", ".github/workflows/other.yml"),
        ("repository", {"full_name": "other/repo"}),
        ("repository", None),
        ("head_sha", "invalid"),
    ],
)
def test_workflow_identity_must_not_change(field, value):
    data = fixture()
    data[0][field] = value
    with pytest.raises(ValueError):
        select(data)


def test_original_failed_shard_is_not_needed_after_a_successful_rerun():
    data = fixture()
    data[2][51]["conclusion"] = "failure"
    assert select(data)["shards"][51]["attempt"] == 2


def test_first_attempt_does_not_fetch_history():
    data = fixture()
    data[0]["run_attempt"] = 1
    data[1][:] = deepcopy(data[2])
    data[3][51].update(name="pytest-coverage-1-51", created_at="2026-10-03T12:00:20Z")
    fetch, calls = fetcher(data)
    result = selection.select_coverage(REPOSITORY, RUN, 1, fetch=fetch)
    assert all(s["attempt"] == 1 for s in result["shards"])
    assert not any("/attempts/2/" in path for path in calls)


def test_download_inventory_requires_every_selected_database(tmp_path):
    result = select(fixture())
    for shard in result["shards"]:
        parent = tmp_path / shard["name"]
        parent.mkdir()
        (parent / ".coverage").write_bytes(b"bounded database")
    selection.verify_downloads(result, tmp_path)
    (tmp_path / result["shards"][-1]["name"] / ".coverage").unlink()
    with pytest.raises(ValueError, match="missing"):
        selection.verify_downloads(result, tmp_path)


def test_workflow_downloads_only_proven_ids_and_checks_files_before_combine():
    root = Path(__file__).resolve().parents[1]
    action = yaml.safe_load((root / ".github/actions/ci-job-sonar/action.yml").read_text())
    steps = action["runs"]["steps"]
    selector = next(step for step in steps if step.get("id") == "coverage-selection")
    download = next(step for step in steps if step.get("name") == "Download pytest coverage data")
    assert "select_pytest_coverage.py" in selector["run"]
    assert not selector.get("continue-on-error")
    assert download["with"]["artifact-ids"] == "${{ steps.coverage-selection.outputs.artifact-ids }}"
    assert "pattern" not in download["with"] and "run-id" not in download["with"]
    prepare = (root / "scripts/ci/prepare_sonar_analysis.sh").read_text()
    assert prepare.index("--verify-downloads") < prepare.index("parallel_coverage_combine.py")
    assert '"${#reports[@]}" -eq 128' in prepare


def test_retry_budget_applies_only_to_read_consistency(monkeypatch):
    calls, delays = [], []

    def pending(*args, **kwargs):
        calls.append(1)
        raise selection._InventoryPendingError("missing")

    monkeypatch.setattr(selection, "select_coverage", pending)
    with pytest.raises(ValueError, match="missing"):
        selection.select_with_retries(REPOSITORY, RUN, 2, sleep=delays.append)
    assert len(calls) == 4
    assert delays == [1.0, 2.0, 4.0]


def test_failed_tests_are_never_retried_by_the_selector(monkeypatch):
    calls = []

    def failed(*args, **kwargs):
        calls.append(1)
        raise ValueError("Coverage producer did not succeed")

    monkeypatch.setattr(selection, "select_coverage", failed)
    with pytest.raises(ValueError, match="did not succeed"):
        selection.select_with_retries(REPOSITORY, RUN, 2, sleep=lambda _: pytest.fail("must not retry"))
    assert calls == [1]


def test_a_new_attempt_during_selection_invalidates_the_snapshot():
    data = fixture()
    fetch, _ = fetcher(data)
    reads = []

    def changing(path, timeout):
        result = fetch(path, timeout)
        if path == BASE:
            reads.append(1)
            if len(reads) > 1:
                return {**result, "run_attempt": 3}
        return result

    with pytest.raises(ValueError, match="changed while selecting"):
        selection.select_coverage(REPOSITORY, RUN, 2, fetch=changing)


def test_cli_publishes_only_the_selected_numeric_artifact_ids(tmp_path, monkeypatch, capsys):
    expected = select(fixture())
    output = tmp_path / "selected.json"
    action_output = tmp_path / "action-output"
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setenv("GITHUB_OUTPUT", str(action_output))
    calls = []

    def wait(repository, run, attempt, **kwargs):
        calls.append((repository, run, attempt))
        assert kwargs["poll_seconds"] == 1

    monkeypatch.setattr(selection.barrier, "wait_for_shards", wait)
    monkeypatch.setattr(selection, "select_with_retries", lambda *args: expected)
    assert selection.main(["--output", str(output)]) == 0
    assert calls == [(REPOSITORY, RUN, 2)]
    assert json.loads(output.read_text()) == expected
    assert (
        action_output.read_text()
        == "artifact-ids=" + ",".join(str(s["artifact_id"]) for s in expected["shards"]) + "\n"
    )
    assert "reused 127" in capsys.readouterr().out


def test_cli_does_not_publish_ids_when_a_producer_is_bad(tmp_path, monkeypatch):
    output = tmp_path / "selected.json"
    action_output = tmp_path / "action-output"
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setenv("GITHUB_OUTPUT", str(action_output))

    def fail(*args, **kwargs):
        raise selection.barrier.ShardWaitError("producer failed")

    monkeypatch.setattr(selection.barrier, "wait_for_shards", fail)
    assert selection.main(["--output", str(output)]) == 1
    assert not output.exists() and not action_output.exists()


def test_extra_downloaded_artifact_cannot_enter_coverage_combine(tmp_path):
    result = select(fixture())
    for shard in result["shards"]:
        parent = tmp_path / shard["name"]
        parent.mkdir()
        (parent / ".coverage").write_bytes(b"database")
    (tmp_path / "pytest-coverage-1-999").mkdir()
    with pytest.raises(ValueError, match="inventory"):
        selection.verify_downloads(result, tmp_path)


@pytest.mark.parametrize("inventory", ["/attempts/2/jobs", "/artifacts"])
def test_decreasing_page_count_retries_the_whole_inventory(inventory):
    fetch, calls = fetcher(fixture())
    truncated, delays = [], []

    def changing(path, timeout):
        result = fetch(path, timeout)
        if inventory + "?" in path and path.endswith("page=2") and not truncated:
            truncated.append(path)
            field = "artifacts" if inventory == "/artifacts" else "jobs"
            return {"total_count": 100, field: []}
        return result

    result = selection.select_with_retries(REPOSITORY, RUN, 2, fetch=changing, sleep=delays.append)
    assert len(result["shards"]) == 128
    assert delays == [1.0]
    assert len(truncated) == 1
    assert calls.count(BASE + inventory + "?per_page=100&page=1") == 2


@pytest.mark.parametrize("name", ["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"])
@pytest.mark.parametrize("value", [None, "", "not-an-integer", "0", "-1"])
def test_cli_identifies_invalid_environment_variable(name, value, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    if value is None:
        monkeypatch.delenv(name)
    else:
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(selection.barrier, "wait_for_shards", lambda *a, **kw: pytest.fail("must not call API"))
    assert selection.main([]) == 1
    assert name in capsys.readouterr().err


@pytest.mark.parametrize("error", [KeyError("programming defect"), TypeError("programming defect")])
def test_cli_does_not_mask_programming_errors(error, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")

    def broken(*args, **kwargs):
        raise error

    monkeypatch.setattr(selection.barrier, "wait_for_shards", broken)
    with pytest.raises(type(error), match="programming defect"):
        selection.main([])
