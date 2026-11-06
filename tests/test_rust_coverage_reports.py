"""Keep partitioned coverage complete, source-bound and lossless when merged."""

from __future__ import annotations

import copy
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci import rust_coverage_reports as reports

SOURCE = "a" * 40
RUN_ID = 7


def _api_fixture(attempt=1):
    run = {
        "id": RUN_ID,
        "run_attempt": attempt,
        "head_sha": SOURCE,
        "path": ".github/workflows/ci.yml",
        "repository": {"full_name": "example/repo"},
    }
    jobs = [
        {
            "id": 10 + index,
            "name": f"Rust coverage ({partition})",
            "run_id": RUN_ID,
            "run_attempt": attempt,
            "head_sha": SOURCE,
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-01-01T00:00:00Z" if attempt == 1 else "2026-01-01T00:00:04Z",
            "started_at": "2026-01-01T00:00:01Z",
            "completed_at": "2026-01-01T00:00:03Z",
        }
        for index, partition in enumerate(reports.PARTITIONS)
    ]
    artifacts = [
        {
            "id": 20 + index,
            "name": f"rust-coverage-1-{partition}",
            "expired": False,
            "workflow_run": {"id": RUN_ID, "head_sha": SOURCE},
            "digest": "sha256:" + "b" * 64,
            "size_in_bytes": 128,
            "created_at": "2026-01-01T00:00:02Z",
        }
        for index, partition in enumerate(reports.PARTITIONS)
    ]

    def fetch(path, timeout):
        if "/jobs?" in path:
            selected = copy.deepcopy(jobs)
            if "/attempts/1/" in path:
                for job in selected:
                    job.update(run_attempt=1, created_at="2026-01-01T00:00:00Z")
            return {"total_count": len(selected), "jobs": selected}
        if "/artifacts?" in path:
            return {"total_count": len(artifacts), "artifacts": artifacts}
        assert path.endswith(f"/runs/{RUN_ID}")
        return run

    return run, jobs, artifacts, fetch


@pytest.mark.parametrize("attempt", [1, 2])
def test_selection_binds_every_current_or_proven_inherited_execution(attempt):
    _, _, _, fetch = _api_fixture(attempt)
    result = reports.select("example/repo", RUN_ID, attempt, fetch=fetch)
    assert result["source_sha"] == SOURCE
    assert [part["partition"] for part in result["partitions"]] == list(reports.PARTITIONS)
    assert [part["attempt"] for part in result["partitions"]] == [1] * len(reports.PARTITIONS)
    assert [part["artifact_id"] for part in result["partitions"]] == list(range(20, 20 + len(reports.PARTITIONS)))


def test_selector_only_retries_transient_inventory_not_tests():
    _, _, _, fetch = _api_fixture()
    calls = []
    sleeps = []

    def eventual(path, timeout):
        calls.append(path)
        if len(calls) == 1:
            raise reports.api.TransientApiError("temporary failure")
        return fetch(path, timeout)

    result = reports.select_with_retries("example/repo", RUN_ID, 1, fetch=eventual, sleep=sleeps.append)
    assert len(result["partitions"]) == len(reports.PARTITIONS)
    assert sleeps == [1]


@pytest.mark.parametrize("partition", reports.PARTITIONS)
def test_failed_latest_producer_is_not_retried_or_replaced_by_earlier_success(partition):
    _, jobs, _, fetch = _api_fixture(2)
    next(job for job in jobs if job["name"] == f"Rust coverage ({partition})")["conclusion"] = "failure"
    with pytest.raises(ValueError, match="did not succeed"):
        reports.select_with_retries(
            "example/repo", RUN_ID, 2, fetch=fetch, sleep=lambda _: pytest.fail("Failed tests were retried")
        )


def test_workflow_and_report_selector_require_both_runtime_halves():
    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text())
    matrix = workflow["jobs"]["sonar-rust-coverage"]["strategy"]["matrix"]["partition"]
    assert tuple(matrix) == reports.PARTITIONS == ("core", "command", "runtime-1", "runtime-2")


@pytest.mark.parametrize(
    "invalid",
    [
        "failure",
        "missing-job",
        "duplicate-job",
        "wrong-source",
        "missing-artifact",
        "duplicate-artifact",
        "expired",
        "wrong-run",
        "old-upload",
        "missing-digest",
    ],
)
def test_failed_missing_or_unbound_producers_cannot_qualify(invalid):
    run, jobs, artifacts, fetch = _api_fixture(2)
    if invalid == "failure":
        jobs[0]["conclusion"] = "failure"
    elif invalid == "missing-job":
        jobs.pop()
    elif invalid == "duplicate-job":
        jobs.append({**jobs[0], "id": 99})
    elif invalid == "wrong-source":
        run["head_sha"] = "c" * 40
    elif invalid == "missing-artifact":
        artifacts.pop()
    elif invalid == "duplicate-artifact":
        artifacts.append({**artifacts[0], "id": 99})
    elif invalid == "expired":
        artifacts[0]["expired"] = True
    elif invalid == "wrong-run":
        artifacts[0]["workflow_run"]["id"] = 8
    elif invalid == "old-upload":
        artifacts[0]["created_at"] = "2025-12-31T23:00:00Z"
    else:
        artifacts[0].pop("digest")
    with pytest.raises(ValueError):
        reports.select("example/repo", RUN_ID, 2, fetch=fetch)


def _trace(source: Path, count: int) -> str:
    return (
        f"TN:\nSF:{source}\nFN:1,f\nFNDA:{count},f\nFNF:1\nFNH:1\n"
        f"DA:1,{count}\nLF:1\nLH:1\nBRDA:1,0,0,{count}\nBRF:1\nBRH:1\nend_of_record\n"
    )


@pytest.fixture
def downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "identity", lambda: {"schema": reports.SCHEMA, "source_sha": SOURCE, "run_id": RUN_ID})
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    directory = tmp_path / "downloads"
    directory.mkdir()
    source = tmp_path / "lib.rs"
    source.write_text("fn f() {}\n")
    _, _, _, fetch = _api_fixture()
    selection = reports.select("example/repo", RUN_ID, 1, fetch=fetch)
    for index, part in enumerate(selection["partitions"], start=1):
        parent = directory / part["name"]
        parent.mkdir()
        (parent / reports.REPORT).write_text(_trace(source, index))
        reports.bind(part["partition"], parent)
    return selection, directory, tmp_path / "output.info"


@pytest.mark.parametrize("invalid", ["missing", "extra", "stale-source", "bad-hash", "empty", "linked", "duplicate"])
def test_merge_rejects_incomplete_tampered_or_stale_reports(downloads, invalid, monkeypatch):
    selection, directory, output = downloads
    part = selection["partitions"][0]
    parent = directory / part["name"]
    report = parent / reports.REPORT
    if invalid == "missing":
        report.unlink()
    elif invalid == "extra":
        (directory / "unselected").mkdir()
    elif invalid == "stale-source":
        selection["source_sha"] = "c" * 40
    elif invalid == "bad-hash":
        report.write_text(report.read_text().replace("DA:1,1", "DA:1,9"))
    elif invalid == "empty":
        report.write_text("")
    elif invalid == "linked":
        target = directory / "linked.info"
        report.rename(target)
        report.symlink_to(target)
    else:
        selection["partitions"][1] = copy.deepcopy(part)
    monkeypatch.setattr(reports.subprocess, "run", lambda *_a, **_kw: pytest.fail("Unverified coverage reached LCOV"))
    with pytest.raises(ValueError):
        reports.merge(selection, directory, output)


def test_merge_preserves_standard_lcov_branch_processing_and_propagates_failure(downloads, monkeypatch):
    selection, directory, output = downloads
    output.write_text("stale report\n")

    def fail(arguments, *, check):
        assert arguments[0:2] == ["lcov", "--branch-coverage"]
        assert arguments.count("--add-tracefile") == len(reports.PARTITIONS)
        assert check is True
        assert not output.exists()
        raise subprocess.CalledProcessError(3, arguments)

    monkeypatch.setattr(reports.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        reports.merge(selection, directory, output)


@pytest.mark.skipif(shutil.which("lcov") is None, reason="Executed by the Sonar merge step after provisioning LCOV")
def test_real_lcov_merges_line_function_and_branch_counters_losslessly(downloads):
    selection, directory, output = downloads
    reports.merge(selection, directory, output)
    lines = set(output.read_text().splitlines())
    total = sum(range(1, len(reports.PARTITIONS) + 1))
    assert {
        f"DA:1,{total}",
        f"FNDA:{total},f",
        f"BRDA:1,0,0,{total}",
        "LF:1",
        "LH:1",
        "FNF:1",
        "FNH:1",
        "BRF:1",
        "BRH:1",
    } <= lines
