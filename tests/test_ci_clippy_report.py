"""Current-attempt and checkout integrity boundaries for imported Clippy reports."""

import json

import pytest

from scripts.ci import clippy_report as report


def inventory():
    run = {
        "id": 12,
        "run_attempt": 2,
        "path": ".github/workflows/ci.yml",
        "repository": {"full_name": "owner/repo"},
        "head_sha": "a" * 40,
    }
    job = {
        "id": 21,
        "name": "Rust workspace (clippy)",
        "run_id": 12,
        "run_attempt": 2,
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-01-01T00:00:00Z",
        "started_at": "2026-01-01T00:00:01Z",
        "completed_at": "2026-01-01T00:00:03Z",
    }
    artifact = {
        "id": 31,
        "name": "clippy-report-2",
        "expired": False,
        "created_at": "2026-01-01T00:00:02Z",
        "workflow_run": {"id": 12, "head_sha": "a" * 40},
    }

    def fetch(path, timeout):
        if "/jobs?" in path:
            return {"total_count": 1, "jobs": [job]}
        if "/artifacts?" in path:
            return {"total_count": 1, "artifacts": [artifact]}
        return run

    return run, job, artifact, fetch


def test_only_successful_current_attempt_is_selected():
    _, _, artifact, fetch = inventory()
    assert report.select("owner/repo", 12, 2, fetch=fetch)["id"] == artifact["id"]


@pytest.mark.parametrize("boundary", ["attempt", "failure", "inherited", "wrong-run", "expired", "before-job", "head"])
def test_selection_rejects_stale_or_unsuccessful_producer(boundary):
    run, job, artifact, fetch = inventory()
    if boundary == "attempt":
        run["run_attempt"] = 1
    elif boundary == "failure":
        job["conclusion"] = "failure"
    elif boundary == "inherited":
        job["created_at"] = "2026-01-01T00:00:02Z"
    elif boundary == "wrong-run":
        artifact["workflow_run"]["id"] = 13
    elif boundary == "expired":
        artifact["expired"] = True
    elif boundary == "before-job":
        artifact["created_at"] = "2026-01-01T00:00:00Z"
    else:
        job["head_sha"] = "b" * 40
    with pytest.raises(ValueError):
        report.select("owner/repo", 12, 2, fetch=fetch)


def test_missing_current_attempt_report_times_out_without_using_previous_attempt():
    _, _, artifact, fetch = inventory()
    artifact["name"] = "clippy-report-1"
    now = [0.0]
    with pytest.raises(ValueError, match="Timed out"):
        report.select(
            "owner/repo",
            12,
            2,
            fetch=fetch,
            clock=lambda: now[0],
            sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
            timeout=6,
        )


def test_diagnostics_survive_partial_json_and_exclude_non_diagnostic_records(tmp_path, capsys):
    (tmp_path / report.REPORT).write_text(
        "incomplete JSON\n"
        + json.dumps({"reason": "build-script-executed", "message": {"rendered": "not a diagnostic"}})
        + "\n"
        + json.dumps({"reason": "compiler-message", "message": {"rendered": "error: unused variable\n"}})
        + "\n",
        encoding="utf-8",
    )
    report.print_diagnostics(tmp_path)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Invalid Clippy diagnostic JSON at line 1\nerror: unused variable\n"


def test_clean_zero_issue_report_is_valid(tmp_path):
    path = tmp_path / report.REPORT
    path.write_text('{"reason":"build-finished","success":true}\n')
    report.validate_report(path, tmp_path)
    expected = {"checkout_sha": "a" * 40, "attempt": 2, "lockfile_hash": "locked"}
    (tmp_path / "metadata.json").write_text(json.dumps({**expected, "report_hash": report.digest(path)}))
    report.verify(tmp_path, tmp_path, expected)
    path.write_text('{"reason":"build-finished","success":false}\n')
    with pytest.raises(ValueError, match="digest mismatch"):
        report.verify(tmp_path, tmp_path, expected)


@pytest.mark.parametrize(
    "field",
    ["checkout_sha", "attempt", "lockfile_hash", "toolchain", "repository", "run_id", "command"],
)
def test_metadata_must_match_actual_consumer_identity(tmp_path, field):
    path = tmp_path / report.REPORT
    path.write_text('{"reason":"build-finished","success":true}\n')
    expected = {field: "consumer"}
    (tmp_path / "metadata.json").write_text(json.dumps({field: "producer", "report_hash": report.digest(path)}))
    with pytest.raises(ValueError, match="provenance"):
        report.verify(tmp_path, tmp_path, expected)


@pytest.mark.parametrize(
    "payload",
    [
        "",
        '{"reason":"build-finished","success":false}\n',
        '{"reason":"compiler-artifact"}\n',
        '{"reason":"build-finished","success":true}\n{}\n',
    ],
)
def test_incomplete_or_failed_stream_is_rejected(tmp_path, payload):
    path = tmp_path / report.REPORT
    path.write_text(payload)
    with pytest.raises(ValueError):
        report.validate_report(path, tmp_path)


@pytest.mark.parametrize("filename", ["../outside.rs", "/outside.rs", "linked.rs"])
def test_diagnostic_paths_cannot_escape_checkout(tmp_path, filename):
    root = tmp_path / "checkout"
    root.mkdir()
    outside = tmp_path / "outside.rs"
    outside.write_text("fn outside() {}")
    (root / "linked.rs").symlink_to(outside)
    item = {
        "reason": "compiler-message",
        "message": {"level": "note", "spans": [{"file_name": filename}], "children": []},
    }
    path = root / report.REPORT
    path.write_text(json.dumps(item) + '\n{"reason":"build-finished","success":true}\n')
    with pytest.raises(ValueError):
        report.validate_report(path, root)


@pytest.mark.parametrize("level", ["warning", "error", "failure-note"])
def test_strict_gate_cannot_be_replaced_by_a_nominal_success_record(tmp_path, level):
    path = tmp_path / report.REPORT
    message = {"reason": "compiler-message", "message": {"level": level, "spans": [], "children": []}}
    path.write_text(json.dumps(message) + '\n{"reason":"build-finished","success":true}\n')
    with pytest.raises(ValueError, match="failed diagnostic"):
        report.validate_report(path, tmp_path)
