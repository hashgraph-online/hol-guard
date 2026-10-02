from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from pathlib import Path

import pytest
import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "ci" / "pytest_duration_manifest.py"
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("pytest_duration_manifest", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
duration_manifest = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = duration_manifest
SPEC.loader.exec_module(duration_manifest)


def _write_report(path: Path, values: dict[str, float]) -> None:
    path.write_text(json.dumps({"schema_version": 1, "node_durations_seconds": values}), encoding="utf-8")


def test_manifest_merges_reports_deterministically_and_rejects_duplicate_nodes(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write_report(first, {"tests/test_b.py::test_b": 2.0})
    _write_report(second, {"tests/test_a.py::test_a": 1.0})

    assert duration_manifest.merge_duration_reports([second, first]) == {
        "tests/test_a.py::test_a": 1.0,
        "tests/test_b.py::test_b": 2.0,
    }
    _write_report(second, {"tests/test_b.py::test_b": 1.0})

    with pytest.raises(ValueError, match="duplicate"):
        duration_manifest.merge_duration_reports([first, second])


def test_ci_duration_artifacts_cannot_mix_rerun_attempts(tmp_path: Path) -> None:
    workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")))
    upload = next(
        step
        for step in workflow["jobs"]["coverage"]["steps"]
        if step.get("with", {}).get("path") == "pytest-durations.json"
    )["with"]["name"]
    candidate = workflow["jobs"]["duration-manifest-candidate"]["steps"]
    pattern = next(step for step in candidate if "pattern" in step.get("with", {}))["with"]["pattern"]
    selected_pattern = pattern.replace("${{ github.run_attempt }}", "3")
    reports = []
    for attempt in (1, 3):
        for shard in range(128):
            name = upload.replace("${{ github.run_attempt }}", str(attempt)).replace(
                "${{ matrix.shard-index }}", str(shard)
            )
            path = tmp_path / name
            # A rerun may use a different shard plan; old reports must not fill its gaps.
            node = (shard + attempt) % 128
            _write_report(path, {f"tests/test_fixture.py::test_{node}": float(attempt)})
            if fnmatchcase(name, selected_pattern):
                reports.append(path)
    assert len(reports) == 128
    merged = duration_manifest.merge_duration_reports(reports)
    assert len(merged) == 128
    assert set(merged.values()) == {3.0}
    assert 'if [ "${#reports[@]}" -ne 128 ]; then' in next(
        step["run"] for step in candidate if step.get("name") == "Build duration manifest candidate"
    )


def test_partial_rerun_retains_previous_manifest_without_publishing(tmp_path: Path) -> None:
    workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")))
    steps = workflow["jobs"]["duration-manifest-candidate"]["steps"]
    build = next(step for step in steps if step.get("name") == "Build duration manifest candidate")
    upload = next(step for step in steps if step.get("name") == "Upload pytest duration manifest candidate")
    artifact = tmp_path / "duration-reports" / "pytest-durations-2-7"
    artifact.mkdir(parents=True)
    _write_report(artifact / "pytest-durations.json", {"tests/test_fixture.py::test_7": 2.0})
    output = tmp_path / "step-output"
    result = subprocess.run(
        ["bash", "-c", build["run"]],
        cwd=tmp_path,
        env={"GITHUB_OUTPUT": str(output)},
        text=True,
        capture_output=True,
        check=True,
    )
    assert "Incomplete attempt reports" in result.stdout
    assert output.read_text() == "complete=false\n"
    assert not (tmp_path / "pytest-duration-manifest-candidate.json.gz").exists()
    assert upload["if"] == "steps.duration-manifest.outputs.complete == 'true'"


def test_manifest_round_trip_and_age_validation(tmp_path: Path) -> None:
    output = tmp_path / "manifest.json"
    observed_at = datetime(2026, 7, 26, 16, 0, tzinfo=timezone.utc)
    duration_manifest.write_duration_manifest(output, {"tests/test_a.py::test_a": 1.0}, observed_at)

    assert duration_manifest.load_duration_manifest(
        output, now=observed_at + timedelta(days=27), max_age=timedelta(days=28)
    ) == {duration_manifest.node_id_digest("tests/test_a.py::test_a"): 1.0}
    assert "tests/test_a.py::test_a" not in output.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="stale"):
        duration_manifest.load_duration_manifest(
            output, now=observed_at + timedelta(days=29), max_age=timedelta(days=28)
        )
    with pytest.raises(ValueError, match="future-dated"):
        duration_manifest.load_duration_manifest(
            output, now=observed_at - timedelta(seconds=1), max_age=timedelta(days=28)
        )


def test_manifest_rejects_non_finite_durations(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    _write_report(output, {"tests/test_a.py::test_a": float("nan")})

    with pytest.raises(ValueError, match="invalid duration"):
        duration_manifest.load_duration_report(output)


@pytest.mark.parametrize("newer_filename", ["committed.json.gz", "trusted-artifact.json.gz"])
@pytest.mark.parametrize("reverse", [False, True])
def test_latest_manifest_uses_observation_time_independent_of_path_order(
    tmp_path: Path, newer_filename: str, reverse: bool
) -> None:
    now = datetime(2026, 9, 20, 16, 10, tzinfo=timezone.utc)
    paths = [tmp_path / "committed.json.gz", tmp_path / "trusted-artifact.json.gz"]
    for path in paths:
        newer = path.name == newer_filename
        duration_manifest.write_duration_manifest(
            path,
            {"tests/test_a.py::test_a": 3.0 if newer else 20.0},
            now - timedelta(hours=1 if newer else 24),
        )

    durations, selected = duration_manifest.load_latest_duration_manifest(
        reversed(paths) if reverse else paths, now=now, max_age=timedelta(days=28)
    )

    assert selected == tmp_path / newer_filename
    assert durations == {duration_manifest.node_id_digest("tests/test_a.py::test_a"): 3.0}


@pytest.mark.parametrize("invalid_kind", ["missing", "corrupt", "truncated", "stale", "future"])
def test_latest_manifest_falls_back_when_an_optional_source_is_invalid(tmp_path: Path, invalid_kind: str) -> None:
    now = datetime(2026, 9, 20, 16, 10, tzinfo=timezone.utc)
    valid = tmp_path / "committed.json.gz"
    invalid = tmp_path / "optional.json.gz"
    duration_manifest.write_duration_manifest(valid, {"tests/test_a.py::test_a": 4.0}, now - timedelta(hours=1))
    if invalid_kind == "corrupt":
        invalid.write_bytes(b"not a gzip stream")
    elif invalid_kind == "truncated":
        invalid.write_bytes(valid.read_bytes()[:10])
    elif invalid_kind in {"stale", "future"}:
        observed_at = now - timedelta(days=29) if invalid_kind == "stale" else now + timedelta(seconds=1)
        duration_manifest.write_duration_manifest(invalid, {"tests/test_a.py::test_a": 99.0}, observed_at)

    durations, selected = duration_manifest.load_latest_duration_manifest(
        [valid, invalid], now=now, max_age=timedelta(days=28)
    )

    assert selected == valid
    assert durations == {duration_manifest.node_id_digest("tests/test_a.py::test_a"): 4.0}


def test_latest_manifest_rejects_all_invalid_candidates(tmp_path: Path) -> None:
    now = datetime(2026, 9, 20, 16, 10, tzinfo=timezone.utc)
    stale = tmp_path / "stale.json.gz"
    missing = tmp_path / "missing.json.gz"
    duration_manifest.write_duration_manifest(stale, {"tests/test_a.py::test_a": 4.0}, now - timedelta(days=29))

    with pytest.raises(ValueError, match="no current pytest duration manifest"):
        duration_manifest.load_latest_duration_manifest([stale, missing], now=now, max_age=timedelta(days=28))
