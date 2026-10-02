"""Source PRs must prove committed evidence, not defer repairs until after merge."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from scripts.ci.check_generated_evidence import snapshot_errors


@pytest.fixture
def snapshot(tmp_path: Path):
    """Build a self-contained report and paired catalog without invoking a compiler."""
    bindings = {"sources_sha256": {"source-example": "a" * 64}, "fixtures_sha256": {"seed.json": "b" * 64}}
    report = tmp_path / "decision-diff-report.json"
    raw = (json.dumps({"bindings": bindings}, indent=2, sort_keys=True) + "\n").encode()
    report.write_bytes(raw)
    digest = report.with_suffix(".framed-sha256")
    digest.write_text(hashlib.sha256(len(raw).to_bytes(8, "big") + raw).hexdigest() + "\n")
    canonical, package = tmp_path / "canonical.json", tmp_path / "package.json"
    canonical.write_text('{"catalog":[]}\n')
    package.write_bytes(canonical.read_bytes())
    return report, bindings, [(canonical, package)]


def test_current_snapshot_passes_without_writing(snapshot) -> None:
    """The gate validates committed bytes without replacing an expectation."""
    report, bindings, mirrors = snapshot
    before = {p: p.read_bytes() for p in report.parent.iterdir()}
    assert snapshot_errors(report, bindings, mirrors) == []
    assert {p: p.read_bytes() for p in report.parent.iterdir()} == before


@pytest.mark.parametrize("kind", ["source", "fixture", "missing", "extra"])
def test_source_only_drift_is_rejected(snapshot, kind: str) -> None:
    """Any input change must be accompanied by an updated report in the same PR."""
    report, bindings, mirrors = snapshot
    if kind == "source":
        bindings["sources_sha256"]["source-example"] = "c" * 64
    elif kind == "fixture":
        bindings["fixtures_sha256"]["seed.json"] = "c" * 64
    elif kind == "missing":
        bindings["sources_sha256"].clear()
    else:
        bindings["sources_sha256"]["source-new"] = "c" * 64
    errors = snapshot_errors(report, bindings, mirrors)
    assert errors == ["decision-diff report does not bind the current source and fixture bytes"]


@pytest.mark.parametrize("target", ["report", "digest", "canonical", "package"])
def test_missing_evidence_fails_closed(snapshot, target: str) -> None:
    """A missing producer output must not turn an incomplete check green."""
    report, bindings, mirrors = snapshot
    paths = {
        "report": report,
        "digest": report.with_suffix(".framed-sha256"),
        "canonical": mirrors[0][0],
        "package": mirrors[0][1],
    }
    paths[target].unlink()
    assert snapshot_errors(report, bindings, mirrors)


@pytest.mark.parametrize("raw", [b"[]\n", b"{broken", b'{"bindings":{},"bindings":{}}\n'])
def test_malformed_or_ambiguous_report_fails_closed(snapshot, raw: bytes) -> None:
    """Do not accept parser ambiguity as regenerated evidence."""
    report, bindings, mirrors = snapshot
    report.write_bytes(raw)
    assert snapshot_errors(report, bindings, mirrors)


def test_recomputed_digest_does_not_excuse_noncanonical_report(snapshot) -> None:
    """An internally consistent hash is insufficient when serialization is wrong."""
    report, bindings, mirrors = snapshot
    raw = json.dumps(json.loads(report.read_bytes()), separators=(",", ":")).encode()
    report.write_bytes(raw)
    report.with_suffix(".framed-sha256").write_text(
        hashlib.sha256(len(raw).to_bytes(8, "big") + raw).hexdigest() + "\n"
    )
    assert snapshot_errors(report, bindings, mirrors) == ["decision-diff report is not canonically serialized"]


def test_digest_mismatch_is_rejected(snapshot) -> None:
    """The framed digest must bind the exact committed report bytes."""
    report, bindings, mirrors = snapshot
    report.with_suffix(".framed-sha256").write_text("0" * 64 + "\n")
    assert snapshot_errors(report, bindings, mirrors) == [
        "decision-diff framed digest does not match the committed report"
    ]


def test_mismatched_package_copy_is_rejected(snapshot) -> None:
    """Packaging cannot use a projection different from its reviewed canonical file."""
    report, bindings, mirrors = snapshot
    mirrors[0][1].write_text('{"catalog":["unexpected"]}\n')
    assert snapshot_errors(report, bindings, mirrors) == ["package copy differs from canonical canonical.json"]


def test_symlink_is_not_accepted_as_generated_evidence(snapshot) -> None:
    """Reject a package-file substitution even when the referenced bytes match."""
    report, bindings, mirrors = snapshot
    canonical, package = mirrors[0]
    package.unlink()
    package.symlink_to(canonical)
    assert snapshot_errors(report, bindings, mirrors)


def test_gate_has_no_author_or_branch_exemption() -> None:
    """Normal, fork and repair PRs all receive the same read-only validation."""
    root = Path(__file__).parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/generated-artifacts-guard.yml").read_text())
    events = workflow.get("on", workflow.get(True))
    assert "pull_request" in events
    assert "pull_request_target" not in events
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["regen-owned-paths"]
    assert "if" not in job
    assert "permissions" not in job
    assert all("if" not in step and "continue-on-error" not in step for step in job["steps"])
    assert any("check_generated_evidence.py" in step.get("run", "") for step in job["steps"])
    assert job["steps"][0]["with"]["persist-credentials"] is False


def test_required_native_producer_never_uses_local_preparation() -> None:
    """Required coverage inherits the native freshness gate for PRs and main."""
    root = Path(__file__).parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    producer = workflow["jobs"]["native-command-evaluators"]
    assert "if" not in producer
    verify = next(step for step in producer["steps"] if "verify_native_command_program.py" in step.get("run", ""))
    assert "--prepare" not in verify["run"]
    assert "continue-on-error" not in verify
    assert "native-command-evaluators" in workflow["jobs"]["coverage"]["needs"]
    aggregate = workflow["jobs"]["ci-python-312"]
    assert "coverage" in aggregate["needs"]
    assert 'test "$COVERAGE_RESULT" = "success"' in aggregate["steps"][0]["run"]
    for path in (root / ".github/workflows").glob("*.yml"):
        for line in path.read_text().splitlines():
            if "verify_native_command_program.py" in line:
                assert "--prepare" not in line, path.name
