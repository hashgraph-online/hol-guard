"""Reject incomplete or mismatched results in the actual retirement validator."""

from __future__ import annotations

import hashlib
import io
import json
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / "scripts/ci/native_retirement_resident_evidence.py"
SOURCE = "a" * 40
CASES = tuple(
    f"test_installation_retirement_fences_actual_resident_across_processes[{outcome}-{shape}]"
    for outcome in ("commit", "sql-refusal")
    for shape in ("v3", "v4")
)


def _execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    xml: str | None,
    *,
    source: str = SOURCE,
    dirty: bool = False,
    binary: bool = True,
):
    code = compile(WORKFLOW.read_text(), str(WORKFLOW), "exec")
    root = tmp_path / "evidence-root"
    root.mkdir()
    evidence = root / "artifacts/native-installation-retirement"
    evidence.mkdir(parents=True)
    if xml is not None:
        (evidence / "results.xml").write_text(xml)
    if binary:
        runtime = root / "rust/target/release/hol-guard-runtime"
        runtime.parent.mkdir(parents=True)
        runtime.write_bytes(b"synthetic-validator-test-binary")
    with monkeypatch.context() as context:
        context.chdir(root)
        context.setenv("GITHUB_SHA", SOURCE)
        failure = None
        with (
            patch("subprocess.check_output", side_effect=[" M synthetic-file" if dirty else "", source]),
            redirect_stdout(io.StringIO()),
        ):
            try:
                exec(code, {})
            except (AssertionError, ET.ParseError) as error:
                failure = type(error).__name__
    report = evidence / "proof.json"
    return failure, json.loads(report.read_text()) if report.exists() else None


def _cases() -> str:
    return "".join(f'<testcase name="{name}"/>' for name in CASES)


def test_exact_four_cases_keep_source_and_original_eight_case_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    failure, report = _execute(tmp_path, monkeypatch, "<testsuite>" + _cases() + "</testsuite>")
    assert failure is None and report is not None
    assert report["status"] == "pass" and report["assertionCount"] == 4
    assert report["schema"] == "native-installation-retirement-proof.v1"
    assert report["sourceSha"] == SOURCE and report["exactCleanSourceVerified"]
    assert report["runtimeBinarySha256"] == hashlib.sha256(b"synthetic-validator-test-binary").hexdigest()
    assert report["originalOriginProofDenominator"] == 8
    assert report["publicationShapes"] == ["v3", "v4"]
    assert report["mutationOutcomes"] == ["commit", "sql-refusal"]
    assert report["hookEvents"] == ["PreToolUse", "PostToolUse"]
    assert report["separateRotationProcess"] and report["nativeAutoRequired"] and report["stagedFeatureNegotiation"]
    assert report["canonicalEnforcement"] == "explicit-test-only"
    assert report["productionAdvertisement"] == report["installedWheel"] == "not-evaluated"


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("replacement", ["missing", "duplicate", "wrong", "failure", "error", "skipped"])
def test_every_retirement_case_must_execute_once_and_pass(tmp_path, monkeypatch, case, replacement):
    original = f'<testcase name="{case}"/>'
    replaced = {
        "missing": "",
        "duplicate": original * 2,
        "wrong": '<testcase name="wrong"/>',
    }.get(replacement, f'<testcase name="{case}"><{replacement}/></testcase>')
    failure, report = _execute(
        tmp_path, monkeypatch, "<testsuite>" + _cases().replace(original, replaced) + "</testsuite>"
    )
    assert failure == "AssertionError" and report is not None
    assert report["status"] == "fail" and not report["allAssertionsPassed"]


@pytest.mark.parametrize("field", ["errors", "failures", "skipped"])
def test_declared_nonpass_suite_counts_are_rejected(tmp_path, monkeypatch, field):
    failure, report = _execute(
        tmp_path, monkeypatch, f'<testsuites {field}="1"><testsuite>' + _cases() + "</testsuite></testsuites>"
    )
    assert failure == "AssertionError" and report is not None
    assert report["status"] == "fail"


@pytest.mark.parametrize("marker", ["failure", "error", "skipped"])
def test_suite_level_nonpass_markers_are_rejected(tmp_path, monkeypatch, marker):
    failure, report = _execute(tmp_path, monkeypatch, "<testsuite>" + _cases() + f"<{marker}/></testsuite>")
    assert failure == "AssertionError" and report is not None
    assert report["status"] == "fail"


@pytest.mark.parametrize("xml", [None, "<testsuite/>", "<testsuite"])
def test_missing_empty_or_malformed_results_never_pass(tmp_path, monkeypatch, xml):
    failure, report = _execute(tmp_path, monkeypatch, xml)
    assert failure in {"AssertionError", "ParseError"}
    assert report is None or report["status"] == "fail"


@pytest.mark.parametrize("source,dirty,binary", [("b" * 40, False, True), (SOURCE, True, True), (SOURCE, False, False)])
def test_wrong_or_dirty_source_and_missing_binary_never_pass(tmp_path, monkeypatch, source, dirty, binary):
    failure, report = _execute(
        tmp_path,
        monkeypatch,
        "<testsuite>" + _cases() + "</testsuite>",
        source=source,
        dirty=dirty,
        binary=binary,
    )
    assert failure == "AssertionError" and report is not None
    assert report["status"] == "fail"
