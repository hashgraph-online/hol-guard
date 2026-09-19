"""The release collector records execution and rejects skipped or failing tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.ci.collect_release_negative_outcomes import collect
from scripts.ci.verify_release_negative_outcomes import REQUIRED_TESTS


def _repository(root: Path, *, first_body: str = "assert True") -> str:
    tests = root / "tests"
    tests.mkdir()
    (root / ".gitignore").write_text("__pycache__/\n.pytest_cache/\n")
    (root / "pytest.ini").write_text("[pytest]\nmarkers = release: required release test\n")
    source = "import pytest\n"
    for index, node in enumerate(REQUIRED_TESTS.values()):
        body = first_body if index == 0 else "assert True"
        source += f"\n@pytest.mark.release\ndef {node.split('::')[1]}():\n    {body}\n"
    (tests / "test_release_negative_outcomes.py").write_text(source)
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test execution fixture",
        ],
        cwd=root,
        check=True,
    )
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def test_collector_records_all_executed_phases(tmp_path: Path) -> None:
    source = _repository(tmp_path)
    payload = collect(tmp_path, source_sha=source)
    assert payload["source_sha"] == source
    assert len(payload["pytest_results"]) == len(REQUIRED_TESTS)
    assert all(result["call"] == "passed" for result in payload["pytest_results"])
    assert all(case["passed"] is False for case in payload["cases"])


@pytest.mark.parametrize("body", ["assert False", "pytest.skip('unavailable')"])
def test_collector_rejects_missing_negative_assertions(tmp_path: Path, body: str) -> None:
    source = _repository(tmp_path, first_body=body)
    with pytest.raises((RuntimeError, ValueError)):
        collect(tmp_path, source_sha=source)


def test_collector_refuses_a_different_or_modified_source(tmp_path: Path) -> None:
    source = _repository(tmp_path)
    with pytest.raises(RuntimeError, match="does not match"):
        collect(tmp_path, source_sha="0" * 40)
    (tmp_path / "tests/test_release_negative_outcomes.py").write_text("raise RuntimeError('modified')")
    with pytest.raises(RuntimeError, match="unchanged source"):
        collect(tmp_path, source_sha=source)
