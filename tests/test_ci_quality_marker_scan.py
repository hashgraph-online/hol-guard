"""The actual quality action accepts no matches and rejects markers or scan errors."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="quality job requires Bash")


def _scan(root: Path, content: str | None) -> subprocess.CompletedProcess[str]:
    if content is not None:
        sources = root / "src/codex_plugin_scanner/guard"
        sources.mkdir(parents=True)
        (sources / "example.py").write_text(content)
        (sources / "ignored.txt").write_text("TODO")
    action = yaml.safe_load((ROOT / ".github/actions/ci-job-quality/action.yml").read_text())
    step = next(item for item in action["runs"]["steps"] if item.get("name") == "TODO/FIXME scan (L330)")
    assert step["shell"] == "bash"
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize("content", ["def example(): pass\n", "# TODO: annotation # type: ignore\n"])
def test_clean_or_ignored_markers_do_not_fail_the_quality_job(tmp_path: Path, content: str) -> None:
    result = _scan(tmp_path, content)
    assert result.returncode == 0, result.stderr
    assert "Guard TODO/FIXME count: 0" in result.stdout


@pytest.mark.parametrize("marker", ["TODO", "FIXME", "HACK", "XXX"])
def test_real_markers_still_fail_the_quality_job(tmp_path: Path, marker: str) -> None:
    result = _scan(tmp_path, f"# TODO: annotation # type: ignore\n# {marker}: unfinished\n")
    assert result.returncode != 0
    assert "Guard TODO/FIXME count: 1" in result.stdout
    assert f"{marker}: unfinished" in result.stdout
    assert "annotation" not in result.stdout


def test_scan_errors_still_fail_the_quality_job(tmp_path: Path) -> None:
    result = _scan(tmp_path, None)
    assert result.returncode != 0


def test_unexpected_scanner_errors_are_not_accepted_as_no_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = tmp_path / "grep"
    scanner.write_text("#!/bin/sh\nprintf 'simulated scan failure\\n' >&2\nexit 2\n")
    scanner.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    result = _scan(tmp_path, "def example(): pass\n")
    assert result.returncode != 0
    assert "simulated scan failure" in result.stderr
