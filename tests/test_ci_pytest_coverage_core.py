"""The fast coverage lane must verify its actual branch-capable measurement core."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import coverage
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _measure(tmp_path: Path, core: str, *, enabled: bool = True) -> subprocess.CompletedProcess[str]:
    (tmp_path / "sample.py").write_text(
        "def choose(value):\n    if value:\n        return 'yes'\n    return 'no'\n",
        encoding="utf-8",
    )
    (tmp_path / "test_sample.py").write_text(
        "from sample import choose\n"
        "def test_branches():\n    assert choose(True) == 'yes'\n    assert choose(False) == 'no'\n",
        encoding="utf-8",
    )
    (tmp_path / ".coveragerc").write_text("[run]\nsource = sample\n", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        PYTHONPATH=str(ROOT / "scripts/ci"),
        COVERAGE_CORE=core,
        COVERAGE_FILE=str(tmp_path / ".coverage"),
    )
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "pytest_coverage_core",
            "test_sample.py",
            "--cov-config=.coveragerc",
            *(["--cov=sample", "--cov-branch", "--cov-report="] if enabled else ["--no-cov"]),
            "-q",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


@pytest.mark.parametrize("enabled", [False, True])
def test_coverage_lane_rejects_missing_measurement_and_c_tracing(tmp_path: Path, enabled: bool) -> None:
    result = _measure(tmp_path, "ctrace", enabled=enabled)

    assert result.returncode != 0
    assert "CI requires" in result.stderr
    assert "1 passed" not in result.stdout


def test_coverage_lane_requires_real_sysmon_branch_support(tmp_path: Path) -> None:
    result = _measure(tmp_path, "sysmon")

    if sys.version_info < (3, 14):
        assert result.returncode != 0
        assert "CI requires SysMonitor branch coverage" in result.stderr
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Verified active SysMonitor branch coverage" in result.stdout
        data = coverage.CoverageData(basename=str(tmp_path / ".coverage"))
        data.read()
        assert data.has_arcs()
        assert {(2, 3), (2, 4), (3, -1), (4, -1)} <= set(data.arcs(str(tmp_path / "sample.py")) or [])
        measurement = coverage.Coverage(data_file=str(tmp_path / ".coverage"), config_file=False)
        measurement.load()
        assert measurement.branch_stats(str(tmp_path / "sample.py")) == {2: (2, 2)}
