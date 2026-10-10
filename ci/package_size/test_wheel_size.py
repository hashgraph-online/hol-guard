"""Package budgets catch compressed, expanded and individual binary growth."""

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from scripts.ci.check_wheel_size import NATIVE, inspect_wheel


@pytest.mark.parametrize(
    "payload,metric",
    [
        ({"data": b"x" * 4096}, "unpacked"),
        ({NATIVE + "hol-guard-runtime.exe": b"x" * 4096}, "runtime"),
        ({NATIVE + "guard-command-source": b"x" * 4096}, "compiler"),
        ({"data": b"x"}, "download"),
    ],
)
def test_budget_rejects_each_growth_dimension(tmp_path, payload, metric):
    wheel = tmp_path / "hol_guard-1.0-py3-none-win_amd64.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in payload.items():
            archive.writestr(name, content)
    limits = {name: 100000 for name in ("download", "unpacked", "runtime", "compiler")}
    limits[metric] = 0
    report, failures = inspect_wheel(wheel, {"win_amd64": limits})
    assert len(failures) == 1
    assert metric + " exceeds budget" in failures[0]
    assert "Largest compressed members" in report
    limits[metric] = 100000
    assert inspect_wheel(wheel, {"win_amd64": limits})[1] == []


def test_unknown_platform_cannot_skip_budget(tmp_path):
    with pytest.raises(ValueError, match="No package-size budget"):
        inspect_wheel(tmp_path / "hol_guard-1.0-py3-none-unknown.whl", {})


@pytest.mark.parametrize("megabytes,expected", [(1, 0), (31, 1)])
def test_cli_enforces_expansion_budget_and_writes_ci_summary(tmp_path, megabytes, expected):
    wheel = tmp_path / "hol_guard-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive, archive.open("data", "w") as output:
        for _ in range(megabytes):
            output.write(b"x" * 1024 * 1024)
    summary = tmp_path / "summary.md"
    script = Path(__file__).resolve().parents[2] / "scripts/ci/check_wheel_size.py"
    result = subprocess.run(
        [sys.executable, str(script), "--dist-dir", str(tmp_path)],
        env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary)},
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == expected, result.stderr
    assert "unpacked" in summary.read_text()
    if expected:
        assert "unpacked exceeds budget" in result.stdout


def test_cli_rejects_empty_distribution_directory(tmp_path):
    script = Path(__file__).resolve().parents[2] / "scripts/ci/check_wheel_size.py"
    result = subprocess.run(
        [sys.executable, str(script), "--dist-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 2
    assert "contains no wheels" in result.stderr


@pytest.mark.parametrize("megabytes,expected", [(1, 0), (12, 1)])
def test_cli_native_gate_reuses_binaries_without_building(tmp_path, megabytes, expected):
    (tmp_path / "hol-guard-runtime.exe").write_bytes(b"runtime")
    (tmp_path / "guard-command-source.exe").write_bytes(b"x" * megabytes * 1024 * 1024)
    script = Path(__file__).resolve().parents[2] / "scripts/ci/check_wheel_size.py"
    result = subprocess.run(
        [sys.executable, str(script), "--native-dir", str(tmp_path), "--platform", "win_amd64"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == expected, result.stderr
    if expected:
        assert "compiler exceeds budget" in result.stdout
