"""Sonar preparation must verify every coverage shard and use the pinned toolchain."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import coverage
import pytest

ROOT = Path(__file__).resolve().parents[1]
PREPARE_SCRIPT = ROOT / "scripts/ci/prepare_sonar_analysis.sh"
SETUP_SCRIPT = ROOT / "scripts/ci/setup_sonar_rust.sh"


def _run_preparation(
    tmp_path: Path, shard_count: int, fail_command: str = "", script: Path = PREPARE_SCRIPT, invalid_inventory: str = ""
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bash = shutil.which("bash")
    if os.name == "nt" or bash is None:
        pytest.skip("Sonar preparation runs on an Ubuntu Bash runner")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    log = tmp_path / "commands.log"
    for name in ("uv", "rustup", "cargo", "python"):
        stub = binaries / name
        stub.write_text(
            f"#!{bash}\n"
            'command="${0##*/} $*"\n'
            'printf "%s\\n" "$command" >> "$COMMAND_LOG"\n'
            'if [[ "$command" == "$FAIL_COMMAND"* && -n "$FAIL_COMMAND" ]]; then exit 7; fi\n'
            'if [[ "${0##*/}" == "uv" && "${4:-}" == "scripts/ci/select_pytest_coverage.py" ]]; then\n'
            '  exec "$REAL_PYTHON" "$SELECTOR_SCRIPT" "${@:5}"\n'
            "fi\n"
            'if [[ "${0##*/}" == "python" ]]; then printf "1.88.0\\n"; fi\n',
            encoding="utf-8",
        )
        stub.chmod(0o700)
    for shard in range(shard_count):
        directory = tmp_path / "coverage-data" / f"pytest-coverage-1-{shard}"
        directory.mkdir(parents=True)
        database = coverage.CoverageData(basename=str(directory / ".coverage"))
        database.add_lines({str(tmp_path / "example.py"): {1}})
        database.write()
    manifest = {
        "schema": "hol-guard.pytest-coverage-selection.v1",
        "shards": [{"shard": shard, "name": f"pytest-coverage-1-{shard}"} for shard in range(128)],
    }
    if invalid_inventory == "empty":
        (tmp_path / "coverage-data/pytest-coverage-1-0/.coverage").write_bytes(b"")
    elif invalid_inventory == "unselected":
        (tmp_path / "coverage-data/pytest-coverage-1-0").rename(tmp_path / "coverage-data/pytest-coverage-2-0")
    elif invalid_inventory == "manifest":
        manifest["shards"].pop()
    (tmp_path / "coverage-selection.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(
        [bash, str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}",
            "REAL_PYTHON": sys.executable,
            "SELECTOR_SCRIPT": str(ROOT / "scripts/ci/select_pytest_coverage.py"),
            "COMMAND_LOG": str(log),
            "FAIL_COMMAND": fail_command,
            "CI_PYTEST_COVERAGE_SHARDS": "128",
        },
    )
    return result, log.read_text(encoding="utf-8").splitlines() if log.exists() else []




@pytest.mark.parametrize("shard_count", [0, 64, 127, 129])
def test_preparation_rejects_incomplete_or_excess_coverage_before_running_tools(
    tmp_path: Path, shard_count: int
) -> None:
    result, commands = _run_preparation(tmp_path, shard_count)
    assert result.returncode != 0
    assert commands == []


@pytest.mark.parametrize(
    "failed_command",
    [
        "uv run --no-sync python scripts/ci/select_pytest_coverage.py",
        "uv run --no-sync python scripts/ci/parallel_coverage_combine.py",
        "uv run --no-sync python scripts/ci/parallel_coverage_xml.py",
    ],
)
def test_preparation_stops_at_each_failed_command(tmp_path: Path, failed_command: str) -> None:
    result, commands = _run_preparation(tmp_path, 128, failed_command)
    assert result.returncode == 7
    assert commands[-1].startswith(failed_command)


@pytest.mark.parametrize("failed_command", ["python", "rustup toolchain install", "rustup default"])
def test_setup_stops_at_each_failed_command(tmp_path: Path, failed_command: str) -> None:
    result, commands = _run_preparation(tmp_path, 0, failed_command, SETUP_SCRIPT)
    assert result.returncode == 7
    assert commands[-1].startswith(failed_command)


@pytest.mark.parametrize("invalid_inventory", ["empty", "unselected", "manifest"])
def test_preparation_runs_real_download_validation_before_combine(tmp_path: Path, invalid_inventory: str) -> None:
    result, _commands = _run_preparation(tmp_path, 128, invalid_inventory=invalid_inventory)
    assert result.returncode == 1
    assert "Coverage selection failed:" in result.stderr
