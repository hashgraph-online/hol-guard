"""Sonar preparation must verify every coverage shard and run the pinned Clippy."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PREPARE_SCRIPT = ROOT / "scripts/ci/prepare_sonar_analysis.sh"


def test_sonar_preparation_precedes_analysis_and_fails_closed() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["sonar"]
    steps = job["steps"]
    download_index = next(i for i, step in enumerate(steps) if step.get("name") == "Download pytest coverage data")
    setup_index = next(i for i, step in enumerate(steps) if step.get("name") == "Prepare coverage and pinned Rust analysis")
    scan_index = next(i for i, step in enumerate(steps) if step.get("name") == "Analyze with SonarQube Cloud")
    setup = steps[setup_index]
    script = PREPARE_SCRIPT.read_text(encoding="utf-8")
    install = 'rustup toolchain install "$toolchain" --profile minimal --component clippy'
    default = 'rustup default "$toolchain"'
    clippy = "cargo clippy --manifest-path rust/Cargo.toml --locked --workspace"

    assert job["timeout-minutes"] == 20
    assert download_index < setup_index < scan_index
    assert setup["run"] == "bash scripts/ci/prepare_sonar_analysis.sh"
    assert '"rust/rust-toolchain.toml"' in script
    assert script.index(install) < script.index(default) < script.index(clippy)
    assert "set -euo pipefail" in script
    assert setup["shell"] == "bash"
    assert not job.get("continue-on-error", False)
    assert not setup.get("continue-on-error", False)
    assert "SONAR_TOKEN" not in setup.get("env", {})


def _run_preparation(
    tmp_path: Path, shard_count: int, fail_command: str = ""
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
            'if [[ "${0##*/}" == "python" ]]; then printf "1.88.0\\n"; fi\n',
            encoding="utf-8",
        )
        stub.chmod(0o700)
    for shard in range(shard_count):
        directory = tmp_path / "coverage-data" / f"shard-{shard:02d}"
        directory.mkdir(parents=True)
        (directory / ".coverage").touch()
    result = subprocess.run(
        [bash, str(PREPARE_SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}",
            "COMMAND_LOG": str(log),
            "FAIL_COMMAND": fail_command,
        },
    )
    return result, log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_preparation_combines_all_shards_before_installing_and_running_clippy(tmp_path: Path) -> None:
    result, commands = _run_preparation(tmp_path, 96)
    assert result.returncode == 0, result.stderr
    assert len(commands) == 6
    assert commands[0].split() == [
        "uv", "run", "--no-sync", "coverage", "combine",
        *(f"coverage-data/shard-{shard:02d}/.coverage" for shard in range(96)),
    ]
    assert commands[1] == "uv run --no-sync coverage xml"
    assert commands[2].startswith("python -c import tomllib;")
    assert commands[3:] == [
        "rustup toolchain install 1.88.0 --profile minimal --component clippy",
        "rustup default 1.88.0",
        "cargo clippy --manifest-path rust/Cargo.toml --locked --workspace",
    ]


@pytest.mark.parametrize("shard_count", [0, 95, 97])
def test_preparation_rejects_incomplete_or_excess_coverage_before_running_tools(tmp_path: Path, shard_count: int) -> None:
    result, commands = _run_preparation(tmp_path, shard_count)
    assert result.returncode != 0
    assert commands == []


@pytest.mark.parametrize(
    "failed_command",
    [
        "uv run --no-sync coverage combine",
        "uv run --no-sync coverage xml",
        "python",
        "rustup toolchain install",
        "rustup default",
        "cargo clippy",
    ],
)
def test_preparation_stops_at_each_failed_command(tmp_path: Path, failed_command: str) -> None:
    result, commands = _run_preparation(tmp_path, 96, failed_command)
    assert result.returncode == 7
    assert commands[-1].startswith(failed_command)
