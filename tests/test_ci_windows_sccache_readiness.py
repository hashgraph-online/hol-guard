"""An optional compiler cache must not prevent Windows shim tests from starting."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/ci-job-windows-shim-admin/action.yml"
PROBE_NAME = "Check Windows shim compiler cache readiness"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="readiness uses Bash")


def _steps() -> list[dict]:
    return yaml.safe_load(ACTION.read_text())["runs"]["steps"]


@pytest.mark.parametrize("cache_exit", [0, 2, 23])
def test_cache_startup_failure_disables_only_the_wrapper_without_leaking_diagnostics(
    tmp_path: Path,
    cache_exit: int,
) -> None:
    """Execute the actual probe, including failure before a daemon can start."""
    probe = next(step for step in _steps() if step.get("name") == PROBE_NAME)
    assert probe["shell"] == "bash"
    cache = tmp_path / "sccache"
    cache.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$*" >> "$PROBE_CALLS"\n'
        "printf '%s\\n' 'private-cache-url?sig=hidden'\n"
        "printf '%s\\n' 'private-cache-error?sig=hidden' >&2\n"
        f"exit {cache_exit}\n",
        encoding="utf-8",
    )
    cache.chmod(0o755)
    environment = tmp_path / "github-env"
    original = "RUSTC_WORKSPACE_WRAPPER=sccache\nSCCACHE_GHA_RW_MODE=READ_ONLY\n"
    environment.write_text(original)
    calls = tmp_path / "probe-calls"
    completed = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", probe["run"]],
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_ENV": str(environment),
            "PROBE_CALLS": str(calls),
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert calls.read_text().splitlines() == ["--zero-stats"]
    assert environment.read_text() == original + ("RUSTC_WORKSPACE_WRAPPER=\n" if cache_exit else "")
    assert ("::warning::" in completed.stdout) == bool(cache_exit)
    assert "private-cache" not in completed.stdout + completed.stderr
    diagnostics = (tmp_path / "sccache-readiness.log").read_text()
    assert "private-cache-url?sig=hidden" in diagnostics
    assert "private-cache-error?sig=hidden" in diagnostics


def test_readiness_runs_after_final_cache_configuration_and_before_every_cargo_gate() -> None:
    steps = _steps()
    configure = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Route Windows shim contract builds through the compiler cache"
    )
    probe_index = next(i for i, step in enumerate(steps) if step.get("name") == PROBE_NAME)
    assert configure < probe_index
    gates = [(i, step) for i, step in enumerate(steps) if "cargo test " in step.get("run", "")]
    assert gates
    for index, step in gates:
        assert index > probe_index
        assert step["shell"] == "pwsh"
        assert "$ErrorActionPreference = 'Stop'" in step["run"]
        assert "$PSNativeCommandUseErrorActionPreference = $true" in step["run"]
        assert "continue-on-error" not in step
    assert "cargo" not in steps[probe_index]["run"]
    assert "continue-on-error" not in steps[probe_index]


def test_readiness_contract_remains_in_both_quality_commands() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/ci-job-quality/action.yml").read_text())
    commands = [
        step["run"]
        for step in action["runs"]["steps"]
        if "ruff check \\\n" in step.get("run", "") or "ruff format --check \\\n" in step.get("run", "")
    ]
    assert len(commands) == 2
    assert all("tests/test_ci_windows_sccache_readiness.py" in command for command in commands)
