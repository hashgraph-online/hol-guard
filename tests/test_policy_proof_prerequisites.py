"""Release proof scripts fail when a required half cannot execute."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = ("run-cloud-exception-sync-proof.sh", "run-policy-cloud-exceptions-release-audit.sh")


def _fixture(
    tmp_path: Path, script: str, *, python_exit: int = 0, frontend_exit: int | None = None
) -> tuple[Path, dict[str, str]]:
    project = tmp_path / "project"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(_ROOT / "scripts" / script, scripts / script)
    binary = tmp_path / "bin"
    binary.mkdir()
    for name, source in {
        "python3": f"#!/bin/sh\necho python-required-check\nexit {python_exit}\n",
        "git": "#!/bin/sh\nexit 0\n",
        "npx": "#!/bin/sh\necho unexpected-package-download\nexit 0\n",
    }.items():
        path = binary / name
        path.write_text(source)
        path.chmod(0o755)
    dashboard = project / "dashboard"
    dashboard.mkdir()
    if frontend_exit is not None:
        tsx = dashboard / "node_modules" / ".bin" / "tsx"
        tsx.parent.mkdir(parents=True)
        tsx.write_text(f'#!/bin/sh\necho "frontend-required-check:$*"\nexit {frontend_exit}\n')
        tsx.chmod(0o755)
    return scripts / script, {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}"}


def _run(script: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=15, check=False)


@pytest.mark.parametrize("script", _SCRIPTS)
def test_missing_frontend_dependency_is_incomplete_before_any_proof_runs(tmp_path: Path, script: str) -> None:
    path, env = _fixture(tmp_path, script)
    result = _run(path, env)
    assert result.returncode == 2
    assert "incomplete" in result.stderr.lower()
    assert "tsx" in result.stderr
    assert "python-required-check" not in result.stdout
    assert "unexpected-package-download" not in result.stdout
    assert ": ok" not in result.stdout


@pytest.mark.parametrize("script", _SCRIPTS)
@pytest.mark.parametrize("python_exit,frontend_exit", [(3, 0), (0, 4)])
def test_failure_in_either_required_half_cannot_report_success(
    tmp_path: Path, script: str, python_exit: int, frontend_exit: int
) -> None:
    path, env = _fixture(tmp_path, script, python_exit=python_exit, frontend_exit=frontend_exit)
    result = _run(path, env)
    assert result.returncode == (python_exit or frontend_exit)
    assert ": ok" not in result.stdout


@pytest.mark.parametrize("script,frontend_calls", [(_SCRIPTS[0], 1), (_SCRIPTS[1], 5)])
def test_complete_proof_executes_both_declared_halves(tmp_path: Path, script: str, frontend_calls: int) -> None:
    path, env = _fixture(tmp_path, script, frontend_exit=0)
    result = _run(path, env)
    assert result.returncode == 0, result.stderr
    assert "python-required-check" in result.stdout
    assert result.stdout.count("frontend-required-check:") == frontend_calls
    assert "unexpected-package-download" not in result.stdout
    assert ": ok" in result.stdout
