"""Test compilation must not block on refreshing package mirrors for LLD."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests.release_workflow_helpers import load_workflow

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci/setup_test_linker.sh"


def fake_tools(tmp_path):
    if os.name == "nt":
        pytest.skip("Linker provisioning runs in Linux CI")
    tools = tmp_path / "tools"
    tools.mkdir()
    sysroot = tmp_path / "sysroot with spaces"
    rustc = tools / "rustc"
    rustc.write_text(
        '#!/bin/bash\nif [[ "$1" == --print ]]; then\n'
        f"  printf '%s\\n' '{sysroot}'\n"
        "else\n  printf '%s\\n' 'host: x86_64-unknown-linux-gnu'\nfi\n"
    )
    rustc.chmod(0o755)
    environment = {**os.environ, "PATH": str(tools), "GITHUB_PATH": str(tmp_path / "github-path")}
    return tools, sysroot, environment


def executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\nprintf '%s\\n' 'LLD fixture'\n")
    path.chmod(0o755)


def test_bundled_linker_is_preferred_and_published_for_future_steps(tmp_path):
    tools, sysroot, environment = fake_tools(tmp_path)
    directory = sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld"
    executable(directory / "ld.lld")
    executable(tools / "ld.lld")
    result = subprocess.run(["/bin/bash", str(SCRIPT)], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert Path(environment["GITHUB_PATH"]).read_text() == f"{directory}\n"
    assert result.stdout.strip() == "LLD fixture"


def test_existing_runner_linker_needs_no_package_install(tmp_path):
    tools, _, environment = fake_tools(tmp_path)
    executable(tools / "ld.lld")
    result = subprocess.run(["/bin/bash", str(SCRIPT)], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not Path(environment["GITHUB_PATH"]).exists()


def test_missing_linker_fails_immediately_without_a_network_fallback(tmp_path):
    _, _, environment = fake_tools(tmp_path)
    result = subprocess.run(["/bin/bash", str(SCRIPT)], env=environment, capture_output=True, text=True)
    assert result.returncode != 0
    assert "no test linker" in result.stderr


def test_normal_and_instrumented_builds_use_the_same_linker_setup():
    workspace = load_workflow(ROOT / ".github/workflows/ci.yml")["jobs"]["native-workspace"]["steps"]
    coverage = load_workflow(ROOT / ".github/actions/prepare-rust-coverage/action.yml")["runs"]["steps"]
    for steps in (workspace, coverage):
        step = next(step for step in steps if "test linker" in step.get("name", ""))
        assert step["run"] == "bash scripts/ci/setup_test_linker.sh"
