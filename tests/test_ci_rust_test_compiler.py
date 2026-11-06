"""Compile test harnesses cheaply without changing cached library flags."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name == "nt", reason="The compiler wrapper runs in Linux CI")
@pytest.mark.parametrize(
    ("arguments", "extra"),
    [
        (
            ["rustc", "--test", "src/main.rs", "-C", "opt-level=1"],
            ["-C", "opt-level=0", "-C", "link-arg=-fuse-ld=lld"],
        ),
        (["rustc", "--crate-type", "rlib", "src/lib.rs", "-C", "opt-level=1"], []),
        (["rustc", "--crate-type", "bin", "src/main.rs", "-C", "opt-level=1"], []),
        (["rustc", "-vV"], []),
        (["rustc", "--cfg", 'feature="--test"', "a file with spaces.rs"], []),
    ],
)
def test_compiler_wrapper_preserves_arguments(tmp_path: Path, arguments: list[str], extra: list[str]) -> None:
    """Only an actual --test flag changes optimization, without shell re-parsing."""
    executable = tmp_path / "sccache"
    executable.write_text(
        f"#!{sys.executable}\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    completed = subprocess.run(
        ["bash", str(ROOT / "scripts/ci/rust_test_compiler.sh"), *arguments],
        env={**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True, text=True, check=True, timeout=5,
    )
    assert json.loads(completed.stdout) == [*arguments, *extra]


@pytest.mark.skipif(os.name == "nt", reason="The compiler wrapper runs in Linux CI")
def test_compiler_wrapper_preserves_cargo_binary_environment(tmp_path: Path) -> None:
    """Preserve Cargo's hyphenated binary path through the executable's shebang."""
    executable = tmp_path / "sccache"
    executable.write_text(
        f"#!{sys.executable}\nimport os\nprint(os.environ['CARGO_BIN_EXE_guard-command-source'])\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    wrapper = tmp_path / "wrapper"
    wrapper.write_bytes((ROOT / "scripts/ci/rust_test_compiler.sh").read_bytes())
    wrapper.chmod(0o755)
    binary = "/tmp/native source/guard-command-source"
    completed = subprocess.run(
        [str(wrapper), "rustc", "--test", "a test.rs"],
        env={
            **os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "CARGO_BIN_EXE_guard-command-source": binary,
        },
        capture_output=True, text=True, check=True, timeout=5,
    )
    assert completed.stdout.strip() == binary


@pytest.mark.skipif(os.name == "nt", reason="The compiler wrapper runs in Linux CI")
def test_cache_compiler_failure_is_not_retried(tmp_path: Path) -> None:
    executable = tmp_path / "sccache"
    executable.write_text("#!/bin/bash\nexit 23\n", encoding="utf-8")
    executable.chmod(0o755)
    completed = subprocess.run(
        ["bash", str(ROOT / "scripts/ci/rust_test_compiler.sh"), "/nonexistent/compiler"],
        env={
            **os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "HOL_GUARD_CI_SCCACHE": "on",
        },
        capture_output=True, text=True, timeout=5,
    )
    assert completed.returncode == 23
    assert completed.stderr == ""


@pytest.mark.skipif(os.name == "nt", reason="The compiler wrapper runs in Linux CI")
@pytest.mark.parametrize("is_test", [False, True])
@pytest.mark.parametrize("exit_code", [0, 23])
def test_direct_compiler_preserves_arguments_environment_and_exit(
    tmp_path: Path, is_test: bool, exit_code: int,
) -> None:
    compiler = tmp_path / "actual compiler"
    compiler.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        "print(json.dumps([sys.argv[1:], os.environ['CARGO_BIN_EXE_guard-command-source']]))\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    compiler.chmod(0o755)
    wrapper = tmp_path / "wrapper"
    wrapper.write_bytes((ROOT / "scripts/ci/rust_test_compiler.sh").read_bytes())
    wrapper.chmod(0o755)
    arguments = ["a file with spaces.rs", "-C", "opt-level=1"]
    if is_test:
        arguments.append("--test")
    completed = subprocess.run(
        [str(wrapper), str(compiler), *arguments],
        env={
            **os.environ, "HOL_GUARD_CI_SCCACHE": "off",
            "CARGO_BIN_EXE_guard-command-source": "native source/guard-command-source",
        },
        capture_output=True, text=True, timeout=5,
    )
    extra = ["-C", "opt-level=0", "-C", "link-arg=-fuse-ld=lld"] if is_test else []
    assert completed.returncode == exit_code
    assert json.loads(completed.stdout) == [
        [*arguments, *extra], "native source/guard-command-source",
    ]


@pytest.mark.skipif(os.name == "nt", reason="The cache readiness check runs in Linux CI")
@pytest.mark.parametrize("exit_code", [0, 2])
def test_cache_readiness_falls_back_without_publishing_diagnostics(tmp_path: Path, exit_code: int) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["native-workspace"]["steps"]
    step = next(step for step in steps if step.get("name") == "Check compiler cache readiness")
    executable = tmp_path / "sccache"
    executable.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "assert sys.argv[1:] == ['--zero-stats']\n"
        "print('private cache diagnostic', file=sys.stderr)\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    environment = tmp_path / "github-env"
    environment.touch()
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        env={
            **os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_ENV": str(environment), "RUNNER_TEMP": str(tmp_path),
        },
        capture_output=True, text=True, check=True, timeout=5,
    )
    assert "private cache diagnostic" not in completed.stdout + completed.stderr
    assert "private cache diagnostic" in (tmp_path / "sccache-readiness.log").read_text()
    assert environment.read_text() == ("HOL_GUARD_CI_SCCACHE=off\n" if exit_code else "")
    assert ("::warning::" in completed.stdout) == bool(exit_code)
