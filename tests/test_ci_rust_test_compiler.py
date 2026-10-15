"""Compile test harnesses cheaply without changing cached library flags."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

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
