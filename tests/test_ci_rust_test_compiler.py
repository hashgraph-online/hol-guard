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
        (["rustc", "--test", "src/main.rs", "-C", "opt-level=1"], ["-C", "opt-level=0"]),
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
        ["sh", str(ROOT / "scripts/ci/rust_test_compiler.sh"), *arguments],
        env={**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True, text=True, check=True, timeout=5,
    )
    assert json.loads(completed.stdout) == [*arguments, *extra]
