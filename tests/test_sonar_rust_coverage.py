"""Rust coverage must come from instrumented tests of the analyzed checkout."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run_rust_coverage(
    tmp_path: Path, mode: str = "", fail_command: str = ""
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if os.name == "nt" or bash is None:
        pytest.skip("Rust coverage runs on an Ubuntu Bash runner")
    script = tmp_path / "scripts/ci/prepare_sonar_rust_coverage.sh"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/ci/prepare_sonar_rust_coverage.sh", script)
    (tmp_path / "rust").mkdir()
    binaries = tmp_path / "bin"
    binaries.mkdir()
    report = tmp_path / "coverage-reports/rust-lcov.info"
    report.parent.mkdir()
    report.write_text("SF:stale.rs\nDA:1,1\nend_of_record\n", encoding="utf-8")
    for name in ("cargo", "rustup", "python"):
        stub = binaries / name
        stub.write_text(
            f"#!{bash}\n"
            'command="${0##*/} $*"\n'
            'if [[ -n "$FAIL_COMMAND" && "$command" == "$FAIL_COMMAND"* ]]; then exit 7; fi\n'
            'if [[ "${0##*/}" == python ]]; then echo 1.88.0; exit 0; fi\n'
            'if [[ "$*" == *"llvm-cov --version" ]]; then\n'
            '  if [[ "$COVERAGE_MODE" != install ]]; then echo "cargo-llvm-cov 0.6.21"; fi\n'
            '  exit 0\n'
            'fi\n'
            'if [[ "$*" == *"--output-path"* ]]; then\n'
            '  if [[ -e "$REPORT" ]]; then echo "stale report survived" >&2; exit 8; fi\n'
            '  if [[ "$COVERAGE_MODE" == failed-tests ]]; then exit 7; fi\n'
            '  case "$COVERAGE_MODE" in\n'
            '    missing) ;;\n'
            '    empty) : > "$REPORT" ;;\n'
            '    malformed) echo "not LCOV" > "$REPORT" ;;\n'
            '    *) printf "SF:crates/example/src/lib.rs\\nDA:1,1\\nend_of_record\\n" > "$REPORT" ;;\n'
            '  esac\n'
            'fi\n',
            encoding="utf-8",
        )
        stub.chmod(0o700)
    result = subprocess.run(
        [bash, str(script)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAIL_COMMAND": fail_command,
            "COVERAGE_MODE": mode,
            "REPORT": str(report),
        },
    )
    return result


@pytest.mark.parametrize("mode", ["", "install"])
def test_rust_coverage_replaces_stale_report(tmp_path: Path, mode: str) -> None:
    result = _run_rust_coverage(tmp_path, mode)
    assert result.returncode == 0, result.stderr
    report = tmp_path / "coverage-reports/rust-lcov.info"
    assert "SF:stale.rs" not in report.read_text(encoding="utf-8")


@pytest.mark.parametrize("mode", ["missing", "empty", "malformed"])
def test_rust_coverage_rejects_missing_empty_or_invalid_current_report(tmp_path: Path, mode: str) -> None:
    result = _run_rust_coverage(tmp_path, mode)
    assert result.returncode != 0


@pytest.mark.parametrize(
    "fail_command",
    [
        "python",
        "rustup component add",
        "cargo +1.88.0 install",
        "cargo +1.88.0 llvm-cov clean",
    ],
)
def test_rust_coverage_propagates_setup_and_cleanup_failures(tmp_path: Path, fail_command: str) -> None:
    result = _run_rust_coverage(tmp_path, "install", fail_command)
    assert result.returncode == 7, result.stderr


def test_failed_tests_cannot_publish_a_previous_coverage_report(tmp_path: Path) -> None:
    result = _run_rust_coverage(tmp_path, "failed-tests")
    assert result.returncode == 7, result.stderr
    assert not (tmp_path / "coverage-reports/rust-lcov.info").exists()
