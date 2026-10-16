"""Rust coverage must come from instrumented tests of the analyzed checkout."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _run_rust_coverage(
    tmp_path: Path, mode: str = "", fail_command: str = "", partition: str = "all"
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if os.name == "nt" or bash is None:
        pytest.skip("Rust coverage runs on an Ubuntu Bash runner")
    script = tmp_path / "scripts/ci/prepare_sonar_rust_coverage.sh"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/ci/prepare_sonar_rust_coverage.sh", script)
    shutil.copyfile(ROOT / "scripts/ci/sonar_rust_profile.sh", script.with_name("sonar_rust_profile.sh"))
    (tmp_path / "rust").mkdir()
    binaries = tmp_path / "bin"
    binaries.mkdir()
    report = tmp_path / "coverage-reports/rust-lcov.info"
    if partition != "all":
        report = tmp_path / "coverage-reports" / partition / "rust-lcov.info"
    report.parent.mkdir(parents=True)
    report.write_text("SF:stale.rs\nDA:1,1\nend_of_record\n", encoding="utf-8")
    for name in ("cargo", "rustup", "python"):
        stub = binaries / name
        stub.write_text(
            f"#!{bash}\n"
            'command="${0##*/} $*"\n'
            'printf "%s|%s|%s|%s|%s|%s\\n" "$command" "${CARGO_PROFILE_TEST_OPT_LEVEL:-}" '
            '"${CARGO_PROFILE_TEST_DEBUG:-}" "${CARGO_PROFILE_TEST_DEBUG_ASSERTIONS:-}" '
            '"${CARGO_PROFILE_TEST_OVERFLOW_CHECKS:-}" "${LLVM_PROFILE_FILE_NAME:-}" >> "$COMMAND_LOG"\n'
            'if [[ -n "$FAIL_COMMAND" && "$command" == "$FAIL_COMMAND"* ]]; then exit 7; fi\n'
            'if [[ "${0##*/}" == python ]]; then echo 1.88.0; exit 0; fi\n'
            'if [[ "$*" == *"llvm-cov nextest"* && "$COVERAGE_MODE" == failed-tests ]]; then exit 7; fi\n'
            'if [[ "$*" == *"llvm-cov --version" ]]; then\n'
            '  if [[ "$COVERAGE_MODE" != install ]]; then echo "cargo-llvm-cov 0.6.21"; fi\n'
            "  exit 0\n"
            "fi\n"
            'if [[ "$*" == *"--output-path"* ]]; then\n'
            '  if [[ -e "$REPORT" ]]; then echo "stale report survived" >&2; exit 8; fi\n'
            '  if [[ "$COVERAGE_MODE" == failed-tests ]]; then exit 7; fi\n'
            '  case "$COVERAGE_MODE" in\n'
            "    missing) ;;\n"
            '    empty) : > "$REPORT" ;;\n'
            '    malformed) echo "not LCOV" > "$REPORT" ;;\n'
            '    *) printf "SF:crates/example/src/lib.rs\\nDA:1,1\\nend_of_record\\n" > "$REPORT" ;;\n'
            "  esac\n"
            "fi\n",
            encoding="utf-8",
        )
        stub.chmod(0o700)
    result = subprocess.run(
        [bash, str(script), partition],
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
            "COMMAND_LOG": str(tmp_path / "commands.log"),
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


def test_coverage_retains_all_checked_tests_and_uses_ci_scheduling(tmp_path: Path) -> None:
    result = _run_rust_coverage(tmp_path)
    assert result.returncode == 0, result.stderr
    lines = (tmp_path / "commands.log").read_text().splitlines()
    clean = next(index for index, line in enumerate(lines) if "llvm-cov clean --workspace" in line)
    run = next(index for index, line in enumerate(lines) if "llvm-cov nextest" in line)
    command, optimization, debug, assertions, overflow, profile_file = lines[run].split("|")
    assert clean < run
    assert "--locked --workspace --all-targets" in command
    assert "--profile ci --test-threads 4 --retries 0 --no-fail-fast" in command
    assert "--no-report" in command
    report = next(line for line in lines if "llvm-cov report" in line)
    assert "llvm-cov report --locked --lcov --output-path" in report
    assert (optimization, debug, assertions, overflow) == ("1", "line-tables-only", "true", "true")
    assert profile_file == "guard-%8m.profraw"
    assert "--filter" not in command and "--ignore" not in command


def test_dependency_cache_tracks_the_instrumented_build_profile() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/prepare-rust-coverage/action.yml").read_text())
    steps = action["runs"]["steps"]
    interpreter = next(step for step in steps if step.get("uses", "").startswith("actions/setup-python@"))
    assert interpreter["with"]["python-version"] == "${{ env.CI_PYTHON_VERSION }}"
    trust = next(step for step in steps if "refresh_extension_artifacts.py --trust-only" in step.get("run", ""))
    compile_step = next(step for step in steps if step.get("name") == "Generate current-checkout Rust coverage")
    assert steps.index(trust) < steps.index(compile_step)
    assert steps.index(interpreter) < steps.index(trust)
    cache = next(step for step in action["runs"]["steps"] if step.get("name") == "Cache Rust analysis dependencies")
    assert (
        "hashFiles('scripts/ci/sonar_rust_profile.sh', 'scripts/ci/rust_test_compiler.sh', 'rust/Cargo.toml')"
        in cache["with"]["shared-key"]
    )
    assert cache["with"]["cache-on-failure"] is False
    assert cache["with"]["save-if"] == "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
    run = next(
        step for step in action["runs"]["steps"] if step.get("name") == "Generate current-checkout Rust coverage"
    )
    assert (
        run["env"]["SCCACHE_GHA_RW_MODE"]
        == "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'READ_WRITE' || 'READ_ONLY' }}"
    )


@pytest.mark.skipif(os.name == "nt", reason="Unix Cargo wrappers require executable mode bits")
def test_coverage_workspace_compiler_wrapper_is_executable() -> None:
    assert os.access(ROOT / "scripts/ci/rust_test_compiler.sh", os.X_OK)


@pytest.mark.parametrize(
    ("partition", "packages"),
    [
        ("core", "--workspace --exclude guard-command --exclude hol-guard-runtime"),
        ("command", "--package guard-command"),
        ("runtime-1", "--package hol-guard-runtime"),
        ("runtime-2", "--package hol-guard-runtime"),
    ],
)
def test_partitions_preserve_every_package_target_and_report_dependency_coverage(tmp_path, partition, packages):
    result = _run_rust_coverage(tmp_path, partition=partition)
    assert result.returncode == 0, result.stderr
    lines = (tmp_path / "commands.log").read_text().splitlines()
    run = next(line for line in lines if "llvm-cov nextest" in line)
    assert f"--locked {packages} --all-targets" in run
    assert "--no-report" in run
    assert "--retries 0 --no-fail-fast" in run
    assert "--filter" not in run and "--ignore" not in run
    if partition.startswith("runtime-"):
        assert f"--partition hash:{partition[-1]}/2" in run
    else:
        assert "--partition" not in run
    report = next(line for line in lines if "llvm-cov report" in line)
    assert "--package" not in report and "--exclude" not in report
    assert f"coverage-reports/{partition}/rust-lcov.info" in report
    assert any(f"rust_coverage_reports bind {partition}" in line for line in lines)
