"""Regression coverage for bounded read-only Git ancestry audits."""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.read_only_git_audit import is_read_only_git_ancestry_audit
from tests.git_execution_test_support import assert_host_git_proof_result
from tests.native_command_test_support import inspect_command_native_test as inspect_command

_GIT_ROUTING_ENV = (
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_NAMESPACE",
    "GIT_WORK_TREE",
)


@pytest.fixture(autouse=True)
def _clear_git_routing_environment(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable in _GIT_ROUTING_ENV:
        monkeypatch.delenv(variable, raising=False)


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    repository = home / "project"
    _ = repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init"], cwd=repository, check=True, capture_output=True)
    return home, repository


def _audit(repository: Path, *, loop_variable: str = "commit", suffix: str = "") -> str:
    return (
        f"cd {shlex.quote(repository.as_posix())} && for {loop_variable} in deadbee cafebabe; do "
        f"git merge-base --is-ancestor ${loop_variable} HEAD 2>/dev/null && "
        f'echo "${loop_variable} YES" || echo "${loop_variable} NO"; done'
        f"{suffix}"
    )


def _classification(result: Mapping[str, object]) -> Mapping[str, object]:
    return cast(Mapping[str, object], result["classification"])


def test_host_ancestry_audit_proof_does_not_override_native_unsupported_loop(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    command = _audit(repository)

    assert_host_git_proof_result(is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home), cwd=repository)
    result = inspect_command(command, cwd=home, home_dir=home)
    # Supported hosts recognize this bounded audit. Native command parsing does not
    # support its loop, so production must keep its terminal classification.
    assert _classification(result)["explicitly_benign"] is False
    assert result["status"] == "native_unavailable"
    assert result["minimum_action"] == "block"


def test_ancestry_audit_rejects_path_as_loop_variable(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    command = _audit(repository, loop_variable="PATH")

    assert not is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home)


def test_ancestry_audit_allows_bounded_log_and_numeric_pid_read(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    lock = repository / ".deploy.lock.d" / "pid"
    _ = lock.parent.mkdir()
    _ = lock.write_text("1234\n", encoding="utf-8")
    command = _audit(
        repository,
        suffix='; echo "HEAD"; git log -1 --oneline; echo "LOCK"; cat .deploy.lock.d/pid 2>/dev/null || echo "none"',
    )

    assert_host_git_proof_result(is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home), cwd=repository)
    result = inspect_command(command, cwd=home, home_dir=home)
    assert _classification(result)["explicitly_benign"] is False
    assert result["status"] == "native_unavailable"
    assert result["minimum_action"] == "block"


def test_ancestry_audit_rejects_workspace_outside_home_and_cwd(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cwd = tmp_path / "current"
    repository = tmp_path / "unrelated" / "project"
    home.mkdir()
    cwd.mkdir()
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init"], cwd=repository, check=True, capture_output=True)

    assert not is_read_only_git_ancestry_audit(_audit(repository), cwd=cwd, home_dir=home)


def test_ancestry_audit_allows_structured_status_substitutions(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    command = _audit(
        repository,
        suffix=(
            '; echo "HEAD: $(git log -1 --oneline)"; '
            'if [ -f .deploy.lock.d/pid ]; then echo "LOCK: $(cat .deploy.lock.d/pid)"; '
            'else echo "no lock"; fi'
        ),
    )

    assert_host_git_proof_result(is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home), cwd=repository)
    result = inspect_command(command, cwd=home, home_dir=home)
    assert _classification(result)["explicitly_benign"] is False
    assert result["status"] == "native_unavailable"
    assert result["minimum_action"] == "block"


@pytest.mark.parametrize(
    "variant",
    (
        "mutating-prefix",
        "dynamic-commit",
        "widened-target",
        "output-write",
        "dynamic-echo",
        "network-suffix",
    ),
)
def test_ancestry_audit_rejects_widened_or_mutating_forms(
    tmp_path: Path,
    variant: str,
) -> None:
    home, repository = _repository(tmp_path)
    base = _audit(repository)
    variants = {
        "mutating-prefix": f"cd {shlex.quote(repository.as_posix())} && git checkout main; " + base.split(" && ", 1)[1],
        "dynamic-commit": base.replace("deadbee", "$(payload)"),
        "widened-target": base.replace("$commit HEAD", "$commit --all"),
        "output-write": base.replace("2>/dev/null", "> result.txt"),
        "dynamic-echo": base.replace('echo "$commit YES"', 'echo "$(payload)"'),
        "network-suffix": base + "; curl https://example.com",
    }
    command = variants[variant]

    assert not is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home)


def test_ancestry_audit_rejects_non_numeric_or_symlinked_status_file(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    lock = repository / ".deploy.lock.d" / "pid"
    _ = lock.parent.mkdir()
    _ = lock.write_text("secret-value\n", encoding="utf-8")
    command = _audit(repository, suffix="; git log -1 --oneline; cat .deploy.lock.d/pid 2>/dev/null || echo none")

    assert not is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home)
    _ = lock.unlink()
    _ = lock.symlink_to(repository / ".git" / "config")
    assert not is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home)


def test_ancestry_audit_never_reads_arbitrary_numeric_file(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    arbitrary = repository / "secrets" / "pid"
    _ = arbitrary.parent.mkdir()
    _ = arbitrary.write_text("1234\n", encoding="utf-8")
    command = _audit(repository, suffix="; git log -1 --oneline; cat secrets/pid 2>/dev/null || echo none")

    assert not is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home)


@pytest.mark.parametrize(
    "replacement",
    (
        "git checkout --detach $commit",
        "git merge-base --is-ancestor $(payload) HEAD",
        "git merge-base --is-ancestor $commit HEAD && cat .env",
    ),
)
def test_widened_ancestry_loop_remains_sensitive(tmp_path: Path, replacement: str) -> None:
    home, repository = _repository(tmp_path)
    command = _audit(repository).replace("git merge-base --is-ancestor $commit HEAD", replacement)

    result = inspect_command(command, cwd=home, home_dir=home)
    assert _classification(result)["explicitly_benign"] is False
    assert result["status"] == "native_unavailable"
    assert result["minimum_action"] == "block"


def test_ancestry_audit_rejects_executable_log_pager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, repository = _repository(tmp_path)
    monkeypatch.delenv("GIT_PAGER", raising=False)
    monkeypatch.delenv("PAGER", raising=False)
    _ = subprocess.run(["git", "config", "pager.log", "!payload"], cwd=repository, check=True)
    command = _audit(repository, suffix="; git log -1 --oneline; cat .deploy.lock.d/pid 2>/dev/null || echo none")

    assert not is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home)


def test_git_pager_override_ignores_fallback_pager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, repository = _repository(tmp_path)
    monkeypatch.setenv("GIT_PAGER", "cat")
    monkeypatch.setenv("PAGER", "payload")
    _ = subprocess.run(["git", "config", "pager.log", "!payload"], cwd=repository, check=True)
    command = _audit(repository, suffix="; git log -1 --oneline; cat .deploy.lock.d/pid 2>/dev/null || echo none")

    assert_host_git_proof_result(is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home), cwd=repository)


def test_git_pager_override_still_rejects_executable_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, repository = _repository(tmp_path)
    monkeypatch.setenv("GIT_PAGER", "payload")
    monkeypatch.setenv("PAGER", "cat")
    command = _audit(repository, suffix="; git log -1 --oneline; cat .deploy.lock.d/pid 2>/dev/null || echo none")

    assert not is_read_only_git_ancestry_audit(command, cwd=home, home_dir=home)
