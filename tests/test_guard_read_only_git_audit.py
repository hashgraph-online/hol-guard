"""Regression coverage for bounded read-only Git ancestry audits."""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

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


@pytest.mark.parametrize(
    ("replacement", "status", "minimum_action"),
    (
        # Literal loops now carry the unrolled model's status. Unsafe variants
        # remain at the review floor, but are modeled as "review" rather than
        # returning the old unmodeled "no_match" status.
        ("git checkout --detach $commit", "review", "review"),
        ("git merge-base --is-ancestor $commit HEAD && cat .env", "review", "review"),
        # A substitution in argument position runs a program the text names,
        # so it reaches the unmodeled review floor instead of an evaluation
        # failure. It still cannot pass silently.
        ("git merge-base --is-ancestor $(payload) HEAD", "no_match", "review"),
    ),
)
def test_widened_ancestry_loop_remains_sensitive(
    tmp_path: Path, replacement: str, status: str, minimum_action: str
) -> None:
    home, repository = _repository(tmp_path)
    command = _audit(repository).replace("git merge-base --is-ancestor $commit HEAD", replacement)

    result = inspect_command(command, cwd=home, home_dir=home)
    assert _classification(result)["explicitly_benign"] is False
    assert result["status"] == status
    assert result["minimum_action"] == minimum_action
