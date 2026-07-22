"""Regression coverage for compositional read-only developer commands."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_generic import _should_relax_configured_default
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    home_dir = tmp_path / "home"
    repository = home_dir / "projects" / "example"
    repository.mkdir(parents=True)
    (repository / "ui.tsx").write_text("export {};\n", encoding="utf-8")
    (repository / "health.py").write_text("pass\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    return home_dir, repository


def _is_benign(command: str, *, home_dir: Path, repository: Path) -> bool:
    return is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=repository,
        home_dir=home_dir,
    )


def test_compound_git_metadata_and_file_listing_is_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    command = f"cd {repository} && git status -sb && git log -1 --oneline && ls ui.tsx health.py 2>/dev/null"

    assert _is_benign(command, home_dir=home_dir, repository=repository)
    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=repository,
            home_dir=home_dir,
        )
        is None
    )
    assert _should_relax_configured_default(
        configured_action="require-reapproval",
        has_narrow_override=False,
        home_dir=home_dir,
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}},
        runtime_workspace=repository,
    )


def test_multiline_read_only_inspection_is_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    command = (
        f"cd {repository}\n"
        "rg -n 'export' ui.tsx | head -20\n"
        "ls ui.tsx health.py 2>/dev/null; echo 'inspection complete'"
    )

    assert _is_benign(command, home_dir=home_dir, repository=repository)
    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=repository,
            home_dir=home_dir,
        )
        is None
    )


@pytest.mark.parametrize(
    "suffix",
    (
        "git status -sb && git push",
        "git log --all --oneline && ls ui.tsx",
        "git log -1 --oneline && cat .env",
        "git log -1 --oneline && ls ../../outside",
        "git log -1 --oneline && ls ui.tsx > report.txt",
        "git log -1 --oneline && ls $(printf ui.tsx)",
        "git log -1 --oneline || cat .env",
        "git log -1 --oneline; rm -rf build",
    ),
)
def test_compound_inspection_rejects_unbounded_dynamic_or_mutating_variants(
    tmp_path: Path,
    suffix: str,
) -> None:
    home_dir, repository = _repository(tmp_path)

    assert not _is_benign(
        f"cd {repository} && {suffix}",
        home_dir=home_dir,
        repository=repository,
    )


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("core.fsmonitor", "./payload"),
        ("core.pager", "./payload"),
        ("pager.log", "./payload"),
    ),
)
def test_compound_git_inspection_rejects_executable_git_config(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    home_dir, repository = _repository(tmp_path)
    subprocess.run(["git", "-C", str(repository), "config", key, value], check=True)

    assert not _is_benign(
        f"cd {repository} && git status -sb && git log -1 --oneline && ls ui.tsx",
        home_dir=home_dir,
        repository=repository,
    )


def test_bounded_wait_with_static_completion_marker_is_benign(tmp_path: Path) -> None:
    command = "perl -e 'sleep 240' && echo WAIT_DONE"

    assert _is_benign(command, home_dir=tmp_path, repository=tmp_path)
    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


@pytest.mark.parametrize(
    "command",
    (
        "perl -e 'sleep 240' && rm -rf build",
        "perl -e 'system(\"touch marker\")' && echo WAIT_DONE",
        "perl -e 'sleep 240' || echo WAIT_DONE",
        "perl -e 'sleep 240' && echo $(whoami)",
    ),
)
def test_wait_chain_rejects_dynamic_or_mutating_continuations(tmp_path: Path, command: str) -> None:
    assert not _is_benign(command, home_dir=tmp_path, repository=tmp_path)
