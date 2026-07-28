"""Regression coverage for compositional read-only developer commands."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

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


def _create_local_branch(repository: Path, branch: str) -> None:
    commit = subprocess.run(
        ["git", "-C", str(repository), "hash-object", "-t", "commit", "-w", "--stdin"],
        input=(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
            "author Guard Test <guard@example.invalid> 0 +0000\n"
            "committer Guard Test <guard@example.invalid> 0 +0000\n\n"
            "initial\n"
        ),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", str(repository), "update-ref", f"refs/heads/{branch}", commit], check=True)


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


def test_compound_inspection_uses_current_repository_without_redundant_cd(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    command = 'pwd; git status --short --branch; sed -n "1,5p" ui.tsx'

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


def test_static_marker_and_trusted_git_version_are_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)

    assert _is_benign(
        "printf 'guard-request-ok\\n' && git --version",
        home_dir=home_dir,
        repository=repository,
    )


def test_existing_local_branch_switch_without_execution_hooks_is_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    _create_local_branch(repository, "main")

    assert _is_benign("git checkout main", home_dir=home_dir, repository=repository)
    assert _is_benign(f"cd {repository} && git switch main", home_dir=home_dir, repository=repository)


def test_git_branch_switch_with_checkout_hook_is_not_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    _create_local_branch(repository, "main")
    subprocess.run(
        ["git", "-C", str(repository), "config", "core.hooksPath", ".git/hooks"],
        check=True,
    )
    hook = repository / ".git" / "hooks" / "post-checkout"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o755)

    assert not _is_benign("git checkout main", home_dir=home_dir, repository=repository)


def test_git_branch_switch_with_custom_filter_is_not_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    _create_local_branch(repository, "main")
    subprocess.run(
        ["git", "-C", str(repository), "config", "filter.untrusted.smudge", "sh payload.sh"],
        check=True,
    )

    assert not _is_benign("git checkout main", home_dir=home_dir, repository=repository)


def test_git_path_checkout_is_not_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)

    assert not _is_benign("git checkout -- ui.tsx", home_dir=home_dir, repository=repository)


def test_active_guard_version_is_explicitly_benign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home_dir, repository = _repository(tmp_path)
    managed_guard = Path(sys.prefix) / ("Scripts" if sys.platform == "win32" else "bin") / "hol-guard"
    if not managed_guard.exists():
        pytest.skip("active test environment does not expose the hol-guard entry point")
    monkeypatch.setenv("PATH", f"{managed_guard.parent}:{os.environ.get('PATH', '')}")

    assert _is_benign("hol-guard --version", home_dir=home_dir, repository=repository)


def test_shadowed_guard_version_is_not_explicitly_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir, repository = _repository(tmp_path)
    shadow_bin = tmp_path / "shadow-bin"
    shadow_bin.mkdir()
    shadow_guard = shadow_bin / "hol-guard"
    shadow_guard.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow_guard.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shadow_bin}:{os.environ.get('PATH', '')}")

    assert not _is_benign("hol-guard --version", home_dir=home_dir, repository=repository)


@pytest.mark.parametrize(
    "command",
    (
        "pwd; git status --short --branch; rm -rf build",
        "pwd; git status --short --branch; cat .env",
        "pwd; git status --short --branch; ls $(printf ui.tsx)",
        "pwd; git status --short --branch; ls ../../outside",
        "pwd; git status --short --branch; grep export ../../outside",
    ),
)
def test_compound_current_repository_rejects_sensitive_or_dynamic_segments(
    tmp_path: Path,
    command: str,
) -> None:
    home_dir, repository = _repository(tmp_path)

    assert not _is_benign(command, home_dir=home_dir, repository=repository)


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
