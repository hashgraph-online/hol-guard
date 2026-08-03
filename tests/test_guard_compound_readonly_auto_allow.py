"""Regression coverage for compositional read-only developer commands."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import secret_file_requests
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


@pytest.fixture(autouse=True)
def _trust_system_ln_precondition(monkeypatch: pytest.MonkeyPatch) -> None:
    original = secret_file_requests.is_trusted_absolute_command_path
    discovered = shutil.which("ln")
    system_ln = Path(discovered).resolve(strict=True) if discovered is not None else None

    def trust_system_ln(path: Path, *, cwd: Path | None, home_dir: Path | None) -> bool:
        if system_ln is not None and path.resolve(strict=False) == system_ln:
            return True
        return original(path, cwd=cwd, home_dir=home_dir)

    monkeypatch.setattr(
        secret_file_requests,
        "is_trusted_absolute_command_path",
        trust_system_ln,
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


def test_find_exec_ls_inventory_is_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    modules = repository / "node_modules"
    (modules / "example").mkdir(parents=True)
    command = "find node_modules -maxdepth 1 -mindepth 1 -print -exec ls -ld {} \\;"

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


def test_find_exec_ls_inventory_rejects_path_shadowing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir, repository = _repository(tmp_path)
    modules = repository / "node_modules"
    (modules / "example").mkdir(parents=True)
    attacker_bin = home_dir / "bin"
    attacker_bin.mkdir()
    fake_ls = attacker_bin / "ls"
    fake_ls.write_text("#!/bin/sh\ntouch compromised\n", encoding="utf-8")
    fake_ls.chmod(0o755)
    system_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{attacker_bin}{os.pathsep}{system_path}")
    command = "find node_modules -maxdepth 1 -mindepth 1 -print -exec ls -ld {} \\;"

    assert not _is_benign(command, home_dir=home_dir, repository=repository)
    monkeypatch.setenv("PATH", system_path)
    assert not _is_benign(
        f"PATH={attacker_bin} {command}",
        home_dir=home_dir,
        repository=repository,
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


def test_workspace_dependency_symlink_is_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    dependency_modules = dependency_project / "node_modules"
    dependency_modules.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    command = f'cd {repository} && ln -s {dependency_modules} ./node_modules 2>/dev/null; echo "linked"'

    assert _is_benign(command, home_dir=home_dir, repository=repository)


@pytest.mark.parametrize(
    "suffix",
    (
        "",
        " 2>/dev/null",
        " 2>/dev/null; echo linked",
    ),
)
def test_workspace_dependency_symlink_directory_destination_is_explicitly_benign(
    tmp_path: Path,
    suffix: str,
) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    dependency_modules = dependency_project / "node_modules"
    dependency_modules.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    command = f"cd {repository} && ln -s {dependency_modules} .{suffix}"

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
    "source_kind",
    ("arbitrary-directory", "secret-file", "symlinked-modules", "missing-modules", "outside-home"),
)
@pytest.mark.parametrize("destination", (".", "./node_modules"))
def test_workspace_dependency_symlink_rejects_untrusted_sources(
    tmp_path: Path,
    source_kind: str,
    destination: str,
) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    dependency_project.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    source = dependency_project / "node_modules"
    if source_kind == "arbitrary-directory":
        source = dependency_project / "build"
        source.mkdir()
    elif source_kind == "secret-file":
        source = dependency_project / ".env"
        source.write_text("TOKEN=fixture\n", encoding="utf-8")
    elif source_kind == "symlinked-modules":
        real_modules = dependency_project / "real-modules"
        real_modules.mkdir()
        source.symlink_to(real_modules, target_is_directory=True)
    elif source_kind == "outside-home":
        outside_project = tmp_path / "outside-home"
        source = outside_project / "node_modules"
        source.mkdir(parents=True)
        (outside_project / "package.json").write_text("{}\n", encoding="utf-8")
    command = f"cd {repository} && ln -s {source} {destination} 2>/dev/null; echo linked"

    assert not _is_benign(command, home_dir=home_dir, repository=repository)


@pytest.mark.parametrize(
    "command_template",
    (
        "cd {repository} && ln -sf {source} ./node_modules 2>/dev/null; echo linked",
        "cd {repository} && ln -s {source} ./vendor 2>/dev/null; echo linked",
        "cd {repository} && ln -s {source} ./node_modules 2>/dev/null; echo done",
        "cd {repository} && ln -s {source} ./node_modules && echo payload > node_modules/changed.txt",
    ),
)
def test_workspace_dependency_symlink_rejects_widened_effects(
    tmp_path: Path,
    command_template: str,
) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    source = dependency_project / "node_modules"
    source.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    command = command_template.format(repository=repository, source=source)

    assert not _is_benign(command, home_dir=home_dir, repository=repository)


@pytest.mark.parametrize(
    "command_template",
    (
        "cd {repository} && ln -sf {source} .",
        "cd {repository} && ln --force -s {source} .",
        "cd {repository} && ln -s $DEPENDENCY_MODULES .",
        "cd {repository} && ln -s {source} $DESTINATION",
        "cd {repository} && ln -s {source} ..",
        "cd {repository} && ln -s {source} .; echo done",
        "cd {repository} && ln -s {source} . && echo payload > node_modules/changed.txt",
    ),
)
def test_workspace_dependency_symlink_directory_destination_rejects_widened_effects(
    tmp_path: Path,
    command_template: str,
) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    source = dependency_project / "node_modules"
    source.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    command = command_template.format(repository=repository, source=source)

    assert not _is_benign(command, home_dir=home_dir, repository=repository)


def test_workspace_dependency_symlink_rejects_existing_destination(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    source = dependency_project / "node_modules"
    source.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    (repository / "node_modules").mkdir()
    command = f"cd {repository} && ln -s {source} ./node_modules 2>/dev/null; echo linked"

    assert not _is_benign(command, home_dir=home_dir, repository=repository)


def test_workspace_dependency_symlink_directory_destination_rejects_existing_destination(
    tmp_path: Path,
) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    source = dependency_project / "node_modules"
    source.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    (repository / "node_modules").mkdir()
    command = f"cd {repository} && ln -s {source} ."

    assert not _is_benign(command, home_dir=home_dir, repository=repository)


@pytest.mark.parametrize("destination", (".", "./node_modules"))
def test_workspace_dependency_symlink_rejects_shadowed_ln(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    destination: str,
) -> None:
    home_dir, repository = _repository(tmp_path)
    dependency_project = home_dir / "projects" / "dependency-source"
    source = dependency_project / "node_modules"
    source.mkdir(parents=True)
    (dependency_project / "package.json").write_text("{}\n", encoding="utf-8")
    shadow_bin = home_dir / "bin"
    shadow_bin.mkdir()
    shadow_ln = shadow_bin / "ln"
    shadow_ln.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow_ln.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shadow_bin}:{os.environ.get('PATH', '')}")
    command = f"cd {repository} && ln -s {source} {destination} 2>/dev/null; echo linked"

    assert not _is_benign(command, home_dir=home_dir, repository=repository)


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


def test_git_branch_switch_with_fsmonitor_program_is_not_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    _create_local_branch(repository, "main")
    subprocess.run(
        ["git", "-C", str(repository), "config", "core.fsmonitor", "sh payload.sh"],
        check=True,
    )

    assert not _is_benign("git checkout main", home_dir=home_dir, repository=repository)


def test_git_branch_switch_with_tracked_hook_directory_is_not_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    _create_local_branch(repository, "main")
    subprocess.run(
        ["git", "-C", str(repository), "config", "core.hooksPath", ".githooks"],
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


def test_relative_path_entry_resolves_from_segment_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir, repository = _repository(tmp_path)
    shadow_dir = repository / "shadow"
    shadow_dir.mkdir()
    shadow_git = shadow_dir / "git"
    shadow_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow_git.chmod(0o755)
    monkeypatch.setenv("PATH", f".:{os.environ.get('PATH', '')}")

    assert not _is_benign(f"cd {shadow_dir} && git --version", home_dir=home_dir, repository=repository)


@pytest.mark.parametrize(
    "command",
    (
        "git checkout main &",
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
