from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_git_execution_safety
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact(command: str, *, home: Path) -> GuardArtifact | None:
    return _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=None,
    )


def _init_repository(path: Path) -> None:
    _ = subprocess.run(
        ["git", "init", "--quiet", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )


def _init_push_repository(path: Path, *, branch: str = "fix/about-partners-link") -> None:
    _ = subprocess.run(
        ["git", "init", "--quiet", "--initial-branch", branch, str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "remote",
            "add",
            "origin",
            "https://github.com/example/project.git",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_compound_current_branch_push_to_verified_origin_is_routine(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is None


@pytest.mark.parametrize(
    "push",
    (
        "git push --force -u origin fix/about-partners-link",
        "git push -u origin fix/other-branch",
        "git push -u upstream fix/about-partners-link",
        "git push origin --delete fix/about-partners-link",
        "git push -u origin fix/about-partners-link:main",
    ),
)
def test_compound_push_keeps_widened_or_mismatched_operations_guarded(
    tmp_path: Path,
    push: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)

    assert _artifact(f"cd {workspace} && {push} 2>&1 | tail -2", home=home) is not None


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("remote.origin.push", "refs/heads/main:refs/heads/main"),
        ("remote.origin.pushurl", "https://github.com/example/other.git"),
        ("remote.origin.receivepack", "./payload"),
        ("remote.origin.vcs", "payload"),
        ("remote.origin.mirror", "true"),
        ("remote.pushDefault", "upstream"),
        ("branch.fix/about-partners-link.pushRemote", "upstream"),
        ("url.https://example.invalid/.pushInsteadOf", "https://github.com/"),
        ("push.gpgSign", "true"),
        ("push.recurseSubmodules", "on-demand"),
        ("push.followTags", "true"),
        ("hook.guard.command", "./payload"),
        ("core.gitProxy", "proxy-command"),
        ("http.proxy", "https://example.invalid"),
        ("http.sslVerify", "false"),
        ("http.sslVersion", "sslv3"),
        ("http.sslCipherList", "insecure"),
        ("credential.helper", "!payload"),
    ),
)
def test_compound_push_rejects_repository_execution_or_routing_config(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)
    _ = subprocess.run(
        ["git", "-C", str(workspace), "config", key, value],
        check=True,
        capture_output=True,
        text=True,
    )

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


def test_compound_push_rejects_executable_pre_push_hook(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)
    _ = subprocess.run(
        ["git", "-C", str(workspace), "config", "core.hooksPath", "hooks"],
        check=True,
        capture_output=True,
        text=True,
    )
    hook = workspace / "hooks" / "pre-push"
    hook.parent.mkdir()
    _ = hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = hook.chmod(hook.stat().st_mode | 0o100)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


def test_compound_push_rejects_symlinked_repository_pre_push_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(native_git_execution_safety, "_account_home_directory", lambda: str(home))
    _ = (home / ".gitconfig").write_text("[core]\n\thooksPath = .git/hooks\n", encoding="utf-8")
    _init_push_repository(workspace)
    payload = home / "payload"
    _ = payload.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = payload.chmod(0o700)
    (workspace / ".git" / "hooks" / "pre-push").symlink_to(payload)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


def test_compound_push_rejects_repository_configured_external_hook(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    external_hooks = home / "hooks"
    workspace.mkdir(parents=True)
    external_hooks.mkdir()
    _init_push_repository(workspace)
    _ = subprocess.run(
        ["git", "-C", str(workspace), "config", "core.hooksPath", str(external_hooks)],
        check=True,
        capture_output=True,
        text=True,
    )
    hook = external_hooks / "pre-push"
    _ = hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = hook.chmod(hook.stat().st_mode | 0o100)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


def test_compound_push_rejects_worktree_configured_external_hook(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    external_hooks = home / "hooks"
    workspace.mkdir(parents=True)
    external_hooks.mkdir()
    _init_push_repository(workspace)
    for key, value in (
        ("extensions.worktreeConfig", "true"),
        ("core.hooksPath", str(external_hooks)),
    ):
        scope = "--local" if key == "extensions.worktreeConfig" else "--worktree"
        _ = subprocess.run(
            ["git", "-C", str(workspace), "config", scope, key, value],
            check=True,
            capture_output=True,
            text=True,
        )
    hook = external_hooks / "pre-push"
    _ = hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = hook.chmod(hook.stat().st_mode | 0o100)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


def test_compound_push_rejects_redirected_global_pre_push_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    hooks = home / "global-hooks"
    workspace.mkdir(parents=True)
    hooks.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    _ = (home / ".gitconfig").write_text(
        f"[core]\n\thooksPath = {hooks}\n",
        encoding="utf-8",
    )
    hook = hooks / "pre-push"
    _ = hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = hook.chmod(hook.stat().st_mode | 0o100)
    _init_push_repository(workspace)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


def test_compound_push_rejects_multiple_origin_urls(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "config",
            "--add",
            "remote.origin.url",
            "https://github.com/example/other.git",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


@pytest.mark.parametrize(
    "variable",
    (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_SSL_NO_VERIFY",
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "GIT_SSL_VERSION",
    ),
)
def test_compound_push_rejects_repository_routing_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)
    monkeypatch.setenv(variable, "redirected")

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _artifact(command, home=home) is not None


def test_compound_git_refresh_and_inspection_is_evaluated_as_one_unit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    repository = workspace / "repository"
    repository.mkdir(parents=True)
    _init_repository(repository)
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/project.git",
        ],
        check=True,
    )

    command = " ".join(
        (
            f"cd {workspace} && git -C repository fetch origin main 2>&1 | tail -5",
            '&& echo "---ORIGIN---" && git -C repository log origin/main -1 --oneline',
            '&& echo "---STATUS---" && git -C repository status --short | head -20',
        )
    )
    artifact = _artifact(command, home=home)

    assert artifact is None


@pytest.mark.parametrize(
    "log_args",
    ("-5 --oneline", "--oneline -20 origin/main", "origin/main -1 --oneline"),
)
def test_compound_git_inspection_accepts_bounded_log_forms(tmp_path: Path, log_args: str) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)

    assert _artifact(f"cd {workspace} && git log {log_args}", home=home) is None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show origin/main:public/example.txt | head -20",
        "git diff origin/main -- public/example.txt | head -20",
    ),
)
def test_compound_git_inspection_accepts_safe_revision_paths(tmp_path: Path, inspection: str) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    (workspace / "public").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && {inspection}", home=home) is None


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_cross_workspace_git_show_accepts_bounded_revision_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness=harness,
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": (f"cd {inspected_workspace} && git show b56514561 -- workers/services/ 2>&1 | head -60")
            },
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show b56514561 -- ../outside | head -60",
        "git show b56514561 -- .env | head -60",
        "git show $REVISION -- workers/services/ | head -60",
        "git show b56514561 --ext-diff -- workers/services/ | head -60",
        "git show b56514561 --textconv -- workers/services/ | head -60",
        "git show b56514561 -- workers/services/ | sh",
        "git show b56514561 -- workers/services/ > report.txt",
    ),
)
def test_cross_workspace_git_show_keeps_unsafe_variants_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"cd {inspected_workspace} && {inspection}"},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is not None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show HEAD",
        "git show b56514561 -- workers/services/ 2>&1 | head -60",
    ),
)
def test_cross_workspace_git_show_rejects_configured_textconv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    _ = (inspected_workspace / ".git" / "config").write_text(
        '[diff "guard"]\n    textconv = helper\n',
        encoding="utf-8",
    )
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"cd {inspected_workspace} && {inspection}"},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is not None


def test_cross_workspace_git_show_rejects_textconv_in_git_c_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    repositories = home / "projects" / "repositories"
    inspected_workspace = repositories / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    _ = (inspected_workspace / ".git" / "config").write_text(
        '[diff "guard"]\n    textconv = helper\n',
        encoding="utf-8",
    )
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": (
                    f"cd {repositories} && git -C inspected show b56514561 -- workers/services/ 2>&1 | head -60"
                )
            },
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is not None


@pytest.mark.parametrize(
    "inspection",
    (
        "git status --short",
        "git log -1 --oneline",
        "git show HEAD",
    ),
)
def test_compound_git_inspection_rejects_path_shadowed_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    _init_repository(workspace)
    shadow_bin = workspace / "bin"
    shadow_bin.mkdir()
    shadow_git = shadow_bin / "git"
    _ = shadow_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shadow_bin}:{os.environ.get('PATH', '')}")

    assert _artifact(f"cd {workspace} && {inspection}", home=home) is not None


@pytest.mark.parametrize(
    "key",
    (
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
    ),
)
def test_compound_git_inspection_rejects_config_routing_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    _init_repository(workspace)
    monkeypatch.setenv(key, "1")

    assert _artifact(f"cd {workspace} && git show HEAD", home=home) is not None


def test_compound_git_c_status_checks_target_repository_fsmonitor(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    repository = workspace / "repository"
    _init_repository(repository)
    _ = subprocess.run(
        ["git", "-C", str(repository), "config", "core.fsmonitor", "./payload"],
        check=True,
        capture_output=True,
    )

    assert _artifact(f"cd {workspace} && git -C repository status --short", home=home) is not None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show origin/main:../settings.txt",
        "git show origin/main:/settings.txt",
        "git diff origin/main -- ../settings.txt",
        "git diff origin/main -- /settings.txt",
    ),
)
def test_compound_git_inspection_rejects_escaping_revision_paths(tmp_path: Path, inspection: str) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)

    assert _artifact(f"cd {workspace} && {inspection}", home=home) is not None


@pytest.mark.parametrize("repository", ("projects/repository", "./projects/repository", "."))
def test_compound_git_inspection_accepts_bounded_relative_repository_paths(
    tmp_path: Path,
    repository: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    (workspace / "projects" / "repository").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && git -C {repository} status --short | head -20", home=home) is None


@pytest.mark.parametrize(
    "suffix",
    (
        "git -C repository push origin main",
        "git -C repository reset --hard origin/main",
        "git -C repository fetch origin main:refs/heads/main",
        "git -C ../outside fetch origin main",
        "git -C projects/../../outside status --short",
        "git -C /outside status --short",
        "git -C ~/outside status --short",
        "git -C projects/$TARGET status --short",
        "git -C repository status --short | sh",
        "git -C repository status --short > report.txt",
        "git log -101 --oneline",
        "git log --all --oneline -5",
    ),
)
def test_compound_git_recovery_keeps_ambiguous_or_mutating_commands_guarded(
    tmp_path: Path,
    suffix: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && {suffix}", home=home) is not None


def test_compound_git_recovery_rejects_dynamic_or_preceding_execution(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _artifact("cd $TARGET && git -C repository fetch origin main", home=home) is not None
    assert (
        _artifact(
            f"printf ready && cd {workspace} && git -C repository status --short",
            home=home,
        )
        is not None
    )
