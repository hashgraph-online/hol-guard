from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_git_execution_safety
from tests.live_hook_review_support import (
    LIVE_ALLOWS_RETIRED_REVIEW,
    LIVE_REVIEWS_RETIRED_ALLOW,
    live_allows_retired_review_on,
    live_reviews_retired_allow_on,
    live_shell_review,
    quietly_allowed,
)


def _reviewed(
    command: str,
    *,
    home: Path,
    harness: str = "pi",
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, object] | None:
    """The live hook answer when it reviews ``command``, or None when it allows it quietly."""

    if cwd is None:
        cwd = home / "projects" / "current"
        cwd.mkdir(parents=True, exist_ok=True)
    result = live_shell_review(
        command, home_dir=home, cwd=cwd, harness=harness, tool_name="Bash", environment=environment
    )
    return None if quietly_allowed(result) else result


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


@LIVE_REVIEWS_RETIRED_ALLOW
def test_compound_current_branch_push_to_verified_origin_is_routine(
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    # Routine push needs global Git config to belong to the account running Git.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(native_git_execution_safety, "_account_home_directory", lambda: str(home))
    _init_push_repository(workspace)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _reviewed(command, home=home) is None


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
    live_hook_root: Path,
    push: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)

    assert _reviewed(f"cd {workspace} && {push} 2>&1 | tail -2", home=home) is not None


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
    live_hook_root: Path,
    key: str,
    value: str,
) -> None:
    home = live_hook_root / "home"
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

    assert _reviewed(command, home=home) is not None


def test_compound_push_rejects_executable_pre_push_hook(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
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

    assert _reviewed(command, home=home) is not None


def test_compound_push_rejects_symlinked_repository_pre_push_hook(
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = live_hook_root / "home"
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

    assert _reviewed(command, home=home) is not None


def test_compound_push_rejects_repository_configured_external_hook(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
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

    assert _reviewed(command, home=home) is not None


def test_compound_push_rejects_worktree_configured_external_hook(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
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

    assert _reviewed(command, home=home) is not None


def test_compound_push_rejects_redirected_global_pre_push_hook(
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = live_hook_root / "home"
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

    assert _reviewed(command, home=home) is not None


def test_compound_push_rejects_multiple_origin_urls(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
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

    assert _reviewed(command, home=home) is not None


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
    live_hook_root: Path,
    variable: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "hol-guard-partners-fix"
    workspace.mkdir(parents=True)
    _init_push_repository(workspace)

    command = f"cd {workspace} && git push -u origin fix/about-partners-link 2>&1 | tail -2"

    assert _reviewed(command, home=home, environment={variable: "redirected"}) is not None


@LIVE_REVIEWS_RETIRED_ALLOW
def test_compound_git_refresh_and_inspection_is_evaluated_as_one_unit(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
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
    artifact = _reviewed(command, home=home)

    assert artifact is None


@pytest.mark.parametrize(
    "log_args",
    ("-5 --oneline", "--oneline -20 origin/main", "origin/main -1 --oneline"),
)
def test_compound_git_inspection_accepts_bounded_log_forms(live_hook_root: Path, log_args: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)

    assert _reviewed(f"cd {workspace} && git log {log_args}", home=home) is None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show origin/main:public/example.txt | head -20",
        pytest.param(
            "git diff origin/main -- public/example.txt | head -20", marks=live_reviews_retired_allow_on("linux")
        ),
    ),
)
def test_compound_git_inspection_accepts_safe_revision_paths(live_hook_root: Path, inspection: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    (workspace / "public").mkdir(parents=True)

    assert _reviewed(f"cd {workspace} && {inspection}", home=home) is None


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_cross_workspace_git_show_accepts_bounded_revision_directory(
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _reviewed(
        f"cd {inspected_workspace} && git show b56514561 -- workers/services/ 2>&1 | head -60",
        home=home,
        harness=harness,
        cwd=active_workspace,
    )

    assert artifact is None


@pytest.mark.parametrize(
    "inspection",
    (
        pytest.param("git show b56514561 -- ../outside | head -60", marks=LIVE_ALLOWS_RETIRED_REVIEW),
        "git show b56514561 -- .env | head -60",
        pytest.param("git show $REVISION -- workers/services/ | head -60", marks=LIVE_ALLOWS_RETIRED_REVIEW),
        "git show b56514561 --ext-diff -- workers/services/ | head -60",
        "git show b56514561 --textconv -- workers/services/ | head -60",
        "git show b56514561 -- workers/services/ | sh",
        "git show b56514561 -- workers/services/ > report.txt",
    ),
)
def test_cross_workspace_git_show_keeps_unsafe_variants_guarded(
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _reviewed(
        f"cd {inspected_workspace} && {inspection}",
        home=home,
        harness="pi",
        cwd=active_workspace,
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
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    _ = (inspected_workspace / ".git" / "config").write_text(
        '[diff "guard"]\n    textconv = helper\n',
        encoding="utf-8",
    )
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _reviewed(
        f"cd {inspected_workspace} && {inspection}",
        home=home,
        harness="pi",
        cwd=active_workspace,
    )

    assert artifact is not None


def test_cross_workspace_git_show_rejects_textconv_in_git_c_target(
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = live_hook_root / "home"
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

    artifact = _reviewed(
        f"cd {repositories} && git -C inspected show b56514561 -- workers/services/ 2>&1 | head -60",
        home=home,
        harness="pi",
        cwd=active_workspace,
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
    live_hook_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    _init_repository(workspace)
    shadow_bin = workspace / "bin"
    shadow_bin.mkdir()
    shadow_git = shadow_bin / "git"
    _ = shadow_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shadow_bin}:{os.environ.get('PATH', '')}")

    assert _reviewed(f"cd {workspace} && {inspection}", home=home) is not None


@pytest.mark.parametrize(
    "key",
    (
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        pytest.param("GIT_CONFIG_NOSYSTEM", marks=LIVE_ALLOWS_RETIRED_REVIEW),
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
    ),
)
def test_compound_git_inspection_rejects_config_routing_environment(
    live_hook_root: Path,
    key: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    _init_repository(workspace)
    assert _reviewed(f"cd {workspace} && git show HEAD", home=home, environment={key: "1"}) is not None


def test_compound_git_c_status_checks_target_repository_fsmonitor(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    repository = workspace / "repository"
    _init_repository(repository)
    _ = subprocess.run(
        ["git", "-C", str(repository), "config", "core.fsmonitor", "./payload"],
        check=True,
        capture_output=True,
    )

    assert _reviewed(f"cd {workspace} && git -C repository status --short", home=home) is not None


@pytest.mark.parametrize(
    "inspection",
    (
        pytest.param("git show origin/main:../settings.txt", marks=LIVE_ALLOWS_RETIRED_REVIEW),
        pytest.param("git show origin/main:/settings.txt", marks=LIVE_ALLOWS_RETIRED_REVIEW),
        pytest.param("git diff origin/main -- ../settings.txt", marks=live_allows_retired_review_on("darwin")),
        pytest.param("git diff origin/main -- /settings.txt", marks=live_allows_retired_review_on("darwin")),
    ),
)
def test_compound_git_inspection_rejects_escaping_revision_paths(live_hook_root: Path, inspection: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)

    assert _reviewed(f"cd {workspace} && {inspection}", home=home) is not None


@pytest.mark.parametrize("repository", ("projects/repository", "./projects/repository", "."))
def test_compound_git_inspection_accepts_bounded_relative_repository_paths(
    live_hook_root: Path,
    repository: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    (workspace / "projects" / "repository").mkdir(parents=True)

    assert _reviewed(f"cd {workspace} && git -C {repository} status --short | head -20", home=home) is None


@pytest.mark.parametrize(
    "suffix",
    (
        "git -C repository push origin main",
        "git -C repository reset --hard origin/main",
        "git -C repository fetch origin main:refs/heads/main",
        "git -C ../outside fetch origin main",
        "git -C projects/../../outside status --short",
        "git -C /outside status --short",
        pytest.param("git -C ~/outside status --short", marks=LIVE_ALLOWS_RETIRED_REVIEW),
        "git -C projects/$TARGET status --short",
        "git -C repository status --short | sh",
        "git -C repository status --short > report.txt",
        pytest.param("git log -101 --oneline", marks=LIVE_ALLOWS_RETIRED_REVIEW),
        pytest.param("git log --all --oneline -5", marks=LIVE_ALLOWS_RETIRED_REVIEW),
    ),
)
def test_compound_git_recovery_keeps_ambiguous_or_mutating_commands_guarded(
    live_hook_root: Path,
    suffix: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _reviewed(f"cd {workspace} && {suffix}", home=home) is not None


def test_compound_git_recovery_rejects_dynamic_cd(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _reviewed("cd $TARGET && git -C repository fetch origin main", home=home) is not None


@LIVE_ALLOWS_RETIRED_REVIEW
def test_compound_git_recovery_rejects_preceding_execution(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _reviewed(f"printf ready && cd {workspace} && git -C repository status --short", home=home) is not None
