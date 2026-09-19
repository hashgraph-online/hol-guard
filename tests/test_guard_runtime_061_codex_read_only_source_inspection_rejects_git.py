"""Runtime regression tests: codex read only source inspection rejects git."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    Path,
    guard_commands_module,
    pytest,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_runtime_test_support import (
    _isolate_git_config,
    _write_text,
)


def test_codex_read_only_source_inspection_rejects_git_diff_global_textconv_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    global_config = tmp_path / "global-gitconfig"
    _write_text(
        global_config,
        """
[diff "guard"]
    textconv = /tmp/guard-textconv
""".strip(),
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_diff_included_config_with_comment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff "guard"]
    textconv = /tmp/guard-textconv
""".strip(),
    )
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f"[include]\n    path = {included_config} # required by local tools\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_diff_included_config_with_section_comment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f"[include] # local helper config\n    path = {included_config}\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_ignores_unmatched_git_include_if(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f'[includeIf "gitdir:{tmp_path / "other-repo"}/"]\n    path = {included_config}\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/main\n")

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_matched_git_include_if(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/main\n")
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f'[includeIf "gitdir:{workspace_dir}/"]\n    path = {included_config}\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_include_if_gitdir_matches_dot_git(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/main\n")
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f'[includeIf "gitdir:{workspace_dir / ".git"}"]\n    path = {included_config}\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_include_if_gitdir_matches_symlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/main\n")
    symlink_dir = tmp_path / "workspace-link"
    try:
        symlink_dir.symlink_to(workspace_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f'[includeIf "gitdir:{symlink_dir / ".git"}"]\n    path = {included_config}\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=symlink_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_include_if_relative_gitdir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/main\n")
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f'[includeIf "gitdir:./workspace/.git"]\n    path = {included_config}\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_include_if_hasconfig(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(
        workspace_dir / ".git" / "config",
        """
[remote "origin"]
    url = https://github.com/hashgraph-online/hol-guard
""".strip(),
    )
    global_config = tmp_path / "global-gitconfig"
    _write_text(
        global_config,
        f'[includeIf "hasconfig:remote.*.url:https://github.com/hashgraph-online/*"]\n    path = {included_config}\n',
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_include_if_hasconfig_nested_include(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    helper_config = tmp_path / "helper-gitconfig"
    _write_text(
        helper_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    remote_config = tmp_path / "remote-gitconfig"
    _write_text(
        remote_config,
        """
[remote "origin"]
    url = https://github.com/hashgraph-online/hol-guard
""".strip(),
    )
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/main\n")
    _write_text(workspace_dir / ".git" / "config", f"[include]\n    path = {remote_config}\n")
    global_config = tmp_path / "global-gitconfig"
    _write_text(
        global_config,
        f'[includeIf "hasconfig:remote.*.url:https://github.com/hashgraph-online/*"]\n    path = {helper_config}\n',
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_config_continued_include_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/main\n")
    _write_text(workspace_dir / "helper-gitconfig", "[diff]\n    external = /tmp/guard-diff\n")
    _write_text(
        workspace_dir / ".git" / "config",
        """
[include]
    path = ../helper-\\
        gitconfig
""".strip(),
    )

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_include_if_onbranch_prefix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    included_config = tmp_path / "included-gitconfig"
    _write_text(
        included_config,
        """
[diff]
    external = /tmp/guard-diff
""".strip(),
    )
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(workspace_dir / ".git" / "HEAD", "ref: refs/heads/feature/read-only\n")
    global_config = tmp_path / "global-gitconfig"
    _write_text(global_config, f'[includeIf "onbranch:feature/"]\n    path = {included_config}\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_allows_git_diff_with_external_helpers_disabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(
        workspace_dir / ".git" / "config",
        """
[diff "guard"]
    textconv = /tmp/guard-textconv
""".strip(),
    )

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff --no-ext-diff --no-textconv -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_config_injection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git -c diff.external=/tmp/guard-helper diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_unknown_git_diff_option(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff --mystery -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_diff_paths_without_separator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_disallowed_option_after_optional_git_diff_flag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff --color --output=/tmp/leak -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_unbounded_sed_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed 's/token/value/'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_invalid_sed_without_crashing(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    for command in (
        "sed -i 's/safe/unsafe/' src/safe.ts",
        "sed --unknown -n '1,40p' src/safe.ts",
    ):
        assert not guard_commands_module._codex_command_is_read_only_source_inspection(
            command,
            cwd=workspace_dir,
        )
