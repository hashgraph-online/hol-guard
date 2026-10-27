"""Regression coverage for routine read-only compound commands."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request
from tests.codex_read_only_inspection import (
    codex_command_is_read_only_source_inspection,
)


def _source_file(repo: Path, relative_path: str) -> None:
    path = repo / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("export const previewTokenLabel = 'previewToken';\n", encoding="utf-8")


@pytest.mark.parametrize(
    "suffix",
    (
        "git diff HEAD -- app/guard/_components/controls/policy-studio/guided-policy-view.tsx | cat",
        (
            "git diff HEAD -- app/guard/_components/controls/guard-controls-policy-studio.tsx "
            "| grep -A5 -B5 'handleUndo|handleRedo|undoAndGet|redoAndGet'"
        ),
        "cat .git 2>/dev/null; echo '---'; git status --short 2>/dev/null | head -50",
    ),
)
def test_literal_sibling_repo_read_only_inspection_does_not_require_review(tmp_path: Path, suffix: str) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "policy-workspace"
    workspace.mkdir(parents=True)
    subprocess.run(
        ["git", "init", "--quiet", f"--separate-git-dir={repo.parent / 'repo.git'}", str(repo)],
        check=True,
        capture_output=True,
    )
    _source_file(repo, "app/guard/_components/controls/policy-studio/guided-policy-view.tsx")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd ~/projects/policy-workspace && {suffix}"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is None


@pytest.mark.parametrize(
    "suffix",
    (
        "cd ../sibling && cat src/safe.ts",
        "cd .. && cat sibling/src/safe.ts",
        "cat ../sibling/src/safe.ts",
    ),
)
def test_literal_repo_read_only_inspection_rejects_later_workspace_escape(
    tmp_path: Path,
    suffix: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "project"
    sibling = home_dir / "projects" / "sibling"
    workspace.mkdir(parents=True)
    _source_file(repo, "src/safe.ts")
    _source_file(sibling, "src/safe.ts")
    (repo / ".git").mkdir()
    (sibling / ".git").mkdir()

    command = f"cd ~/projects/project && {suffix}"
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None
    assert not codex_command_is_read_only_source_inspection(
        command,
        cwd=workspace,
        home_dir=home_dir,
    )


def test_literal_repo_read_only_inspection_stays_within_first_marked_workspace(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    _source_file(repo, "src/safe.ts")
    (repo / ".git").mkdir()
    command = "cd ~/projects/project && cd src && sed -n '1,20p' safe.ts"

    assert codex_command_is_read_only_source_inspection(
        command,
        cwd=workspace,
        home_dir=home_dir,
    )


@pytest.mark.parametrize("link_kind", ("file", "directory"))
def test_literal_repo_read_only_inspection_rejects_symlinked_hidden_operand(
    tmp_path: Path,
    link_kind: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    _source_file(repo, "src/safe.ts")
    (repo / ".git").mkdir()
    hidden = repo / ".private"
    hidden.mkdir()
    (hidden / "safe.ts").write_text("secret\n", encoding="utf-8")
    if link_kind == "file":
        target = repo / "src" / "linked.ts"
        target.symlink_to(hidden / "safe.ts")
    else:
        linked_dir = repo / "linked"
        linked_dir.symlink_to(hidden, target_is_directory=True)
        target = linked_dir / "safe.ts"

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd ~/projects/project && cat {target.relative_to(repo)}"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


def test_read_only_source_pipeline_allows_identifier_like_output(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    _source_file(repo, "src/repository.ts")
    command = "cd ~/projects/project && sed -n '1,20p' src/repository.ts | cat -A | head -20"

    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "export const previewTokenLabel = 'previewToken';$\n"},
        },
        config_path=str(home_dir / ".pi" / "settings.json"),
        source_scope="workspace",
        cwd=workspace,
        home_dir=home_dir,
    )

    assert artifact is None


def test_literal_sibling_repo_bounded_sed_edit_with_same_file_verification_does_not_require_review(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "email-workspace"
    workspace.mkdir(parents=True)
    _source_file(repo, "src/emails/notice.tsx")
    (repo / ".git").mkdir()
    command = """cd ~/projects/email-workspace && sed -i '' \\
  -e 's/previewToken/previewLabel/g' \\
  -e 's/Token/Value/g' \\
  src/emails/notice.tsx
echo "=== Verify ==="
grep -n "previewLabel\\|Value" src/emails/notice.tsx"""

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is None


def test_literal_current_workspace_bounded_sed_edit_does_not_require_review(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "analytics"
    _source_file(workspace, "src/lib/guard/analytics/report.ts")
    target = workspace / "src/lib/guard/analytics/report.ts"
    (workspace / ".git").mkdir()
    target.write_text(
        "const query = `${fromDate}:${toDate}`;\n",
        encoding="utf-8",
    )
    command = (
        "sed -i '' 's/\\${fromDate}/\\${fromIso}/g; s/\\${toDate}/\\${toIso}/g' "
        'src/lib/guard/analytics/report.ts 2>&1 && echo "done"'
    )

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is None


@pytest.mark.parametrize(
    "command",
    (
        r"sed -i '' 's/\${fromDate}/$HOME/g' src/safe.ts",
        r"sed -i '' 's/.*/new/g' src/safe.ts",
        r"sed -i '' 's/old/prefix-&/g' src/safe.ts",
        r"sed -i '' 's/old/new/e' src/safe.ts",
        r"sed -i '' 's/old\{1,2\}/new/g' src/safe.ts",
        r"sed -i '' 's/old/new/w leaked.txt' src/safe.ts",
        r"sed -i '' 's/old/new/g; e cat .env' src/safe.ts",
        r"sed -i '' 's/old/new/g' src/safe.ts src/other.ts",
        r"sed -E -i '' 's/old/new/g' src/safe.ts",
        r"sed -i '' 's/old/new/g' ../outside.ts",
        r"sed -i '' 's/old/new/g' .env",
        r"sed -i '' 's/old/new/g' src/safe.ts && git add src/safe.ts",
        r"sed -i '' 's/old/new/g' src/safe.ts && echo $(cat .env)",
    ),
)
def test_literal_current_workspace_bounded_sed_edit_rejects_unsafe_variants(
    tmp_path: Path,
    command: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    _source_file(workspace, "src/safe.ts")
    _source_file(workspace, "src/other.ts")
    (workspace / ".git").mkdir()
    (workspace / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (workspace.parent / "outside.ts").write_text("old\n", encoding="utf-8")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


def test_literal_current_workspace_bounded_sed_edit_rejects_unmarked_workspace(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "unmarked"
    _source_file(workspace, "src/safe.ts")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "sed -i '' 's/old/new/g' src/safe.ts"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


def test_literal_current_workspace_bounded_sed_edit_rejects_symlink_escape(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    (workspace / ".git").mkdir()
    outside = home_dir / "outside.ts"
    outside.write_text("old\n", encoding="utf-8")
    target = workspace / "src" / "linked.ts"
    target.parent.mkdir()
    target.symlink_to(outside)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "sed -i '' 's/old/new/g' src/linked.ts"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


@pytest.mark.parametrize("link_kind", ("file", "directory"))
def test_literal_current_workspace_bounded_sed_edit_rejects_symlink_components(
    tmp_path: Path,
    link_kind: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    (workspace / ".git").mkdir()
    hidden = workspace / ".private"
    hidden.mkdir()
    (hidden / "safe.ts").write_text("old\n", encoding="utf-8")
    source = workspace / "src"
    source.mkdir()
    target = source / "safe.ts"
    if link_kind == "file":
        target.symlink_to(hidden / "safe.ts")
    else:
        target.parent.rmdir()
        target.parent.symlink_to(hidden, target_is_directory=True)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "sed -i '' 's/old/new/g' src/safe.ts"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


@pytest.mark.parametrize(
    "target",
    ("-e e id #.ts", "--expression=e id #.ts", "-fscript.ts"),
)
def test_literal_current_workspace_bounded_sed_edit_rejects_option_like_target(
    tmp_path: Path,
    target: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    (workspace / ".git").mkdir()
    (workspace / target).write_text("old\n", encoding="utf-8")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"""sed -i '' 's/old/new/g' '{target}'"""},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


@pytest.mark.parametrize(
    "edit,verification",
    (
        ("sed -i '' -e 's/old/new/e' src/safe.ts", "grep -n new src/safe.ts"),
        ("sed -i.bak -e 's/old/new/g' src/safe.ts", "grep -n new src/safe.ts"),
        ("sed -i '' -e 's/old/new/g' .env", "grep -n new .env"),
        ("sed -i '' -e 's/old/new/g' src/safe.ts", "grep -n new src/other.ts"),
        ("sed -i '' -e 's/old/new/g' src/safe.ts", "grep -n new ../../outside.ts"),
        ("sed -i '' -e 's/old/new/g' src/safe.ts", ""),
        ("sed -i '' -e 's/old/$HOME/g' src/safe.ts", "grep -n HOME src/safe.ts"),
        ("sed -i '' -e 's/.*/new/g' src/safe.ts", "grep -n new src/safe.ts"),
        ("sed -i '' -e 's/old/prefix-&/g' src/safe.ts", "grep -n prefix src/safe.ts"),
        (r"sed -i '' -e 's/(old)/\\1/g' src/safe.ts", "grep -n old src/safe.ts"),
    ),
)
def test_bounded_sed_edit_rejects_unverified_or_sensitive_variants(
    tmp_path: Path,
    edit: str,
    verification: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    _source_file(repo, "src/safe.ts")
    _source_file(repo, "src/other.ts")
    (repo / ".git").mkdir()
    (repo / ".env").write_text("old=value\n", encoding="utf-8")
    (home_dir / "outside.ts").write_text("old\n", encoding="utf-8")
    suffix = f" && {verification}" if verification else ""

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd ~/projects/project && {edit}{suffix}"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


@pytest.mark.parametrize(
    ("repo_relative", "with_marker"),
    (("projects/unmarked", False), (".config/project", True)),
)
def test_bounded_sed_edit_requires_visible_marked_workspace(
    tmp_path: Path,
    repo_relative: str,
    with_marker: bool,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / repo_relative
    workspace.mkdir(parents=True)
    _source_file(repo, "src/safe.ts")
    if with_marker:
        (repo / ".git").mkdir()

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": (f"cd ~/{repo_relative} && sed -i '' -e 's/old/new/g' src/safe.ts && grep -n new src/safe.ts")},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None


@pytest.mark.parametrize(
    "suffix",
    (
        "git diff HEAD -- .env | cat",
        "git diff HEAD -- .aws/credentials | cat",
        "git diff --stat && echo '---' && git diff",
        "git diff HEAD -- src/safe.ts | cat /etc/passwd",
        "git diff HEAD -- src/safe.ts | grep pattern ../../outside.txt",
        "git diff HEAD -- src/safe.ts | grep -f /outside/patterns",
        "git diff HEAD -- src/safe.ts | cat $(printf payload)",
        "sed -i '' 's/old/new/' src/safe.ts",
        "git add -A && git commit -m change",
    ),
)
def test_literal_sibling_repo_sensitive_or_mutating_commands_still_require_review(
    tmp_path: Path,
    suffix: str,
) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "workspace"
    repo = home_dir / "projects" / "project"
    workspace.mkdir(parents=True)
    _source_file(repo, "src/safe.ts")
    (repo / ".env").write_text("TOKEN=secret\n", encoding="utf-8")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd ~/projects/project && {suffix}"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is not None
