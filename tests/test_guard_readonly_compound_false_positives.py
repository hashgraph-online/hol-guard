"""Regression coverage for routine read-only compound commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


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
    _source_file(repo, "app/guard/_components/controls/policy-studio/guided-policy-view.tsx")
    (repo / ".git").write_text("gitdir: ../repo.git\n", encoding="utf-8")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"cd ~/projects/policy-workspace && {suffix}"},
        cwd=workspace,
        home_dir=home_dir,
    )

    assert match is None


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
