from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request


def _is_benign(command: str, *, workspace: Path, home: Path) -> bool:
    return is_explicitly_benign_tool_action_request(
        "Bash",
        {"command": command},
        cwd=workspace,
        home_dir=home,
    )


@pytest.fixture
def guidance_home(tmp_path: Path) -> Path:
    skill = tmp_path / ".agents" / "skills" / "github-pr-review-loop" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# PR review\n", encoding="utf-8")
    safety = tmp_path / ".hol-support" / "SAFETY.md"
    safety.parent.mkdir(parents=True)
    safety.write_text("# Safety\n", encoding="utf-8")
    docs = tmp_path / ".codex" / "docs"
    docs.mkdir(parents=True)
    (docs / "harness-engineering.md").write_text("# Harness\n", encoding="utf-8")
    (docs / "token-discipline.md").write_text("# Tokens\n", encoding="utf-8")
    return tmp_path


def test_bounded_agent_guidance_read_chain_is_benign(guidance_home: Path, tmp_path: Path) -> None:
    command = (
        "sed -n '1,240p' ~/.agents/skills/github-pr-review-loop/SKILL.md && "
        "sed -n '1,240p' ~/.hol-support/SAFETY.md && "
        "sed -n '1,220p' ~/.codex/docs/harness-engineering.md && "
        "sed -n '1,180p' ~/.codex/docs/token-discipline.md"
    )

    assert _is_benign(command, workspace=tmp_path, home=guidance_home)


@pytest.mark.parametrize(
    "suffix",
    (
        "&& cat ~/.ssh/id_rsa",
        "&& rm ~/.hol-support/SAFETY.md",
        "> /tmp/guidance.txt",
        "&& sed -n '1,20p' ~/.codex/docs/credentials.json",
        "&& sed -n '1,20p' ~/.agents/skills/github-pr-review-loop/credentials",
        "&& sed -n '1,20p' \"$(printf ~/.hol-support/SAFETY.md)\"",
        "&& sed -n '1,501p' ~/.hol-support/SAFETY.md",
        "&& sed -n '20,1p' ~/.hol-support/SAFETY.md",
    ),
)
def test_agent_guidance_read_chain_rejects_unsafe_variants(
    guidance_home: Path,
    tmp_path: Path,
    suffix: str,
) -> None:
    command = f"sed -n '1,20p' ~/.hol-support/SAFETY.md {suffix}"

    assert not _is_benign(command, workspace=tmp_path, home=guidance_home)


def test_agent_guidance_read_rejects_skill_symlink_escape(guidance_home: Path, tmp_path: Path) -> None:
    skill = guidance_home / ".agents" / "skills" / "github-pr-review-loop" / "SKILL.md"
    skill.unlink()
    outside = tmp_path / "outside.md"
    outside.write_text("outside\n", encoding="utf-8")
    skill.symlink_to(outside)

    assert not _is_benign(
        "sed -n '1,20p' ~/.agents/skills/github-pr-review-loop/SKILL.md",
        workspace=tmp_path,
        home=guidance_home,
    )


@pytest.mark.parametrize(
    "target",
    (
        "~/.agents/skills/github-pr-review-loop/credentials/config.ts",
        "~/.agents/skills/github-pr-review-loop/*.md",
        "~/.agents/skills/github-pr-review-loop/[.]env",
        "~/.agents/skills/github-pr-review-loop/../secret.py",
    ),
)
def test_shell_skill_read_rejects_sensitive_glob_and_traversal_targets(
    guidance_home: Path,
    tmp_path: Path,
    target: str,
) -> None:
    credentials = guidance_home / ".agents" / "skills" / "github-pr-review-loop" / "credentials"
    credentials.mkdir(exist_ok=True)
    (credentials / "config.ts").write_text("export const value = 1\n", encoding="utf-8")

    assert not _is_benign(f"cat {target}", workspace=tmp_path, home=guidance_home)


def test_agent_guidance_read_rejects_safety_parent_symlink(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SAFETY.md").write_text("outside\n", encoding="utf-8")
    (home / ".hol-support").symlink_to(outside, target_is_directory=True)

    assert not _is_benign(
        "sed -n '1,20p' ~/.hol-support/SAFETY.md",
        workspace=tmp_path,
        home=home,
    )
