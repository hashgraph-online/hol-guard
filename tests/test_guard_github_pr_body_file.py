from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.github_pr_body_file import (
    github_pr_body_file_is_safe,
)


def test_github_pr_body_file_accepts_bounded_owner_controlled_markdown(tmp_path: Path) -> None:
    body_file = tmp_path / "focused-pr-body.md"
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")

    assert github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


@pytest.mark.parametrize("name", ("pr-body.md", "pr-body.markdown", "PR-BODY.MD"))
def test_github_pr_body_file_accepts_canonical_markdown_name(tmp_path: Path, name: str) -> None:
    body_file = tmp_path / name
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")

    assert github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


def test_github_pr_body_file_rejects_oversized_markdown(tmp_path: Path) -> None:
    body_file = tmp_path / "focused-pr-body.md"
    _ = body_file.write_bytes(b"x" * (128 * 1024 + 1))

    assert not github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


def test_github_pr_body_file_rejects_sensitive_path(tmp_path: Path) -> None:
    body_file = tmp_path / ".env-pr-body.md"
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")

    assert not github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


def test_github_pr_body_file_rejects_arbitrary_markdown_name(tmp_path: Path) -> None:
    body_file = tmp_path / "internal-notes.md"
    _ = body_file.write_text("Private planning notes.\n", encoding="utf-8")

    assert not github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


@pytest.mark.parametrize("padding", (" ", "\t", "\n"))
def test_github_pr_body_file_rejects_padded_operand(tmp_path: Path, padding: str) -> None:
    body_file = tmp_path / "pr-body.md"
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")

    assert not github_pr_body_file_is_safe(
        f"{padding}{body_file}",
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX permissions required")
def test_github_pr_body_file_rejects_group_or_world_writable_file(tmp_path: Path) -> None:
    body_file = tmp_path / "pr-body.md"
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")
    body_file.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    assert not github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX permissions required")
def test_github_pr_body_file_rejects_writable_intermediate_directory(tmp_path: Path) -> None:
    shared_directory = tmp_path / "shared"
    shared_directory.mkdir()
    shared_directory.chmod(
        stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO,
    )
    body_file = shared_directory / "pr-body.md"
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")
    body_file.chmod(stat.S_IRUSR | stat.S_IWUSR)

    assert not github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )
