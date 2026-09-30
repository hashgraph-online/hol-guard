from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import github_pr_body_file as body_file_module
from codex_plugin_scanner.guard.runtime.github_pr_body_file import (
    github_pr_body_file_is_safe,
)


@pytest.mark.parametrize("newline", (b"\n", b"\r\n"), ids=("lf", "crlf"))
def test_github_pr_body_file_accepts_bounded_owner_controlled_markdown(tmp_path: Path, newline: bytes) -> None:
    body_file = tmp_path / "focused-pr-body.md"
    _ = body_file.write_bytes(newline.join((b"## Summary", b"- Focused change.", b"")))

    assert github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


@pytest.mark.parametrize(
    "changed_at", (None, "open", "open-unavailable", "different-file", "read", "after", "short-read")
)
def test_windows_body_file_reader_binds_locked_path_and_descriptor_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_at: str | None
) -> None:
    body_file = tmp_path / "pr-body.md"
    _ = body_file.write_bytes(b"## Summary\r\n- Focused change.\r\n")
    metadata = os.lstat(body_file)
    fields = {
        name: getattr(metadata, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime",
            "st_mtime_ns",
            "st_ctime",
            "st_ctime_ns",
        )
    }
    path_stats = 0
    descriptor_stats = 0
    locked = False

    def path_stat(candidate: Path) -> SimpleNamespace:
        nonlocal path_stats
        assert candidate == body_file
        path_stats += 1
        assert locked is (path_stats > 1)
        if changed_at == "open-unavailable" and path_stats == 2:
            raise FileNotFoundError("parent directory moved during open")
        result = {**fields, "st_file_attributes": 0x20}
        if (changed_at == "open" and path_stats == 2) or (changed_at == "after" and path_stats == 3):
            result["st_ino"] += 1
        return SimpleNamespace(**result)

    def descriptor_stat(_descriptor: int) -> SimpleNamespace:
        nonlocal descriptor_stats
        descriptor_stats += 1
        assert locked
        # CPython can expose different ctime values across these stat APIs,
        # while the volume/file identity must still bind the actual handle.
        result = {**fields, "st_ctime_ns": fields["st_ctime_ns"] + 1, "st_file_attributes": 0}
        if changed_at == "different-file":
            result["st_ino"] += 1
        if changed_at == "read" and descriptor_stats == 2:
            result["st_mtime_ns"] += 1
        return SimpleNamespace(**result)

    def open_locked(candidate: Path) -> int:
        nonlocal locked
        assert candidate == body_file
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        locked = True
        return descriptor

    def read_locked(descriptor: int, size: int) -> bytes:
        assert locked
        payload = os.read(descriptor, size)
        return payload[:-1] if changed_at == "short-read" else payload

    def close_locked(descriptor: int) -> None:
        nonlocal locked
        os.close(descriptor)
        locked = False

    monkeypatch.setattr(body_file_module, "open_windows_locked_regular_descriptor", open_locked)
    monkeypatch.setattr(
        body_file_module,
        "os",
        SimpleNamespace(name="nt", lstat=path_stat, fstat=descriptor_stat, read=read_locked, close=close_locked),
    )

    safe = github_pr_body_file_is_safe(str(body_file), cwd=tmp_path, home_dir=tmp_path.parent)

    assert not locked
    assert safe is (changed_at is None)


@pytest.mark.parametrize(
    "name",
    ("pr-body.md", "pr-body.markdown", "PR-BODY.MD", "PR_BODY.md", "PR_BODY_PROTECTION.md"),
)
def test_github_pr_body_file_accepts_canonical_markdown_name(tmp_path: Path, name: str) -> None:
    body_file = tmp_path / name
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")

    assert github_pr_body_file_is_safe(
        str(body_file),
        cwd=tmp_path,
        home_dir=tmp_path.parent,
    )


def test_github_pr_body_file_accepts_named_body_in_user_cascade_projects(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "CascadeProjects" / "active-project"
    body_directory = home_dir / "CascadeProjects" / "proposal-worktree"
    workspace.mkdir(parents=True)
    body_directory.mkdir()
    body_file = body_directory / "PR_BODY_PROTECTION.md"
    _ = body_file.write_text("## Summary\n- Focused change.\n", encoding="utf-8")

    assert github_pr_body_file_is_safe(
        "~/CascadeProjects/proposal-worktree/PR_BODY_PROTECTION.md",
        cwd=workspace,
        home_dir=home_dir,
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


def test_github_pr_body_file_rejects_pr_body_marker_only_as_suffix(tmp_path: Path) -> None:
    body_file = tmp_path / "internal_notes_pr_body.md"
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
