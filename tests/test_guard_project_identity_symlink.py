from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.project_identity import resolve_portable_project_identity


def _write_git_identity_metadata(git_dir: Path, remote: str) -> None:
    (git_dir / "logs").mkdir(parents=True, exist_ok=True)
    (git_dir / "config").write_text(
        f'[remote "origin"]\n\turl = {remote}\n',
        encoding="utf-8",
    )
    (git_dir / "logs" / "HEAD").write_text(
        f"{'0' * 40} {'1' * 40} Guard Test <guard@example.invalid> 0 +0000\tclone: from {remote}\n",
        encoding="utf-8",
    )


def test_gitdir_directory_symlink_cannot_claim_external_repository_identity(tmp_path: Path) -> None:
    remote = "https://github.com/example/trusted-repository.git"
    external_git = tmp_path / "external-git"
    _write_git_identity_metadata(external_git, remote)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".git").symlink_to(external_git, target_is_directory=True)

    assert resolve_portable_project_identity(workspace) is None


def test_nested_git_metadata_symlinks_cannot_claim_external_repository_identity(tmp_path: Path) -> None:
    remote = "https://github.com/example/trusted-repository.git"
    external_git = tmp_path / "external-git"
    _write_git_identity_metadata(external_git, remote)

    for layout in ("config", "logs", "head"):
        workspace = tmp_path / f"workspace-{layout}"
        git_dir = workspace / ".git"
        git_dir.mkdir(parents=True)
        (git_dir / "logs").mkdir()

        if layout == "config":
            (git_dir / "config").symlink_to(external_git / "config")
            (git_dir / "logs" / "HEAD").write_text(
                (external_git / "logs" / "HEAD").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        elif layout == "logs":
            (git_dir / "logs").rmdir()
            (git_dir / "logs").symlink_to(external_git / "logs", target_is_directory=True)
            (git_dir / "config").write_text(
                (external_git / "config").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        else:
            (git_dir / "config").write_text(
                (external_git / "config").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (git_dir / "logs" / "HEAD").symlink_to(external_git / "logs" / "HEAD")

        assert resolve_portable_project_identity(workspace) is None
