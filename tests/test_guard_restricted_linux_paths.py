"""No workspace read grant may follow credentials, aliases or mutable directory routing."""

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.restricted_linux_landlock import LinuxContainmentUnavailableError
from codex_plugin_scanner.guard.runtime.restricted_linux_paths import collect_linux_read_grants


def test_ordinary_source_is_admitted_without_reading_credential_data(tmp_path: Path):
    source = tmp_path / "source.py"
    source.write_text("ordinary source")
    for name in (".env", ".ENV.local", ".npmrc", "private-key.pem", "wallet.key"):
        (tmp_path / name).write_text("synthetic fixture only")
    keys = tmp_path / ".ssh"
    keys.mkdir()
    (keys / "config").write_text("synthetic fixture only")
    grants = collect_linux_read_grants(tmp_path)
    assert [grant.path for grant in grants] == [source]
    metadata = source.stat()
    assert (grants[0].device, grants[0].inode) == (metadata.st_dev, metadata.st_ino)


def test_credential_symlinks_hardlinks_and_directory_escapes_are_not_admitted(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    credential = tmp_path / ".env"
    credential.write_text("synthetic fixture only")
    (workspace / "innocent.txt").hardlink_to(credential)
    (workspace / "alias.txt").symlink_to(credential)
    (workspace / "external").symlink_to(tmp_path, target_is_directory=True)
    assert collect_linux_read_grants(workspace) == ()


def test_discovery_budget_aborts_instead_of_admitting_partial_tree(tmp_path: Path):
    for name in ("a.py", "b.py"):
        (tmp_path / name).touch()
    with pytest.raises(LinuxContainmentUnavailableError, match="budget"):
        collect_linux_read_grants(tmp_path, max_entries=1)


def test_symlink_workspace_root_is_not_followed(tmp_path: Path):
    actual, alias = tmp_path / "actual", tmp_path / "alias"
    actual.mkdir()
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(LinuxContainmentUnavailableError):
        collect_linux_read_grants(alias)


def test_parent_symlink_cannot_redirect_workspace_discovery(tmp_path: Path):
    actual, alias = tmp_path / "actual", tmp_path / "alias"
    actual.mkdir()
    (actual / "workspace").mkdir()
    alias.symlink_to(actual, target_is_directory=True)
    with pytest.raises(LinuxContainmentUnavailableError, match="canonical"):
        collect_linux_read_grants(alias / "workspace")


def test_credential_directory_cannot_become_an_index_root(tmp_path: Path):
    directory = tmp_path / ".aws"
    directory.mkdir()
    (directory / "ordinary-name.txt").write_text("synthetic fixture only")
    with pytest.raises(LinuxContainmentUnavailableError, match="nonsensitive"):
        collect_linux_read_grants(directory)


def test_directory_replacement_during_discovery_fails_closed(tmp_path: Path, monkeypatch):
    directory = tmp_path / "source"
    directory.mkdir()
    (directory / "example.py").touch()
    original = os.open

    def changed(path, flags, *, dir_fd=None):
        if path == "source" and dir_fd is not None:
            directory.rename(tmp_path / "old-source")
            directory.mkdir()
        return original(path, flags, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", changed)
    with pytest.raises(LinuxContainmentUnavailableError, match="changed"):
        collect_linux_read_grants(tmp_path)
