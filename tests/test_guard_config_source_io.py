"""Config source confinement and rejection at the actual configuration boundary."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config_source_io as source_io
from codex_plugin_scanner.guard.config import _read_toml, load_guard_config
from codex_plugin_scanner.guard.config_source_io import (
    MAX_GUARD_CONFIG_BYTES,
    GuardConfigSourceError,
    capture_guard_config,
)


def _link(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError:
        pytest.skip("creating symlinks requires runner support")


def test_missing_config_and_workspace_keep_existing_defaults(tmp_path: Path) -> None:
    assert _read_toml(tmp_path / "absent" / "config.toml") == {}
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
    assert load_guard_config(home, tmp_path / "absent-workspace").default_action == "block"


def test_canonical_directory_aliases_and_relative_paths_remain_supported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    (home / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
    (workspace / ".hol-guard.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    _link(tmp_path / "home-alias", home, directory=True)
    _link(tmp_path / "workspace-alias", workspace, directory=True)
    monkeypatch.chdir(tmp_path)
    actual = load_guard_config(Path("home-alias"), Path("workspace-alias"))
    expected = load_guard_config(home, workspace)
    assert actual == replace(expected, guard_home=Path("home-alias"), workspace=Path("workspace-alias"))
    assert actual.default_action == "block"
    assert actual.sandbox_analysis == "strict"


@pytest.mark.parametrize("descendant", [False, True])
def test_dangling_workspace_directory_alias_is_not_absent(tmp_path: Path, descendant: bool) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
    alias = tmp_path / "workspace-alias"
    _link(alias, tmp_path / "missing-target", directory=True)
    workspace = alias / "child" if descendant else alias
    with pytest.raises(GuardConfigSourceError, match="guard_config_source_unavailable"):
        load_guard_config(home, workspace)


def test_missing_child_beneath_valid_directory_alias_remains_absent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    _link(alias, real, directory=True)
    assert capture_guard_config(alias / "missing-child" / ".hol-guard.toml").identity is None


@pytest.mark.parametrize("location", ["home", "workspace", "legacy-workspace"])
@pytest.mark.parametrize("target_exists", [True, False])
def test_config_leaf_links_never_load_outside_content_or_fall_back_to_defaults(
    tmp_path: Path, location: str, target_exists: bool
) -> None:
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    outside = tmp_path / "outside.toml"
    if target_exists:
        outside.write_text('default_action = "allow"\nsandbox_analysis = "off"\n', encoding="utf-8")
    if location == "home":
        leaf = home / "config.toml"
    else:
        (home / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
        leaf = workspace / (".hol-guard.toml" if location == "workspace" else ".ai-plugin-scanner-guard.toml")
    _link(leaf, outside)
    with pytest.raises(GuardConfigSourceError, match="guard_config_not_regular"):
        load_guard_config(home, workspace)


def test_non_regular_config_is_explicitly_rejected(tmp_path: Path) -> None:
    (tmp_path / "config.toml").mkdir()
    with pytest.raises(GuardConfigSourceError, match="guard_config_not_regular"):
        load_guard_config(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_fifo_is_rejected_before_any_content_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "config.toml"
    os.mkfifo(path)
    monkeypatch.setattr(source_io, "_read_descriptor", lambda *_: pytest.fail("FIFO must never be read"))
    with pytest.raises(GuardConfigSourceError, match="guard_config_not_regular"):
        _read_toml(path)


def test_hard_link_cannot_import_config_from_outside_scope(tmp_path: Path) -> None:
    original = tmp_path / "outside.toml"
    original.write_text('default_action = "allow"\n', encoding="utf-8")
    try:
        (tmp_path / "config.toml").hardlink_to(original)
    except OSError:
        pytest.skip("hard links require runner support")
    with pytest.raises(GuardConfigSourceError, match="guard_config_link_count"):
        load_guard_config(tmp_path)


@pytest.mark.parametrize("extra", [0, 1])
def test_exact_size_limit_and_oversize_never_parse_a_truncated_config(tmp_path: Path, extra: int) -> None:
    prefix = b'default_action = "block"\n#'
    path = tmp_path / "config.toml"
    path.write_bytes(prefix + b"x" * (MAX_GUARD_CONFIG_BYTES - len(prefix) + extra))
    if extra:
        with pytest.raises(GuardConfigSourceError, match="guard_config_too_large"):
            load_guard_config(tmp_path)
    else:
        assert load_guard_config(tmp_path).default_action == "block"


def test_invalid_toml_and_utf8_remain_explicit_errors(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    for content in (b"broken = [", b"\xff"):
        path.write_bytes(content)
        with pytest.raises(ValueError):
            load_guard_config(tmp_path)


def test_unexpected_basename_is_rejected_before_filesystem_access(tmp_path: Path) -> None:
    with pytest.raises(GuardConfigSourceError, match="guard_config_name_invalid"):
        capture_guard_config(tmp_path / "outside.toml")


def test_inaccessible_existing_config_is_not_an_empty_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")

    def denied(*_args: object) -> bytes:
        raise PermissionError("fixture read denied")

    monkeypatch.setattr(source_io, "_read_descriptor", denied)
    with pytest.raises(GuardConfigSourceError, match="guard_config_source_unavailable"):
        load_guard_config(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative races")
@pytest.mark.parametrize("replacement", ["symlink", "file"])
def test_leaf_replacement_between_validation_and_open_is_rejected_without_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    path = tmp_path / "config.toml"
    path.write_text('default_action = "block"\n', encoding="utf-8")
    outside = tmp_path / "outside.toml"
    outside.write_text('default_action = "allow"\n', encoding="utf-8")
    original_open, original_read = os.open, os.read
    reads: list[int] = []

    def replace_then_open(name, flags, *args, **kwargs):
        if name == "config.toml":
            path.unlink()
            if replacement == "symlink":
                path.symlink_to(outside)
            else:
                path.write_text('default_action = "allow"\n', encoding="utf-8")
        return original_open(name, flags, *args, **kwargs)

    def observed_read(fd: int, size: int) -> bytes:
        reads.append(fd)
        return original_read(fd, size)

    monkeypatch.setattr(os, "open", replace_then_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, replace_then_open})
    monkeypatch.setattr(os, "read", observed_read)
    with pytest.raises(GuardConfigSourceError):
        load_guard_config(tmp_path)
    assert reads == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative races")
@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_parent_replacement_cannot_redirect_leaf_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str
) -> None:
    home, moved, outside = tmp_path / "home", tmp_path / "moved", tmp_path / "outside"
    home.mkdir()
    outside.mkdir()
    original_bytes = b'default_action = "block"\n'
    (home / "config.toml").write_bytes(original_bytes)
    (outside / "config.toml").write_text('default_action = "allow"\n', encoding="utf-8")
    original_open, original_read = os.open, os.read
    observed: list[bytes] = []

    def replace_then_open(name, flags, *args, **kwargs):
        if name == "config.toml":
            home.rename(moved)
            if replacement == "symlink":
                home.symlink_to(outside, target_is_directory=True)
            else:
                home.mkdir()
                (home / "config.toml").write_text('default_action = "allow"\n', encoding="utf-8")
        return original_open(name, flags, *args, **kwargs)

    def observed_read(fd: int, size: int) -> bytes:
        value = original_read(fd, size)
        observed.append(value)
        return value

    monkeypatch.setattr(os, "open", replace_then_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, replace_then_open})
    monkeypatch.setattr(os, "read", observed_read)
    with pytest.raises(GuardConfigSourceError, match="guard_config_parent_changed"):
        load_guard_config(home)
    assert b"".join(observed) == original_bytes


@pytest.mark.skipif(os.name != "posix", reason="POSIX in-place mutation")
@pytest.mark.parametrize("mutation", ["grow", "shrink", "same-size", "replace"])
def test_file_changes_during_read_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    path = tmp_path / "config.toml"
    original = b'default_action = "block"\n'
    path.write_bytes(original)
    original_read = os.read
    changed = False

    def mutate_after_read(fd: int, size: int) -> bytes:
        nonlocal changed
        value = original_read(fd, size)
        if not changed:
            changed = True
            if mutation == "replace":
                (tmp_path / "replacement").write_bytes(original)
                (tmp_path / "replacement").replace(path)
            else:
                payload = original + b"#grow" if mutation == "grow" else original[:4]
                if mutation == "same-size":
                    payload = original.replace(b"block", b"allow")
                path.write_bytes(payload)
        return value

    monkeypatch.setattr(os, "read", mutate_after_read)
    with pytest.raises(GuardConfigSourceError, match="guard_config_changed"):
        load_guard_config(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX short-read behavior")
def test_short_reads_use_one_file_descriptor_and_consume_complete_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b'default_action = "block"\n'
    (tmp_path / "config.toml").write_bytes(payload)
    original_read = os.read
    descriptors: set[int] = set()

    def short_read(fd: int, size: int) -> bytes:
        descriptors.add(fd)
        return original_read(fd, min(size, 3))

    monkeypatch.setattr(os, "read", short_read)
    assert load_guard_config(tmp_path).default_action == "block"
    assert len(descriptors) == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor capabilities")
def test_missing_descriptor_capability_has_no_pathname_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "config.toml").write_text('default_action = "block"\n', encoding="utf-8")
    monkeypatch.setattr(os, "supports_dir_fd", set())
    monkeypatch.setattr(source_io, "_capture_in_parent", lambda *_: pytest.fail("unsafe fallback attempted"))
    with pytest.raises(GuardConfigSourceError, match="guard_config_descriptor_io_unavailable"):
        load_guard_config(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor accounting")
@pytest.mark.parametrize("content", [b'default_action = "block"\n', b"missing", b"directory"])
def test_all_opened_descriptors_are_closed_after_success_absence_or_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    path = tmp_path / "config.toml"
    if content == b"directory":
        path.mkdir()
    elif content != b"missing":
        path.write_bytes(content)
    original_open = os.open
    opened: list[int] = []

    def recorded_open(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", recorded_open)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, recorded_open})
    if content == b"directory":
        with pytest.raises(GuardConfigSourceError):
            capture_guard_config(path)
    else:
        capture_guard_config(path)
    assert opened
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="actual Windows handle sharing")
def test_windows_directory_and_file_cannot_be_replaced_while_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    path = home / "config.toml"
    path.write_text('default_action = "block"\n', encoding="utf-8")
    original_read = os.read

    def try_replace(fd: int, size: int) -> bytes:
        with pytest.raises(OSError):
            home.rename(tmp_path / "moved")
        with pytest.raises(OSError):
            path.unlink()
        return original_read(fd, size)

    monkeypatch.setattr(os, "read", try_replace)
    assert load_guard_config(home).default_action == "block"
