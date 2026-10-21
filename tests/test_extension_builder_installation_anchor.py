"""Installed reads must survive a symlinked installation prefix.

macOS reaches the per-user temporary directory through ``/var`` and several
Linux distributions symlink ``/tmp``. On Windows the trigger is a directory
symlink (``mklink /D``); a junction (``mklink /J``) is not one, because
``Path.is_symlink`` is False for a junction. The cases that need a real
symlink are gated on this account holding the privilege to create one rather
than skipped on Windows outright, and the anchored branch itself is covered
without a symlink so Windows always exercises it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path, read_bytes
from tests.symlink_support import SYMLINK_REASON, directory_symlinks_available

needs_symlinks = pytest.mark.skipif(not directory_symlinks_available(), reason=SYMLINK_REASON)


def _installation(tmp_path: Path) -> tuple[Path, Path]:
    """Return a package root reached through a symlinked prefix, and the real one."""

    real = tmp_path / "private" / "extraction"
    (real / "codex_plugin_scanner" / "_native").mkdir(parents=True)
    (real / "codex_plugin_scanner" / "_native" / "runtime-manifest.json").write_bytes(b'{"ok":true}')
    (tmp_path / "extraction").symlink_to(real)
    return tmp_path / "extraction" / "codex_plugin_scanner", real / "codex_plugin_scanner"


@needs_symlinks
def test_a_symlinked_installation_prefix_still_reads_the_installed_file(tmp_path: Path) -> None:
    package, real = _installation(tmp_path)
    target = package / "_native" / "runtime-manifest.json"

    with pytest.raises(BuilderError, match="Symlink paths"):
        read_bytes(target, limit=65536)

    assert read_bytes(target, limit=65536, anchor=package) == b'{"ok":true}'
    assert checked_path(target, anchor=package) == real / "_native" / "runtime-manifest.json"


@needs_symlinks
def test_a_symlink_below_the_installation_prefix_is_still_rejected(tmp_path: Path) -> None:
    package, real = _installation(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b'{"planted":true}')
    (real / "_native" / "planted.json").symlink_to(outside)

    with pytest.raises(BuilderError, match="Symlink paths"):
        read_bytes(package / "_native" / "planted.json", limit=65536, anchor=package)

    (real / "_native" / "nested").symlink_to(tmp_path)
    with pytest.raises(BuilderError, match="Symlink paths"):
        read_bytes(package / "_native" / "nested" / "outside.json", limit=65536, anchor=package)


def _plain_installation(tmp_path: Path) -> Path:
    """A package root with no symlink anywhere, creatable without privilege."""

    package = tmp_path / "extraction" / "codex_plugin_scanner"
    (package / "_native").mkdir(parents=True)
    (package / "_native" / "runtime-manifest.json").write_bytes(b'{"ok":true}')
    return package


def test_a_path_outside_the_installation_prefix_is_rejected(tmp_path: Path) -> None:
    package = _plain_installation(tmp_path)
    (tmp_path / "elsewhere.json").write_bytes(b"{}")

    with pytest.raises(BuilderError, match="installation root"):
        read_bytes(tmp_path / "elsewhere.json", limit=65536, anchor=package)


def test_an_unsymlinked_installation_prefix_reads_and_resolves_to_itself(tmp_path: Path) -> None:
    package = _plain_installation(tmp_path)
    target = package / "_native" / "runtime-manifest.json"

    assert read_bytes(target, limit=65536, anchor=package) == b'{"ok":true}'
    assert checked_path(target, anchor=package) == target
    assert read_bytes(target, limit=65536) == b'{"ok":true}'


def test_parent_traversal_is_rejected_with_and_without_an_anchor(tmp_path: Path) -> None:
    package = _plain_installation(tmp_path)

    with pytest.raises(BuilderError, match="parent traversal"):
        checked_path(package / ".." / "escape.json", anchor=package)
    with pytest.raises(BuilderError, match="parent traversal"):
        checked_path(package / "_native" / "runtime-manifest.json", anchor=package / "..")


@needs_symlinks
def test_installed_reads_anchor_on_the_package_the_runtime_was_extracted_into(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package, _ = _installation(tmp_path)
    monkeypatch.setattr(installed_bundle, "_package", lambda: package)

    manifest = package / "_native" / "runtime-manifest.json"

    assert installed_bundle._read_installed(manifest, limit=65536) == b'{"ok":true}'
