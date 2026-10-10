"""Public catalog generation must not follow links or mix two source versions."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from tests.extension_builder_support import REPOSITORY

spec = importlib.util.spec_from_file_location(
    "guard_directory_io_export", REPOSITORY / "scripts/export_extension_directory.py"
)
assert spec and spec.loader
exporter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = exporter
spec.loader.exec_module(exporter)


def one_source(tmp_path: Path) -> tuple[Path, bytes]:
    parent = tmp_path / "contributions/extensions"
    parent.mkdir(parents=True)
    path = parent / "command.blitcp.json"
    content = (REPOSITORY / "contributions/extensions/command.blitcp.json").read_bytes()
    path.write_bytes(content)
    return path, content


def symlink(target: Path, link: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError:
        pytest.skip("This host does not permit unprivileged symlink creation")


def test_source_is_read_once_and_digest_matches_validated_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, content = one_source(tmp_path)
    original = exporter.validate_contribution

    def mutate_after_validation(payload: dict[str, object], *, filename: str) -> None:
        original(payload, filename=filename)
        path.write_bytes(b"a different source after validation")

    monkeypatch.setattr(exporter, "validate_contribution", mutate_after_validation)
    result = exporter._sources(tmp_path)["command.blitcp"]
    assert result[1]["id"] == "command.blitcp"
    assert result[2] == "sha256:" + hashlib.sha256(content).hexdigest()


def test_duplicate_keys_and_oversized_sources_are_rejected(tmp_path: Path) -> None:
    path, _ = one_source(tmp_path)
    path.write_bytes(b'{"id":"command.blitcp","id":"command.other"}')
    with pytest.raises(BuilderError):
        exporter._sources(tmp_path)
    path.write_bytes(b" " * (exporter.MAX_SOURCE_BYTES + 1))
    with pytest.raises(BuilderError):
        exporter._sources(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="Named pipes are a POSIX input case")
def test_fifo_source_is_rejected_without_waiting_for_a_writer(tmp_path: Path) -> None:
    path, _ = one_source(tmp_path)
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(BuilderError):
        exporter._sources(tmp_path)


def test_catalog_file_symlink_never_overwrites_target(tmp_path: Path) -> None:
    outside = tmp_path / "private.txt"
    outside.write_text("unchanged")
    output = tmp_path / "catalog.json"
    symlink(outside, output)
    with pytest.raises(BuilderError):
        exporter.write_catalog(output, "new catalog\n")
    assert outside.read_text() == "unchanged"


def test_catalog_parent_symlink_never_writes_through_it(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    parent = tmp_path / "linked"
    symlink(outside, parent, directory=True)
    with pytest.raises(BuilderError):
        exporter.write_catalog(parent / "catalog.json", "new catalog\n")
    assert list(outside.iterdir()) == []


def test_staging_failure_preserves_previous_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "catalog.json"
    output.write_bytes(b"previous\n")

    def fail_replace(*args: object, **kwargs: object) -> None:
        raise OSError("injected replacement failure")

    monkeypatch.setattr(exporter.os, "replace", fail_replace)
    with pytest.raises(OSError):
        exporter.write_catalog(output, "replacement\n")
    assert output.read_bytes() == b"previous\n"
    assert not list(tmp_path.glob(".guard-catalog-*"))


def test_successful_write_is_exact_and_cleans_staging(tmp_path: Path) -> None:
    output = tmp_path / "catalog.json"
    exporter.write_catalog(output, '{"entries":[]}\n')
    assert output.read_bytes() == b'{"entries":[]}\n'
    assert not list(tmp_path.glob(".guard-catalog-*"))


def test_nonregular_or_missing_output_parent_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        exporter.write_catalog(tmp_path, "replacement\n")
    with pytest.raises(ValueError):
        exporter.write_catalog(tmp_path / "missing/catalog.json", "replacement\n")
