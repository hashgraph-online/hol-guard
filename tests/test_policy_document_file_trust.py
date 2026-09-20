"""Private policy file trust and atomic output regressions."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_document import policy_document_digest
from codex_plugin_scanner.guard.policy_document_io import (
    PolicyFileTrustError,
    load_trusted_policy_document,
    read_trusted_policy_text,
    write_private_policy_text,
)
from codex_plugin_scanner.guard.policy_document_yaml import MAX_POLICY_BYTES, format_policy_document_yaml
from tests.test_policy_document_io import _policy_document, _private_directory


def test_trusted_file_round_trip_and_atomic_private_output(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "source.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o600)
    destination = directory / "output.yaml"

    document = load_trusted_policy_document(source)
    write_private_policy_text(destination, format_policy_document_yaml(document))

    assert policy_document_digest(load_trusted_policy_document(destination)) == policy_document_digest(document)
    assert destination.stat().st_mode & 0o777 == 0o600


def test_trusted_read_rejects_symlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    target.chmod(0o600)
    link = directory / "link.yaml"
    link.symlink_to(target)

    with pytest.raises(PolicyFileTrustError, match="policy_file_not_regular"):
        read_trusted_policy_text(link)


def test_trusted_read_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    trusted = _private_directory(tmp_path / "trusted")
    directory = _private_directory(trusted / "private")
    source = directory / "policy.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(trusted, target_is_directory=True)

    with pytest.raises(PolicyFileTrustError, match="policy_parent_unavailable"):
        read_trusted_policy_text(alias / "private" / source.name)


def test_trusted_read_rejects_hardlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    target.chmod(0o600)
    link = directory / "hardlink.yaml"
    os.link(target, link)

    with pytest.raises(PolicyFileTrustError, match="policy_file_link_count"):
        read_trusted_policy_text(link)


def test_trusted_read_rejects_group_writable_file(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "policy.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o620)

    with pytest.raises(PolicyFileTrustError, match="policy_file_insecure_mode"):
        read_trusted_policy_text(source)


def test_trusted_read_rejects_world_writable_parent(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "policy.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o600)
    directory.chmod(0o777)

    with pytest.raises(PolicyFileTrustError, match="policy_parent_insecure_mode"):
        read_trusted_policy_text(source)


def test_trusted_read_rejects_oversized_file(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "policy.yaml"
    source.write_bytes(b"x" * (MAX_POLICY_BYTES + 1))
    source.chmod(0o600)

    with pytest.raises(PolicyFileTrustError, match="policy_file_too_large"):
        read_trusted_policy_text(source)


def test_private_output_rejects_oversized_content(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    destination = directory / "policy.yaml"

    with pytest.raises(PolicyFileTrustError, match="policy_output_too_large"):
        write_private_policy_text(destination, "x" * (MAX_POLICY_BYTES + 1))

    assert not destination.exists()


def test_private_output_rejects_existing_symlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text("target", encoding="utf-8")
    target.chmod(0o600)
    destination = directory / "policy.yaml"
    destination.symlink_to(target)

    with pytest.raises(PolicyFileTrustError, match="policy_file_not_regular"):
        write_private_policy_text(destination, "replacement")

    assert target.read_text(encoding="utf-8") == "target"


def test_private_output_rejects_existing_hardlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text("target", encoding="utf-8")
    target.chmod(0o600)
    destination = directory / "policy.yaml"
    os.link(target, destination)

    with pytest.raises(PolicyFileTrustError, match="policy_file_link_count"):
        write_private_policy_text(destination, "replacement")

    assert target.read_text(encoding="utf-8") == "target"


def test_private_output_retries_short_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = _private_directory(tmp_path / "private")
    destination = directory / "policy.yaml"
    original_write = os.write

    def short_write(descriptor: int, payload: bytes | memoryview) -> int:
        return original_write(descriptor, payload[:1])

    monkeypatch.setattr(os, "write", short_write)

    write_private_policy_text(destination, "complete")

    assert destination.read_text(encoding="utf-8") == "complete"


def test_atomic_output_preserves_existing_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _private_directory(tmp_path / "private")
    destination = directory / "policy.yaml"
    destination.write_text("before", encoding="utf-8")
    destination.chmod(0o600)

    def fail_replace(_source: str, _destination: str, **_kwargs: int) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(PolicyFileTrustError, match="policy_output_write_failed"):
        write_private_policy_text(destination, "after")

    assert destination.read_text(encoding="utf-8") == "before"
    assert not list(directory.glob(".*.tmp"))
