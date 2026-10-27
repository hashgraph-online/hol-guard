"""The publishing path refuses a distribution whose core metadata it cannot upload."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.ci.core_metadata import core_metadata_version_error
from scripts.verify_native_runtime_release import (
    NativeReleaseError,
    _assert_sdist_core_metadata,
    _assert_wheel_core_metadata,
)

VERSION = "3.40.0"


def _metadata(declared: str) -> bytes:
    return f"Metadata-Version: {declared}\nName: hol-guard\nVersion: {VERSION}\n\nA description.\n".encode()


def _wheel(root: Path, declared: str) -> Path:
    wheel = root / f"hol_guard-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"hol_guard-{VERSION}.dist-info/METADATA", _metadata(declared))
        archive.writestr(f"hol_guard-{VERSION}.dist-info/WHEEL", b"Wheel-Version: 1.0\n")
    return wheel


def _sdist(root: Path, declared: str) -> Path:
    sdist = root / f"hol_guard-{VERSION}.tar.gz"
    payload = _metadata(declared)
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo(f"hol_guard-{VERSION}/PKG-INFO")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return sdist


@pytest.mark.parametrize("declared", ["2.1", "2.4"])
def test_a_supported_declaration_passes(tmp_path: Path, declared: str) -> None:
    _assert_wheel_core_metadata(_wheel(tmp_path, declared))
    _assert_sdist_core_metadata(_sdist(tmp_path, declared))


@pytest.mark.parametrize(
    "declared",
    [
        # A backend whose default moved past what the upload can read.
        "2.5",
        # PEP 440 reads these as equal to and below 2.4, so an upper bound on
        # the parsed version accepts them, yet neither names a core metadata
        # version and the upload rejects both.
        "2.4.0",
        "2.4.dev1",
    ],
)
def test_an_unpublishable_declaration_is_refused(tmp_path: Path, declared: str) -> None:
    with pytest.raises(NativeReleaseError, match=f"core metadata '{declared}'"):
        _assert_wheel_core_metadata(_wheel(tmp_path, declared))
    with pytest.raises(NativeReleaseError, match=f"core metadata '{declared}'"):
        _assert_sdist_core_metadata(_sdist(tmp_path, declared))


def test_a_header_without_a_declaration_is_refused(tmp_path: Path) -> None:
    wheel = tmp_path / f"hol_guard-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"hol_guard-{VERSION}.dist-info/METADATA", b"Name: hol-guard\n")
    with pytest.raises(NativeReleaseError, match="declares no core metadata version"):
        _assert_wheel_core_metadata(wheel)


def test_a_description_line_is_not_read_as_a_header() -> None:
    # The header ends at the first blank line. A description that quotes a
    # Metadata-Version line must not stand in for the declaration itself.
    metadata = f"Name: hol-guard\nVersion: {VERSION}\n\nMetadata-Version: 2.4\n"
    assert core_metadata_version_error(metadata, label="wheel") == "wheel declares no core metadata version"


@pytest.mark.parametrize("order", [("2.4", "2.5"), ("2.5", "2.4"), ("2.4", "2.4")])
def test_more_than_one_declaration_is_refused(order: tuple[str, str]) -> None:
    # Parsers disagree on which of two headers wins, so a second declaration is
    # refused even when it repeats the first.
    metadata = f"Metadata-Version: {order[0]}\nName: hol-guard\nMetadata-Version: {order[1]}\nVersion: {VERSION}\n"
    error = core_metadata_version_error(metadata, label="wheel")
    assert error is not None and "more than one core metadata version" in error
