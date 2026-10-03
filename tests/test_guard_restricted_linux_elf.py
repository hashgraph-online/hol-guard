"""Interpreter metadata is bounded input, not permission to run arbitrary loaders."""

import struct

import pytest

from codex_plugin_scanner.guard.runtime.restricted_linux_elf import resolve_linux_elf_loader
from codex_plugin_scanner.guard.runtime.restricted_linux_landlock import LinuxContainmentUnavailableError


def _image(path, *, interpreter=None, machine=183):
    identity = b"\x7fELF\x02\x01\x01" + bytes(9)
    count = 1 if interpreter is None else 2
    header = struct.pack("<16sHHIQQQIHHHHHH", identity, 2, machine, 1, 0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    programs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 64, 64, 4096)
    tail = b""
    if interpreter is not None:
        tail = interpreter
        programs += struct.pack("<IIQQQQQQ", 3, 4, 64 + 56 * count, 0, 0, len(tail), len(tail), 1)
    path.write_bytes(header + programs + tail)


def test_static_image_does_not_receive_an_unneeded_loader(tmp_path):
    image = tmp_path / "native"
    _image(image)
    assert resolve_linux_elf_loader(image) is None


@pytest.mark.parametrize(
    "interpreter", [b"/tmp/loader\x00", b"/bin/sh\x00", b"/lib/ld-linux-aarch64.so.1", b"/lib/ld\x00extra\x00"]
)
def test_unapproved_or_malformed_loader_cannot_receive_exec_grant(tmp_path, interpreter):
    image = tmp_path / "native"
    _image(image, interpreter=interpreter)
    with pytest.raises(LinuxContainmentUnavailableError):
        resolve_linux_elf_loader(image)


@pytest.mark.parametrize("content", [b"", b"\x7fELF", bytes(4096)])
def test_bad_native_metadata_does_not_fall_back_to_guessed_loader(tmp_path, content):
    image = tmp_path / "native"
    image.write_bytes(content)
    with pytest.raises(LinuxContainmentUnavailableError):
        resolve_linux_elf_loader(image)


def test_executable_symlink_must_already_be_resolved_by_owner(tmp_path):
    actual, alias = tmp_path / "native", tmp_path / "alias"
    _image(actual)
    alias.symlink_to(actual)
    with pytest.raises(LinuxContainmentUnavailableError):
        resolve_linux_elf_loader(alias)
