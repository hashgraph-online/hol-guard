"""Mapping exceptions are bounded immutable evidence, not directory exec grants."""

import hashlib
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import restricted_linux_mapping_plan as mapping
from codex_plugin_scanner.guard.runtime.restricted_linux_landlock import LinuxContainmentUnavailableError


def _image(path, *, library=False, needed=(), soname=None, entry=0):
    strings = bytearray(b"\x00")
    names = []
    for tag, name in [(1, name) for name in needed] + ([(14, soname)] if soname else []):
        names.append((tag, len(strings)))
        strings.extend(name.encode("ascii") + b"\x00")
    dynamic = [*names, (5, 176 + (len(names) + 3) * 16), (10, len(strings)), (0, 0)]
    tail = b"".join(struct.pack("<qQ", *record) for record in dynamic) + strings
    size = 176 + len(tail)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3 if library else 2,
        62,
        1,
        entry,
        64,
        0,
        0,
        64,
        56,
        2,
        0,
        0,
        0,
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, size, 4096)
    dyn = struct.pack("<IIQQQQQQ", 2, 4, 176, 176, 0, len(dynamic) * 16, len(dynamic) * 16, 8)
    path.write_bytes(header + load + dyn + tail)
    return path


def _collect(workspace, images, files, roots=()):
    return mapping.collect_mapping_evidence(
        images=set(images), read_files=set(files), runtime_roots=roots, workspace=workspace
    )


def test_only_dependency_closure_and_runtime_modules_receive_exceptions(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    system = tmp_path / "system"
    system.mkdir()
    program = _image(system / "runner", needed=("libordinary.so.1",))
    dependency = _image(system / "libordinary.so.1", library=True)
    unrelated = _image(system / "libunneeded.so", library=True)
    module = _image(workspace / "extension.node", library=True)
    note = workspace / "library.so.txt"
    note.write_text("Not an ELF library")
    records = _collect(workspace, [program], [dependency, unrelated, module, note])
    assert {record["path"] for record in records} == {str(program), str(dependency), str(module)}
    for record in records:
        assert record["sha256"] == hashlib.sha256(Path(record["path"]).read_bytes()).hexdigest()
        assert len(record["identity"]) == 5


def test_missing_dependency_fails_without_partial_evidence(tmp_path):
    program = _image(tmp_path / "runner", needed=("missing.so",))
    with pytest.raises(LinuxContainmentUnavailableError):
        _collect(tmp_path, [program], [])


def test_dependency_on_an_already_approved_loader_is_not_reclassified_as_library(tmp_path):
    loader = _image(tmp_path / "aaa-loader.so", entry=4096)
    program = _image(tmp_path / "zzz-runner", needed=(loader.name,))
    assert len(_collect(tmp_path, [loader, program], [loader])) == 2


def test_large_export_string_table_reads_only_bounded_dependency_names(tmp_path):
    library = _image(tmp_path / "ordinary.so", library=True)
    program = _image(tmp_path / "runner", needed=(library.name,))
    raw = bytearray(program.read_bytes())
    padding = 2 * 1024 * 1024
    raw.extend(bytes(padding))
    struct.pack_into("<Q", raw, 96, len(raw))  # PT_LOAD file size.
    struct.pack_into("<Q", raw, 104, len(raw))  # PT_LOAD memory size.
    original_size = struct.unpack_from("<Q", raw, 216)[0]  # DT_STRSZ value.
    struct.pack_into("<Q", raw, 216, original_size + padding)
    program.write_bytes(raw)
    assert len(_collect(tmp_path, [program], [library])) == 2


@pytest.mark.parametrize("name", ["../escape.so", "/tmp/escape.so", "bad\\name.so", "bad\nname.so"])
def test_dependency_names_cannot_inject_paths(tmp_path, name):
    program = _image(tmp_path / "runner", needed=(name,))
    with pytest.raises(LinuxContainmentUnavailableError):
        _collect(tmp_path, [program], [])


def test_program_shaped_workspace_library_cannot_claim_system_libc_exception(tmp_path):
    fake = _image(tmp_path / "libc.so.6", library=True, soname="libc.so.6", entry=4096)
    metadata = SimpleNamespace(st_size=fake.stat().st_size, st_uid=0, st_mode=0o100555)
    with fake.open("rb") as stream, pytest.raises(ValueError, match="Program image"):
        mapping._elf(stream, metadata, library=True)
    with fake.open("rb") as stream:
        assert mapping._elf(stream, metadata, library=True, system_library=True) == ("libc.so.6", ())


def test_unresolved_symlink_cannot_be_admitted_as_a_program(tmp_path):
    actual = _image(tmp_path / "runner")
    alias = tmp_path / "alias"
    alias.symlink_to(actual)
    with pytest.raises(LinuxContainmentUnavailableError):
        _collect(tmp_path, [alias], [])


def test_mapping_budget_fails_closed(tmp_path, monkeypatch):
    program = _image(tmp_path / "runner")
    monkeypatch.setattr(mapping, "_MAX_MAPPING_BYTES", program.stat().st_size - 1)
    with pytest.raises(LinuxContainmentUnavailableError):
        _collect(tmp_path, [program], [])
