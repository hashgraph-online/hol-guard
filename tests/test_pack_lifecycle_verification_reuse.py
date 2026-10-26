from __future__ import annotations

import hashlib
import os

import pytest

from codex_plugin_scanner.guard.catalog_delivery import lifecycle
from codex_plugin_scanner.guard.extension_builder import native_executable_root

transport = lifecycle.transport


@pytest.fixture
def package(monkeypatch, tmp_path):
    native = tmp_path / "_native"
    native.mkdir()
    for name in (transport._MANIFEST_NAME, "runtime-manifest.json", "program.json"):
        (native / name).write_text("{}")
    (native / transport._COMPILER_NAME).write_bytes(b"#!/bin/sh\n")
    monkeypatch.setattr(transport, "_NATIVE_PACKAGE", native)
    monkeypatch.setattr(transport, "_PACKAGED_PROGRAM", native / "program.json")
    monkeypatch.setattr(lifecycle, "_verified", None)
    monkeypatch.setattr(native_executable_root, "_current", None)
    verifications = []

    def verify_manifest(path):
        raw = (native / transport._COMPILER_NAME).read_bytes()
        return {"compiler_sha256": hashlib.sha256(raw).hexdigest()}

    def verify_compiler(path, manifest):
        verifications.append(path)
        return path.read_bytes()

    monkeypatch.setattr(transport, "_verify_manifest", verify_manifest)
    monkeypatch.setattr(transport, "_verify_compiler", verify_compiler)
    yield native, verifications
    native_executable_root.release_copies()


def run():
    with lifecycle._verified_runtime() as executable:
        return executable


def test_unchanged_runtime_files_reuse_the_kept_copy(package):
    native, verifications = package
    first = run()
    assert run() == first
    assert len(verifications) == 1

    (native / "runtime-manifest.json").write_text('{"changed": true}')
    assert run() == first
    assert len(verifications) == 2
    assert run() == first
    assert len(verifications) == 2


def test_a_changed_copy_is_replaced_from_a_full_verification(package):
    _native, verifications = package
    first = run()
    os.chmod(first, 0o700)
    first.write_bytes(b"#!/bin/sh\r")
    replacement = run()
    assert replacement != first
    assert replacement.read_bytes() == b"#!/bin/sh\n"
    assert len(verifications) == 2


def test_missing_runtime_files_are_verified_every_time(package):
    native, verifications = package
    (native / "program.json").unlink()
    run()
    run()
    assert len(verifications) == 2
