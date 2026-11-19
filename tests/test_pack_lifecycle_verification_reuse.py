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
    # The stub manifest names no package version; the installed-version check has its own test.
    monkeypatch.setattr(transport, "_matches_installed_version", lambda version: True)
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
    # A Guard home keeps one copy per runtime, so the replacement may take the same path.
    assert replacement.read_bytes() == b"#!/bin/sh\n"
    assert len(verifications) == 2


def test_missing_runtime_files_are_verified_every_time(package):
    native, verifications = package
    (native / "program.json").unlink()
    run()
    run()
    assert len(verifications) == 2


def test_source_compiler_calls_share_one_verification_while_the_package_is_unchanged(package, monkeypatch):
    native, verifications = package
    monkeypatch.delenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", raising=False)
    spawned = []

    def bounded(arguments, payload, *, timeout, limit=None):
        spawned.append(arguments[0])
        return 0, b'{"schema": "ok"}', b""

    monkeypatch.setattr(transport, "_run_bounded", bounded)
    assert transport.run_source_compiler("schema") == {"schema": "ok"}
    assert transport.run_source_compiler("schema") == {"schema": "ok"}
    assert len(verifications) == 1
    assert spawned[0] == spawned[1]

    (native / transport._MANIFEST_NAME).write_text('{"changed": true}')
    transport.run_source_compiler("schema")
    assert len(verifications) == 2


def test_a_changed_installed_version_forces_a_full_verification(package, monkeypatch):
    _native, verifications = package
    versions = iter(["1.0.0", "2.0.0"])
    monkeypatch.setattr(transport, "_matches_installed_version", lambda version: next(versions) == "1.0.0")
    run()
    run()
    assert len(verifications) == 1
    run()
    assert len(verifications) == 2
