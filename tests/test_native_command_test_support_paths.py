from __future__ import annotations

from pathlib import Path

import pytest

from tests import native_command_test_support as support


def test_native_fixture_prefers_release_and_falls_back_to_debug(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(support, "ROOT", tmp_path)
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", raising=False)
    release = tmp_path / "rust" / "target" / "release"
    debug = tmp_path / "rust" / "target" / "debug"
    release.mkdir(parents=True)
    debug.mkdir(parents=True)
    release_compiler = release / "guard-command-source"
    debug_runtime = debug / "hol-guard-runtime"
    release_compiler.touch()
    debug_runtime.touch()

    compiler, runtime = support._native_binaries()

    assert compiler == release_compiler
    assert runtime == debug_runtime


def test_native_fixture_accepts_explicit_binary_paths(tmp_path: Path, monkeypatch) -> None:
    runtime = tmp_path / "runtime.exe"
    compiler = tmp_path / "compiler.exe"
    runtime.touch()
    compiler.touch()
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))
    monkeypatch.setenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", str(compiler))
    monkeypatch.setenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", str(tmp_path / "development-compiler"))

    resolved_compiler, resolved_runtime = support._native_binaries()

    assert resolved_compiler == compiler
    assert resolved_runtime == runtime


def test_native_fixture_discovers_windows_suffix_on_any_host(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(support, "ROOT", tmp_path)
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", raising=False)
    release = tmp_path / "rust" / "target" / "release"
    release.mkdir(parents=True)
    compiler = release / "guard-command-source.exe"
    runtime = release / "hol-guard-runtime.exe"
    compiler.touch()
    runtime.touch()

    resolved_compiler, resolved_runtime = support._native_binaries()

    assert resolved_compiler == compiler
    assert resolved_runtime == runtime


def test_native_regression_gate_fails_when_binaries_are_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(support, "ROOT", tmp_path)
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", raising=False)
    monkeypatch.setenv("HOL_GUARD_NATIVE_REGRESSION", "1")

    with pytest.raises(pytest.fail.Exception, match="offline native test binaries"):
        support._native_binaries()
