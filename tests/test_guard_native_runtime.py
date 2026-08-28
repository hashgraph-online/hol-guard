from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_runtime as native_runtime_module
from codex_plugin_scanner.guard.codex_hook_launch_runtime import isolated_hook_environment
from codex_plugin_scanner.guard.native_runtime import (
    native_mode,
    native_runtime_status,
    parity_signature,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewResponse


def test_native_mode_defaults_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_GUARD_NATIVE", raising=False)
    monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: ())
    assert native_mode() == "auto"
    status = native_runtime_status()
    assert status.mode == "auto"
    assert status.reason == "native_unavailable"


def test_isolated_hook_environment_keeps_native_mode_and_drops_loaders(tmp_path: Path) -> None:
    binary = tmp_path / "hol-guard-runtime"
    hostile = {
        "PATH": str(tmp_path / "bin"),
        "HOME": str(tmp_path / "home"),
        "HOL_GUARD_NATIVE": "off",
        "HOL_GUARD_NATIVE_BINARY": str(binary),
        "PYTHONPATH": str(tmp_path / "python-path"),
        "LD_PRELOAD": str(tmp_path / "preload.so"),
    }

    environment = isolated_hook_environment(hostile)

    assert environment["HOL_GUARD_NATIVE"] == "off"
    assert environment["HOL_GUARD_NATIVE_BINARY"] == str(binary)
    assert "PYTHONPATH" not in environment
    assert "LD_PRELOAD" not in environment


def test_explicit_off_remains_emergency_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    assert native_mode() == "off"
    status = native_runtime_status()
    assert status.mode == "off"
    assert status.reason == "native_disabled"


def test_invalid_native_mode_fails_to_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "unexpected")
    monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: ())
    assert native_mode() == "auto"
    assert native_runtime_status().reason == "native_unavailable"


def test_empty_native_mode_fails_to_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "  ")
    assert native_mode() == "auto"


def test_parity_signature_hashes_excerpt() -> None:
    response = HookReviewResponse(
        decision="allow",
        reason="reviewed",
        model_output_action="replace_with_reviewed_excerpt",
        reviewed_excerpt="safe excerpt",
        notice="excerpt",
        reason_code="reviewed_excerpt",
    )
    signature = parity_signature(response)
    assert signature[0] == "allow"
    assert signature[2] == "reviewed_excerpt"
    assert isinstance(signature[-1], str)
    assert "safe excerpt" not in json.dumps(signature)


@pytest.mark.skipif(os.name == "nt", reason="fake executable uses a POSIX shebang")
def test_explicit_shadow_runtime_is_validated_without_path_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "hol-guard-runtime"
    payload = {
        "protocol_version": 1,
        "runtime_version": "0.0",
        "rule_digest": "abc",
        "build_sha": "test",
        "target": "test",
        "features": [],
    }
    binary.write_text(
        "#!/bin/sh\nprintf '%s\\n' '" + json.dumps(payload, separators=(",", ":")) + "'\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "shadow")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary))
    status = native_runtime_status()
    assert status.available is True
    assert status.compatible is True
    assert status.identity is not None
    assert status.identity.path == binary.resolve()


@pytest.mark.skipif(os.name == "nt", reason="PyInstaller DATA drops POSIX execute bits")
def test_bundled_runtime_restores_owner_execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"native-runtime")
    runtime.chmod(0o644)
    monkeypatch.setattr(native_runtime_module, "_bundled_runtime_candidate", lambda: runtime)

    native_runtime_module._restore_bundled_runtime_execute_bit(runtime)

    assert stat.S_IMODE(runtime.stat().st_mode) & 0o111 == 0o111
    assert stat.S_IMODE(runtime.stat().st_mode) & 0o022 == 0


@pytest.mark.skipif(os.name == "nt", reason="PyInstaller DATA drops POSIX execute bits")
def test_bundled_runtime_skips_world_writable_execute_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"native-runtime")
    runtime.chmod(0o666)
    monkeypatch.setattr(native_runtime_module, "_bundled_runtime_candidate", lambda: runtime)

    native_runtime_module._restore_bundled_runtime_execute_bit(runtime)

    assert stat.S_IMODE(runtime.stat().st_mode) & 0o111 == 0


def test_override_is_ignored_in_auto_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "hol-guard-runtime"
    binary.write_text("not executable", encoding="utf-8")
    binary.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary))
    status = native_runtime_status()
    assert status.available is False
