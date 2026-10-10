from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_runtime as native_runtime_module
from codex_plugin_scanner.guard.codex_hook_launch_runtime import isolated_hook_environment
from codex_plugin_scanner.guard.config import hook_fast_path_enabled
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


def test_hook_fast_path_defaults_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)
    assert hook_fast_path_enabled() is True


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


def test_windows_native_environment_uses_the_interpreter_crt_without_user_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "python"
    prefix.mkdir()
    (prefix / "vcruntime140.dll").write_bytes(b"crt")
    runtime_dir = tmp_path / "native"
    runtime_dir.mkdir()
    monkeypatch.setattr(native_runtime_module.os, "name", "nt")
    monkeypatch.setattr(native_runtime_module.sys, "base_prefix", str(prefix))
    monkeypatch.setattr(
        native_runtime_module,
        "_bundled_runtime_candidate",
        lambda: runtime_dir / "hol-guard-runtime.exe",
    )
    monkeypatch.setenv("PATH", str(tmp_path / "user-bin"))
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path / "Windows"))

    environment = native_runtime_module._isolated_environment()

    assert str(tmp_path / "user-bin") not in environment["PATH"].split(os.pathsep)
    assert str(prefix) in environment["PATH"].split(os.pathsep)
    assert str(tmp_path / "Windows" / "System32") in environment["PATH"].split(os.pathsep)


def test_override_is_ignored_in_auto_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "hol-guard-runtime"
    binary.write_text("not executable", encoding="utf-8")
    binary.chmod(0o700)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary))
    status = native_runtime_status()
    assert status.available is False


def _probe_identity(tmp_path: Path) -> native_runtime_module.NativeRuntimeIdentity:
    binary = tmp_path / "hol-guard-runtime"
    binary.write_bytes(b"probe-runtime")
    binary.chmod(0o700)
    metadata = binary.stat()
    return native_runtime_module.NativeRuntimeIdentity(
        path=binary.resolve(),
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        sha256=hashlib.sha256(b"probe-runtime").hexdigest(),
    )


def _capabilities_payload() -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "runtime_version": "3.0.0a1",
            "rule_digest": "b" * 64,
            "build_sha": "a" * 40,
            "target": "x86_64-unknown-linux-musl",
            "features": ["hook-envelope-v2"],
        }
    )


def test_capability_probe_records_retry_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed probe is remembered briefly: a second call inside the retry
    window must not spawn the binary again."""
    identity = _probe_identity(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        native_runtime_module,
        "_run_native_process",
        lambda *args, **kwargs: calls.append("probe") or None,
    )
    native_runtime_module._clear_capabilities_probe_state()

    key = (str(identity.path), identity.size, identity.mtime_ns, identity.sha256)
    assert native_runtime_module._capabilities_for_identity(*key) is None
    assert key in native_runtime_module._capabilities_retry_after
    assert native_runtime_module._capabilities_for_identity(*key) is None
    assert calls == ["probe"]


def test_capability_probe_respects_caller_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An exhausted caller deadline prevents any subprocess spawn."""
    identity = _probe_identity(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        native_runtime_module,
        "_run_native_process",
        lambda *args, **kwargs: calls.append("probe") or "",
    )
    native_runtime_module._clear_capabilities_probe_state()

    result = native_runtime_module._capabilities_for_identity(
        str(identity.path),
        identity.size,
        identity.mtime_ns,
        identity.sha256,
        deadline_monotonic=time.monotonic() - 1.0,
    )
    assert result is None
    assert calls == []


def test_capability_probe_rejects_malformed_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _probe_identity(tmp_path)
    monkeypatch.setattr(
        native_runtime_module,
        "_run_native_process",
        lambda *args, **kwargs: "not-json",
    )
    native_runtime_module._clear_capabilities_probe_state()

    assert (
        native_runtime_module._capabilities_for_identity(
            str(identity.path), identity.size, identity.mtime_ns, identity.sha256
        )
        is None
    )


def test_capability_probe_evicts_oldest_when_full(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _probe_identity(tmp_path)
    monkeypatch.setattr(
        native_runtime_module,
        "_run_native_process",
        lambda *args, **kwargs: _capabilities_payload(),
    )
    native_runtime_module._clear_capabilities_probe_state()
    for index in range(native_runtime_module._CAPABILITIES_CACHE_MAX):
        native_runtime_module._capabilities_cache[(f"old-{index}", 0, 0, "x")] = (
            native_runtime_module.NativeRuntimeCapabilities(
                protocol_version=1,
                runtime_version="0",
                rule_digest="b" * 64,
                build_sha="a" * 40,
                target="x",
                features=(),
            )
        )

    result = native_runtime_module._capabilities_for_identity(
        str(identity.path), identity.size, identity.mtime_ns, identity.sha256
    )

    assert result is not None
    assert len(native_runtime_module._capabilities_cache) <= (native_runtime_module._CAPABILITIES_CACHE_MAX)


def test_status_breaks_when_deadline_already_spent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The candidate loop must not start a probe once the budget is spent."""
    identity = _probe_identity(tmp_path)
    monkeypatch.setenv(native_runtime_module._NATIVE_BINARY_ENV, str(identity.path))
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    calls: list[str] = []
    monkeypatch.setattr(
        native_runtime_module,
        "_run_native_process",
        lambda *args, **kwargs: calls.append("probe") or "",
    )
    native_runtime_module._clear_capabilities_probe_state()

    status = native_runtime_module.native_runtime_status(deadline_monotonic=time.monotonic() - 1.0)

    assert status.available is False
    assert calls == []


def test_clear_capabilities_probe_state_resets_both_maps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native_runtime_module._capabilities_retry_after[("binary", 1, 2, "x")] = time.monotonic()
    native_runtime_module._capabilities_cache[("binary", 1, 2, "x")] = native_runtime_module.NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="0",
        rule_digest="b" * 64,
        build_sha="a" * 40,
        target="x",
        features=(),
    )

    native_runtime_module._clear_capabilities_probe_state()

    assert native_runtime_module._capabilities_cache == {}
    assert native_runtime_module._capabilities_retry_after == {}
