"""Process-wide native runtime status cache: stat-only hits, fail-closed misses."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_runtime as native_runtime_module
import codex_plugin_scanner.guard.native_runtime_process_cache as process_cache
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

pytestmark = pytest.mark.skipif(not process_cache._ENABLED, reason="process cache is POSIX-only")


def _capabilities() -> native_runtime_module.NativeRuntimeCapabilities:
    return native_runtime_module.NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="0.0.0",
        rule_digest="b" * 64,
        build_sha="a" * 40,
        target="x86_64-unknown-linux-musl",
        features=(),
    )


@pytest.fixture
def probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Path, list[Path]]]:
    binary = tmp_path / "hol-guard-runtime"
    binary.write_bytes(b"process-cache-runtime")
    binary.chmod(0o700)
    manifest = tmp_path / "runtime-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    manifest.chmod(0o600)
    calls: list[Path] = []
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setattr(process_cache, "_MIN_AGE_NS", 0)

    def validate(candidate: Path) -> native_runtime_module.NativeRuntimeIdentity | None:
        calls.append(candidate)
        if not candidate.exists():
            return None
        metadata = candidate.stat()
        return native_runtime_module.NativeRuntimeIdentity(
            path=candidate.resolve(),
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
        )

    monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: (binary,))
    monkeypatch.setattr(native_runtime_module, "_validate_binary", validate)
    monkeypatch.setattr(native_runtime_module, "_is_bundled_candidate", lambda candidate: False)
    monkeypatch.setattr(
        native_runtime_module,
        "_capabilities_for_identity",
        lambda *args, **kwargs: _capabilities(),
    )
    native_runtime_module._clear_capabilities_probe_state()
    yield binary, manifest, calls
    native_runtime_module._clear_capabilities_probe_state()


def test_second_call_reuses_the_status_without_validating(probe: tuple[Path, Path, list[Path]]) -> None:
    _binary, _manifest, calls = probe
    first = native_runtime_status()
    second = native_runtime_status()
    assert first.reason == "native_ready"
    assert second is first
    assert len(calls) == 1


def test_a_touched_binary_recomputes(probe: tuple[Path, Path, list[Path]]) -> None:
    binary, _manifest, calls = probe
    first = native_runtime_status()
    binary.write_bytes(b"process-cache-runtime-longer")
    second = native_runtime_status()
    assert len(calls) == 2
    assert second is not first
    assert second.identity is not None and first.identity is not None
    assert second.identity.size != first.identity.size


def test_a_same_size_rewrite_recomputes(probe: tuple[Path, Path, list[Path]]) -> None:
    binary, _manifest, calls = probe
    native_runtime_status()
    stat_before = binary.stat()
    binary.write_bytes(b"process-cache-runtimX")
    os.utime(binary, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    native_runtime_status()
    assert len(calls) == 2


def test_a_removed_binary_fails_closed(probe: tuple[Path, Path, list[Path]]) -> None:
    binary, _manifest, _calls = probe
    assert native_runtime_status().available
    binary.unlink()
    status = native_runtime_status()
    assert not status.available
    assert not status.compatible


def test_a_fresh_binary_is_never_cached(probe: tuple[Path, Path, list[Path]], monkeypatch: pytest.MonkeyPatch) -> None:
    _binary, _manifest, calls = probe
    monkeypatch.setattr(process_cache, "_MIN_AGE_NS", int(time.time_ns()))
    native_runtime_status()
    native_runtime_status()
    assert len(calls) == 2


def test_a_swapped_manifest_recomputes_for_a_bundled_status(
    probe: tuple[Path, Path, list[Path]], monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, manifest_path, calls = probe
    manifest = native_runtime_module.NativeRuntimeManifest(
        schema="s",
        protocol_version=1,
        package_version="0.0.0",
        target="t",
        platform_tag="p",
        source_sha="a" * 40,
        rule_digest="b" * 64,
        runtime_sha256="0" * 64,
        runtime_size=1,
    )
    monkeypatch.setattr(native_runtime_module, "_is_bundled_candidate", lambda candidate: True)
    monkeypatch.setattr(native_runtime_module, "_manifest_for_bundled_identity", lambda identity: (manifest, None))
    monkeypatch.setattr(native_runtime_module, "_restore_bundled_runtime_execute_bit", lambda path: None)
    monkeypatch.setattr(
        native_runtime_module,
        "_capabilities_for_identity",
        lambda *args, **kwargs: native_runtime_module.NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0.0.0",
            rule_digest="b" * 64,
            build_sha="a" * 40,
            target="t",
            features=(),
        ),
    )
    first = native_runtime_status()
    assert first.manifest is manifest
    assert native_runtime_status() is first
    assert len(calls) == 1
    manifest_path.write_text('{"changed": true}', encoding="utf-8")
    native_runtime_status()
    assert len(calls) == 2
    manifest_path.unlink()
    native_runtime_status()
    assert len(calls) == 3
    assert binary.exists()


def test_a_fallback_candidate_is_never_cached(
    probe: tuple[Path, Path, list[Path]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, _manifest, calls = probe
    preferred = tmp_path / "missing-preferred"
    monkeypatch.setattr(native_runtime_module, "_runtime_candidates", lambda: (preferred, binary))
    first = native_runtime_status()
    assert first.identity is not None and first.identity.path == binary.resolve()
    preferred.write_bytes(b"preferred-runtime")
    preferred.chmod(0o700)
    second = native_runtime_status()
    assert second.identity is not None and second.identity.path == preferred.resolve()
    assert len(calls) == 3


def test_an_expired_deadline_ignores_a_cached_status(probe: tuple[Path, Path, list[Path]]) -> None:
    _binary, _manifest, calls = probe
    assert native_runtime_status().available
    expired = native_runtime_status(deadline_monotonic=time.monotonic() - 1.0)
    assert not expired.available
    assert len(calls) == 1


def test_a_file_swapped_while_the_status_is_computed_is_not_cached(
    probe: tuple[Path, Path, list[Path]], monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, _manifest, calls = probe
    real_validate = native_runtime_module._validate_binary

    def swap_after_validation(candidate: Path) -> native_runtime_module.NativeRuntimeIdentity | None:
        identity = real_validate(candidate)
        candidate.write_bytes(b"replacement-after-validation")
        return identity

    monkeypatch.setattr(native_runtime_module, "_validate_binary", swap_after_validation)
    native_runtime_status()
    monkeypatch.setattr(native_runtime_module, "_validate_binary", real_validate)
    native_runtime_status()
    assert len(calls) == 2
    assert binary.read_bytes() == b"replacement-after-validation"
