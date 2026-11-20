from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard import native_runtime, native_transport_error
from codex_plugin_scanner.guard.native_runtime import (
    _INTEGRITY_FAILURE_REASONS,
    _native_error,
)
from codex_plugin_scanner.guard.native_runtime_resilience import _public_reason

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_compatibility_mismatches_remain_recoverable() -> None:
    assert "native_protocol_mismatch" not in _INTEGRITY_FAILURE_REASONS
    assert "native_version_mismatch" not in _INTEGRITY_FAILURE_REASONS
    assert "native_manifest_protocol_mismatch" in _INTEGRITY_FAILURE_REASONS
    assert "native_manifest_version_mismatch" in _INTEGRITY_FAILURE_REASONS


def test_privacy_safe_reason_validation_uses_bounded_safe_characters() -> None:
    assert _public_reason("native.resident-safe_code", "fallback") == "native.resident-safe_code"
    assert _public_reason("unsafe reason /private/path", "fallback") == "fallback"


def test_native_error_requires_a_bounded_known_error_envelope() -> None:
    assert _native_error({"error": "native_overloaded", "retryable": True}) == "native_overloaded"
    assert _native_error({"error": "native_overloaded", "retryable": False}) == "native_overloaded"
    assert _native_error({"error": "native_overloaded", "retryable": "yes"}) is None
    assert _native_error({"error": "native_overloaded", "retryable": True, "extra": 1}) is None
    assert _native_error({"error": "unknown", "retryable": True}) is None


def test_native_error_prefers_rust_transport_validation(monkeypatch) -> None:
    calls: list[tuple[object, tuple[str, ...], str, float, int]] = []
    candidate = ROOT / "runtime"

    monkeypatch.setattr(
        native_runtime,
        "native_runtime_status",
        lambda: SimpleNamespace(available=True, compatible=True, identity=SimpleNamespace(path=candidate)),
    )

    def run(path, args, *, input_text, timeout_seconds, output_limit, **kwargs):
        calls.append((path, args, input_text, timeout_seconds, output_limit))
        return '{"error":"native_overloaded"}'

    monkeypatch.setattr(native_runtime, "_run_native_process", run)
    assert native_transport_error.native_error({"error": "native_overloaded", "retryable": True}) == (
        "native_overloaded"
    )
    assert calls[0][:3] == (
        candidate,
        ("native-error-code", "--stdin"),
        '{"error":"native_overloaded","retryable":true}',
    )
    assert calls[0][4] == 16 * 1024
    assert calls[0][3] == 0.25


def test_native_error_keeps_deadline_bound_calls_in_process(monkeypatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(native_transport_error.time, "monotonic", lambda: 1.0)
    monkeypatch.setattr(native_runtime, "_run_native_process", lambda *args, **kwargs: calls.append(args))

    assert native_transport_error.native_error(
        {"error": "native_overloaded", "retryable": True}, deadline_monotonic=1.05
    ) == "native_overloaded"
    assert calls == []


def test_native_runtime_fixtures_use_the_platform_temp_directory() -> None:
    for relative in (
        "ci/native_runtime/test_guard_native_runtime_mutation_differential.py",
        "ci/native_runtime/test_native_runtime_recovery.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "tempfile.gettempdir()" in source
        assert 'dir="/tmp"' not in source
