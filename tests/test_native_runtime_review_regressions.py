from __future__ import annotations

from pathlib import Path

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


def test_command_model_reuses_the_canonical_native_error_parser() -> None:
    source = (
        ROOT / "src" / "codex_plugin_scanner" / "guard" / "native_command_model.py"
    ).read_text(encoding="utf-8")
    assert "_native_error(resident_payload) == \"native_overloaded\"" in source
    assert 'resident_payload == {"error": "native_overloaded"' not in source


def test_native_runtime_fixtures_use_the_platform_temp_directory() -> None:
    for relative in (
        "ci/native_runtime/test_guard_native_runtime_mutation_differential.py",
        "ci/native_runtime/test_native_runtime_recovery.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "tempfile.gettempdir()" in source
        assert 'dir="/tmp"' not in source
