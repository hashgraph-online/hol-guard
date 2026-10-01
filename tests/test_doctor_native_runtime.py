from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli.doctor_native_runtime import doctor_native_availability
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus


def test_passive_scope_does_not_probe_or_repair_native_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_probe() -> NativeRuntimeStatus:
        pytest.fail("Passive diagnostics must not probe or change the native binary")

    monkeypatch.setattr(native_runtime, "native_runtime_status", unexpected_probe)
    with without_command_probes():
        assert doctor_native_availability() == {
            "mode": "unknown",
            "available": None,
            "compatible": None,
            "reason_code": "native_status_probe_skipped",
            "evaluation_verified": False,
        }


@pytest.mark.parametrize(
    ("available", "compatible", "reason"),
    [
        (False, False, "native_binary_missing"),
        (True, False, "native_manifest_version_mismatch"),
        (True, True, "native_available"),
    ],
)
def test_availability_preserves_validation_result_without_claiming_evaluation(
    monkeypatch: pytest.MonkeyPatch, available: bool, compatible: bool, reason: str
) -> None:
    status = NativeRuntimeStatus(mode="auto", available=available, compatible=compatible, reason=reason)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    assert doctor_native_availability() == {
        "mode": "auto",
        "available": available,
        "compatible": compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }


def test_availability_does_not_serialize_binary_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = NativeRuntimeIdentity(path=Path("/private/user/native-secret"), size=123, mtime_ns=456, sha256="a" * 64)
    status = NativeRuntimeStatus(
        mode="auto", available=True, compatible=True, reason="native_available", identity=identity
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    encoded = json.dumps(doctor_native_availability())
    assert "private" not in encoded
    assert "sha256" not in encoded
    assert "mtime" not in encoded


@pytest.mark.parametrize("exception", [OSError, RuntimeError, ValueError])
def test_failed_probe_does_not_disclose_exception(monkeypatch: pytest.MonkeyPatch, exception: type[Exception]) -> None:
    def failed_probe() -> NativeRuntimeStatus:
        raise exception("/private/user/native-secret")

    monkeypatch.setattr(native_runtime, "native_runtime_status", failed_probe)
    result = doctor_native_availability()
    assert result["reason_code"] == "native_status_probe_failed"
    assert result["mode"] == "unknown"
    assert result["available"] is False
    assert result["evaluation_verified"] is False
    assert "private" not in json.dumps(result)


def test_invalid_reason_is_not_disclosed(monkeypatch: pytest.MonkeyPatch) -> None:
    status = NativeRuntimeStatus(mode="auto", available=False, compatible=False, reason="/private/user/native-secret")
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status)
    assert doctor_native_availability()["reason_code"] == "native_status_reason_unavailable"
