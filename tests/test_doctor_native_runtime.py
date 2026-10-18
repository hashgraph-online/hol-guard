from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
from codex_plugin_scanner.guard.cli.doctor_native_runtime import NativeAvailabilityResult, doctor_native_availability
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


def _hold_owner_lock(state_base: Path):
    fcntl = pytest.importorskip("fcntl")
    state_base.mkdir(parents=True)
    handle = (state_base / "managed-resident-owner.v1.lock").open("w+b")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return handle


def _status_for(runtime_sha256: str) -> NativeRuntimeStatus:
    identity = NativeRuntimeIdentity(path=Path("hol-guard-runtime"), size=1, mtime_ns=1, sha256=runtime_sha256)
    return NativeRuntimeStatus(mode="auto", available=True, compatible=True, reason="native_ready", identity=identity)


def _availability_while_held(
    guard_home: Path, runtime_sha256: str, monkeypatch: pytest.MonkeyPatch
) -> NativeAvailabilityResult:
    # flock conflicts across separate open() calls, even inside one process.
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for(runtime_sha256))
    return doctor_native_availability(guard_home)


def test_a_resident_owned_by_another_install_is_explained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _hold_owner_lock(tmp_path / "native-runtime"):
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)

    assert result["reason_code"] == "native_resident_owner_busy"
    assert "Another Guard install" in result["message"]


def test_a_live_resident_of_this_runtime_is_not_called_another_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_base = tmp_path / "native-runtime"
    with _hold_owner_lock(state_base):
        resident = state_base / "resident-v3-aaaaaaaaaaaaaaaa"
        resident.mkdir()
        state = {"runtime_sha256": "a" * 64, "process_id": os.getpid()}
        (resident / "generation-1.json").write_text(json.dumps(state), encoding="utf-8")
        result = _availability_while_held(tmp_path, "a" * 64, monkeypatch)

    assert result["reason_code"] == "native_ready"
    assert "message" not in result


def test_a_free_owner_lock_is_not_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status_for("a" * 64))

    result = doctor_native_availability(tmp_path)

    assert result["reason_code"] == "native_ready"
    assert "message" not in result


def test_the_default_doctor_explains_a_busy_owner_without_running_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.adapters.diagnostic_probes import without_command_probes
    from codex_plugin_scanner.guard.cli import doctor_native_runtime

    def _must_not_run() -> NativeRuntimeStatus:
        raise AssertionError("the runtime must not run while command probes are off")

    monkeypatch.setattr(native_runtime, "native_runtime_status", _must_not_run)
    monkeypatch.setattr(doctor_native_runtime, "_passive_runtime_sha256", lambda: "a" * 64)
    with _hold_owner_lock(tmp_path / "native-runtime"), without_command_probes():
        result = doctor_native_availability(tmp_path)

    assert result["reason_code"] == "native_resident_owner_busy"
    assert result["available"] is None
    assert "Another Guard install" in result["message"]
