from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm import continuity
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _prepare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MachinePaths:
    paths = _paths(tmp_path)
    paths.state_root.mkdir()
    monkeypatch.setattr(continuity.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(continuity, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(continuity, "require_machine_device_context", lambda _system_name: None)
    monkeypatch.setattr(continuity, "_private_regular_file", lambda _metadata: True)
    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: ("active-key", frozenset({"active-key"})),
    )
    monkeypatch.setattr(
        continuity,
        "observe_boot",
        lambda **_kwargs: continuity.BootObservation("boot-a", 10_000_000_000),
    )
    return paths


def test_continuity_provision_is_idempotent_and_snapshot_read_is_immutable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)

    first = continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    before = state_path.read_bytes()
    before_stat = state_path.stat()
    second = continuity.provision_machine_continuity()
    verification = continuity.verify_installation_continuity(paths, system_name="Darwin")
    after_stat = state_path.stat()

    assert first == second
    assert len(first["machineInstallationId"]) == 32
    assert len(first["installationGeneration"]) == 32
    assert state_path.read_bytes() == before
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert verification.healthy is True
    assert verification.identity_reason_code == "installation_identity_active"
    assert verification.lease_reason_code == "lease_continuity_uninitialized"
    assert verification.record is not None and verification.record.last_issued_sequence == 0


def test_uninitialized_v1_state_without_lease_key_id_remains_compatible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    del payload["lastLeaseKeyId"]
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.healthy is True
    assert result.record is not None and result.record.last_lease_key_id is None


def test_missing_state_creates_a_fresh_generation_without_inheriting_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    first = continuity.provision_machine_continuity()
    (paths.state_root / "installation-continuity.json").unlink()

    second = continuity.provision_machine_continuity()

    assert second["machineInstallationId"] != first["machineInstallationId"]
    assert second["installationGeneration"] != first["installationGeneration"]
    assert second["sequence"] == 0


@pytest.mark.parametrize(
    ("mutation", "identity_reason"),
    [
        (lambda payload: payload.update(schemaVersion="wrong"), "installation_identity_invalid"),
        (lambda payload: payload.update(lastIssuedSequence=-1), "installation_identity_invalid"),
        (
            lambda payload: payload.update(keyIdAtGenerationCreation="replaced-key"),
            "installation_identity_key_mismatch",
        ),
    ],
)
def test_continuity_tamper_fails_without_rewriting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
    identity_reason: str,
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert callable(mutation)
    mutation(payload)
    state_path.write_text(json.dumps(payload), encoding="utf-8")
    before = state_path.read_bytes()

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "tampered"
    assert result.identity_reason_code == identity_reason
    assert state_path.read_bytes() == before
    with pytest.raises((OSError, ValueError)):
        continuity.provision_machine_continuity()
    assert state_path.read_bytes() == before


def test_continuity_accepts_retained_rotation_key_and_rejects_unrelated_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: ("new-key", frozenset({"new-key", "active-key"})),
    )
    assert continuity.verify_installation_continuity(paths, system_name="Darwin").healthy is True

    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: ("new-key", frozenset({"new-key"})),
    )
    result = continuity.verify_installation_continuity(paths, system_name="Darwin")
    assert result.state == "tampered"
    assert result.identity_reason_code == "installation_identity_key_mismatch"


def test_continuity_detects_same_boot_monotonic_regression(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload.update(
        lastIssuedSequence=8,
        lastLeaseDigest="a" * 64,
        lastLeaseBootSessionId="boot-a",
        lastLeaseMonotonicUptimeNs=20_000_000_000,
        lastLeaseKeyId="active-key",
    )
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "tampered"
    assert result.identity_reason_code == "installation_identity_active"
    assert result.lease_reason_code == "lease_continuity_monotonic_regression"


def test_continuity_allows_lower_uptime_after_reboot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload.update(
        lastIssuedSequence=8,
        lastLeaseDigest="a" * 64,
        lastLeaseBootSessionId="boot-before",
        lastLeaseMonotonicUptimeNs=20_000_000_000,
        lastLeaseKeyId="active-key",
    )
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.healthy is True
    assert result.lease_reason_code == "lease_continuity_active"


def test_boot_probe_failure_preserves_verified_installation_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    monkeypatch.setattr(
        continuity,
        "observe_boot",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("lease_continuity_boot_probe_failed")),
    )

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "unknown"
    assert result.identity_reason_code == "installation_identity_active"
    assert result.lease_reason_code == "lease_continuity_boot_probe_failed"
    assert result.record is not None


def test_rotation_in_progress_is_unknown_not_tamper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: (_ for _ in ()).throw(OSError("device_key_rotation_incomplete")),
    )

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "unknown"
    assert result.identity_reason_code == "installation_identity_probe_failed"
    assert result.lease_reason_code == "lease_continuity_probe_failed"


def test_maximum_sequence_is_degraded_not_healthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload.update(
        lastIssuedSequence=continuity._MAX_UINT64,
        lastLeaseDigest="a" * 64,
        lastLeaseBootSessionId="boot-before",
        lastLeaseMonotonicUptimeNs=1,
        lastLeaseKeyId="active-key",
    )
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "degraded"
    assert result.identity_reason_code == "installation_identity_active"
    assert result.lease_reason_code == "lease_continuity_sequence_exhausted"


def test_continuity_rejects_symlink_and_oversized_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    paths.state_root.mkdir()
    state_path = paths.state_root / "installation-continuity.json"
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    state_path.symlink_to(outside)

    symlink_result = continuity.verify_installation_continuity(paths, system_name="Darwin")
    assert symlink_result.identity_reason_code == "installation_identity_acl_invalid"

    state_path.unlink()
    state_path.write_bytes(b"x" * (continuity._MAX_STATE_BYTES + 1))
    monkeypatch.setattr(continuity, "_private_regular_file", lambda _metadata: True)
    oversized = continuity.verify_installation_continuity(paths, system_name="Darwin")
    assert oversized.identity_reason_code == "installation_identity_acl_invalid"


def test_linux_boot_observation_is_boot_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(continuity.time, "monotonic_ns", lambda: 123)
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: "boot-id\n")

    assert continuity.observe_boot(system_name="Linux") == continuity.BootObservation("boot-id", 123)


def test_macos_boot_observation_rejects_empty_kernel_identifier(monkeypatch: pytest.MonkeyPatch) -> None:
    class EmptyBootLib:
        def sysctlbyname(self, _name: object, output: object, size: object, *_args: object) -> int:
            if output is None:
                size_pointer = continuity.ctypes.cast(size, continuity.ctypes.POINTER(continuity.ctypes.c_size_t))
                size_pointer.contents.value = 1
            return 0

    monkeypatch.setattr(continuity.ctypes, "CDLL", lambda *_args, **_kwargs: EmptyBootLib())

    with pytest.raises(OSError, match="lease_continuity_boot_probe_failed"):
        continuity.observe_boot(system_name="Darwin")


def test_windows_boot_observation_rejects_zero_identifier(monkeypatch: pytest.MonkeyPatch) -> None:
    class TickCount:
        restype: object | None = None

        def __call__(self) -> int:
            return 3_000_000_000

    windll = SimpleNamespace(
        ntdll=SimpleNamespace(NtQuerySystemInformation=lambda *_args: 0),
        kernel32=SimpleNamespace(GetTickCount64=TickCount()),
    )
    monkeypatch.setattr(continuity.ctypes, "windll", windll, raising=False)

    with pytest.raises(OSError, match="lease_continuity_boot_probe_failed"):
        continuity.observe_boot(system_name="Windows")


def test_windows_boot_observation_preserves_64_bit_uptime(monkeypatch: pytest.MonkeyPatch) -> None:
    class QueryBoot:
        def __call__(self, _kind: object, target: object, *_args: object) -> int:
            continuity.ctypes.memmove(target, b"\x01" + b"\x00" * 15, 16)
            return 0

    class TickCount:
        restype: object | None = None

        def __call__(self) -> int:
            return 3_000_000_000

    windll = SimpleNamespace(
        ntdll=SimpleNamespace(NtQuerySystemInformation=QueryBoot()),
        kernel32=SimpleNamespace(GetTickCount64=TickCount()),
    )
    monkeypatch.setattr(continuity.ctypes, "windll", windll, raising=False)

    result = continuity.observe_boot(system_name="Windows")

    assert result.boot_session_id == "00000001-0000-0000-0000-000000000000"
    assert result.monotonic_uptime_ns == 3_000_000_000_000_000


def test_state_file_mode_is_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()

    assert os.stat(paths.state_root / "installation-continuity.json").st_mode & 0o777 == 0o600
    assert os.stat(paths.state_root / ".installation-continuity.lock").st_mode & 0o777 == 0o600


def test_continuity_provision_cli_is_prompt_free(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        commands_dispatch_mdm,
        "provision_machine_continuity",
        lambda: {
            "schemaVersion": "hol-guard-mdm-status.v1",
            "operation": "continuity-provision",
            "healthy": True,
            "state": "active",
            "reasonCodes": ["installation_identity_active"],
        },
    )

    assert cli.main(["mdm", "continuity-provision", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["operation"] == "continuity-provision"
