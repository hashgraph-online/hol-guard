from __future__ import annotations

import json
import os
import secrets
import subprocess
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm import device_key
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _prepare_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MachinePaths:
    paths = _paths(tmp_path)
    paths.state_root.mkdir(parents=True)
    monkeypatch.setattr(device_key.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(device_key, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(device_key, "_require_machine_context", lambda _system_name: None)
    monkeypatch.setattr(device_key, "_machine_key_lock", lambda _paths: nullcontext())
    monkeypatch.setattr(device_key, "_bounded_private_file", lambda path: path.read_bytes())
    return paths


class _NativeKeys:
    def __init__(self) -> None:
        self.keys: dict[str, tuple[bytes, str]] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_after_create = False
        self.fail_delete_once = False

    def __call__(
        self, _paths: MachinePaths, verb: str, generation: str, *, system_name: str
    ) -> device_key.NativeKeyEvidence:
        assert system_name == "Darwin"
        self.calls.append((verb, generation))
        if verb == "create":
            private_key = ec.generate_private_key(ec.SECP256R1())
            public = private_key.public_key().public_bytes(
                device_key.serialization.Encoding.X962,
                device_key.serialization.PublicFormat.UncompressedPoint,
            )
            self.keys[generation] = (public, "os-protected")
            if self.fail_after_create:
                self.fail_after_create = False
                raise OSError("device_key_probe_failed")
        elif verb == "delete":
            if self.fail_delete_once:
                self.fail_delete_once = False
                raise OSError("device_key_revocation_incomplete")
            self.keys.pop(generation, None)
            return device_key.NativeKeyEvidence("absent", "unknown", None, "device_key_absent")
        material = self.keys.get(generation)
        if material is None:
            return device_key.NativeKeyEvidence("absent", "unknown", None, "device_key_absent")
        public, level = material
        return device_key.NativeKeyEvidence("active", level, public, "device_key_active")


def test_device_key_provision_is_idempotent_and_public(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare_lifecycle(tmp_path, monkeypatch)
    native = _NativeKeys()
    monkeypatch.setattr(device_key, "_run_helper", native)

    first = device_key.provision_machine_device_key()
    second = device_key.provision_machine_device_key()

    metadata = json.loads((paths.state_root / "device-key.json").read_text(encoding="utf-8"))
    assert first == second
    assert first["healthy"] is True
    assert first["protectionLevel"] == "os-protected"
    assert metadata["state"] == "active"
    assert metadata["pendingGeneration"] is None
    assert [verb for verb, _generation in native.calls].count("create") == 1
    encoded = json.dumps(first, sort_keys=True)
    assert "PRIVATE" not in encoded
    assert str(tmp_path) not in encoded
    assert "org.hol.guard.device-key" not in encoded


def test_device_key_provision_recovers_crash_after_native_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare_lifecycle(tmp_path, monkeypatch)
    native = _NativeKeys()
    native.fail_after_create = True
    monkeypatch.setattr(device_key, "_run_helper", native)

    with pytest.raises(OSError, match="device_key_probe_failed"):
        device_key.provision_machine_device_key()
    pending = json.loads((paths.state_root / "device-key.json").read_text(encoding="utf-8"))
    assert pending["state"] == "pending"

    recovered = device_key.provision_machine_device_key()

    assert recovered["healthy"] is True
    assert [verb for verb, _generation in native.calls].count("create") == 1


def test_device_key_rotation_retains_previous_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare_lifecycle(tmp_path, monkeypatch)
    native = _NativeKeys()
    monkeypatch.setattr(device_key, "_run_helper", native)
    original = device_key.provision_machine_device_key()

    rotated = device_key.rotate_machine_device_key()

    metadata = json.loads((paths.state_root / "device-key.json").read_text(encoding="utf-8"))
    assert rotated["keyId"] != original["keyId"]
    assert metadata["previous"]["keyId"] == original["keyId"]
    assert len(native.keys) == 2
    assert not any(verb == "delete" for verb, _generation in native.calls)
    with pytest.raises(OSError, match="device_key_previous_generation_pending"):
        device_key.rotate_machine_device_key()


def test_device_key_revoke_disables_first_and_retries_partial_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare_lifecycle(tmp_path, monkeypatch)
    native = _NativeKeys()
    monkeypatch.setattr(device_key, "_run_helper", native)
    device_key.provision_machine_device_key()
    device_key.rotate_machine_device_key()
    native.fail_delete_once = True

    with pytest.raises(OSError, match="device_key_revocation_incomplete"):
        device_key.revoke_machine_device_key()
    revoked = json.loads((paths.state_root / "device-key.json").read_text(encoding="utf-8"))
    assert revoked["state"] == "revoked"

    result = device_key.revoke_machine_device_key()

    assert result["reasonCodes"] == ["device_key_revoked"]
    assert native.keys == {}
    with pytest.raises(OSError, match="device_key_revoked"):
        device_key.provision_machine_device_key()


def test_atomic_metadata_write_skips_posix_directory_fsync_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    paths.state_root.mkdir()
    metadata = device_key.DeviceKeyMetadata("revoked", None, None, None, "2026-07-17T00:00:00+00:00")
    original_open = device_key.os.open

    def guarded_open(path: Path, flags: int, mode: int = 0o777) -> int:
        if path == paths.state_root:
            raise AssertionError("Windows must not open directories through the CRT")
        return original_open(path, flags, mode)

    monkeypatch.setattr(device_key.os, "name", "nt")
    monkeypatch.setattr(device_key.os, "open", guarded_open)

    device_key._atomic_metadata_write(paths, metadata)

    assert device_key._read_metadata(paths) == metadata


def test_device_key_verification_rejects_public_or_provider_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare_lifecycle(tmp_path, monkeypatch)
    native = _NativeKeys()
    monkeypatch.setattr(device_key, "_run_helper", native)
    device_key.provision_machine_device_key()
    metadata = device_key._read_metadata(paths)
    assert metadata is not None and metadata.active is not None
    generation = metadata.active.generation
    original_public, _level = native.keys[generation]

    replacement = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            device_key.serialization.Encoding.X962,
            device_key.serialization.PublicFormat.UncompressedPoint,
        )
    )
    native.keys[generation] = (replacement, "os-protected")
    mismatch = device_key.verify_machine_device_key(paths, system_name="Darwin")
    native.keys[generation] = (original_public, "hardware-backed")
    provider_substitution = device_key.verify_machine_device_key(paths, system_name="Darwin")

    assert mismatch.reason_code == "device_key_public_mismatch"
    assert provider_substitution.reason_code == "device_key_public_mismatch"


def test_device_key_verification_rejects_symlink_and_oversized_metadata(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.state_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (paths.state_root / "device-key.json").symlink_to(outside)

    symlink = device_key.verify_machine_device_key(paths, system_name="Darwin")
    (paths.state_root / "device-key.json").unlink()
    (paths.state_root / "device-key.json").write_bytes(b"x" * (device_key._MAX_METADATA_BYTES + 1))
    oversized = device_key.verify_machine_device_key(paths, system_name="Darwin")

    assert symlink.reason_code == "device_key_probe_failed"
    assert oversized.reason_code == "device_key_probe_failed"


def test_native_helper_response_is_strict_and_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    run = Mock(
        return_value=subprocess.CompletedProcess(
            ["helper"],
            0,
            json.dumps(
                {
                    "ok": True,
                    "state": "active",
                    "protectionLevel": "os-protected",
                    "publicKeyX963": "not-base64",
                    "reasonCode": "device_key_active",
                }
            ),
            "",
        )
    )
    monkeypatch.setattr(device_key.subprocess, "run", run)

    with pytest.raises(OSError, match="device_key_probe_failed"):
        device_key._run_helper(paths, "inspect", "a" * 32, system_name="Darwin")

    command = run.call_args.args[0]
    kwargs = run.call_args.kwargs
    assert command == [str(paths.runtime_root / "hol-guard-device-key"), "inspect", "a" * 32]
    assert kwargs["cwd"] == "/"
    assert kwargs["env"] == {
        "HOME": "/var/root",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": "/var/tmp",
    }


@pytest.mark.parametrize(
    ("verb", "return_code", "ok"),
    [("inspect", 1, False), ("delete", 0, True)],
)
def test_native_helper_absent_result_is_operation_aware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    verb: str,
    return_code: int,
    ok: bool,
) -> None:
    paths = _paths(tmp_path)
    run = Mock(
        return_value=subprocess.CompletedProcess(
            ["helper"],
            return_code,
            json.dumps(
                {
                    "ok": ok,
                    "state": "absent",
                    "protectionLevel": "os-protected",
                    "publicKeyX963": None,
                    "reasonCode": "device_key_absent",
                }
            ),
            "",
        )
    )
    monkeypatch.setattr(device_key.subprocess, "run", run)

    evidence = device_key._run_helper(paths, verb, "a" * 32, system_name="Darwin")

    assert evidence.state == "absent"


def test_native_helper_rejects_inconsistent_success_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    monkeypatch.setattr(
        device_key.subprocess,
        "run",
        Mock(
            return_value=subprocess.CompletedProcess(
                ["helper"],
                0,
                json.dumps(
                    {
                        "ok": False,
                        "state": "active",
                        "protectionLevel": "os-protected",
                        "publicKeyX963": None,
                        "reasonCode": "device_key_active",
                    }
                ),
                "",
            )
        ),
    )

    with pytest.raises(OSError, match="device_key_probe_failed"):
        device_key._run_helper(paths, "inspect", "a" * 32, system_name="Darwin")


@pytest.mark.parametrize(
    ("verb", "state", "return_code", "ok"),
    [("delete", "active", 0, True), ("create", "absent", 1, False)],
)
def test_native_helper_rejects_cross_operation_result_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    verb: str,
    state: str,
    return_code: int,
    ok: bool,
) -> None:
    paths = _paths(tmp_path)
    reason_code = "device_key_absent"
    if state == "active":
        reason_code = "device_key_active"
    monkeypatch.setattr(
        device_key.subprocess,
        "run",
        Mock(
            return_value=subprocess.CompletedProcess(
                ["helper"],
                return_code,
                json.dumps(
                    {
                        "ok": ok,
                        "state": state,
                        "protectionLevel": "os-protected",
                        "publicKeyX963": None,
                        "reasonCode": reason_code,
                    }
                ),
                "",
            )
        ),
    )

    with pytest.raises(OSError, match="device_key_probe_failed"):
        device_key._run_helper(paths, verb, "a" * 32, system_name="Darwin")


def test_device_key_cli_status_emits_only_component_state(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        commands_dispatch_mdm,
        "verify_machine_device_key",
        lambda _paths: device_key.KeyProtectionStatus("healthy", "os-protected", "device_key_active"),
    )

    exit_code = cli.main(["mdm", "device-key-status", "--json"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "device-key-status",
        "healthy": True,
        "state": "healthy",
        "protectionLevel": "os-protected",
        "reasonCodes": ["device_key_active"],
    }


@pytest.mark.skipif(device_key.platform.system() != "Darwin", reason="Swift Security helper requires macOS")
def test_macos_device_key_helper_typechecks() -> None:
    result = subprocess.run(
        [
            "xcrun",
            "swiftc",
            "-typecheck",
            "-framework",
            "Security",
            "-framework",
            "Foundation",
            "scripts/mdm/macos/device-key-helper.swift",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell helper requires Windows")
def test_windows_device_key_helper_parses_and_rejects_non_system_context() -> None:
    powershell = Path(os.environ["SYSTEMROOT"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    helper = Path("scripts/mdm/windows/device-key-helper.ps1").resolve()
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(helper),
            "-Verb",
            "inspect",
            "-Generation",
            "a" * 32,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    payload = json.loads(result.stdout)
    assert result.returncode == 2
    assert payload["reasonCode"] == "device_key_system_context_required"


@pytest.mark.skipif(
    device_key.platform.system() != "Darwin"
    or os.geteuid() != 0
    or os.environ.get("HOL_GUARD_RUN_SYSTEM_KEYCHAIN_TEST") != "1",
    reason="requires an explicitly enabled root managed-mac test host",
)
def test_macos_installed_device_key_helper_create_inspect_delete() -> None:
    helper = Path("/Library/Application Support/HOL Guard/hol-guard-device-key")
    assert helper.is_file()
    generation = secrets.token_hex(16)
    try:
        created = subprocess.run(
            [str(helper), "create", generation],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        inspected = subprocess.run(
            [str(helper), "inspect", generation],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert created.returncode == 0, created.stdout
        assert inspected.returncode == 0, inspected.stdout
        assert json.loads(created.stdout)["publicKeyX963"] == json.loads(inspected.stdout)["publicKeyX963"]
    finally:
        subprocess.run(
            [str(helper), "delete", generation],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )


def test_native_device_key_helpers_enforce_fixed_protected_providers() -> None:
    macos = Path("scripts/mdm/macos/device-key-helper.swift").read_text(encoding="utf-8")
    windows = Path("scripts/mdm/windows/device-key-helper.ps1").read_text(encoding="utf-8")

    assert "/Library/Keychains/System.keychain" in macos
    assert "kSecAttrIsExtractable: false" in macos
    assert "kSecACLAuthorizationSign" in macos
    assert "SecTrustedApplicationCopyData" in macos
    assert "String(data:" not in macos
    assert "SecureEnclave" not in macos
    assert "security " not in macos
    assert "Microsoft Platform Crypto Provider" in windows
    assert "Microsoft Software Key Storage Provider" in windows
    assert "CngExportPolicies]::None" in windows
    assert "CngKeyCreationOptions]::MachineKey" in windows
    assert "S-1-5-18" in windows
    assert "D:P(A;;FA;;;SY)(A;;FA;;;BA)" in windows
    assert "80090029" in windows
    assert "OverwriteExistingKey" not in windows
