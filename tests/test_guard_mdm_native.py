from __future__ import annotations

import plistlib
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock
from xml.etree import ElementTree

import pytest

from codex_plugin_scanner.guard.mdm import native
from codex_plugin_scanner.guard.mdm.contracts import default_machine_paths


def test_unsupported_platform_never_reports_healthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native.platform, "system", lambda: "Linux")
    result = native.verify_native_install(tmp_path)
    assert not result.healthy
    assert result.reason_code == "native_platform_unsupported"


def test_windows_manifest_is_generated_after_runtime_signing() -> None:
    script = Path("scripts/mdm/windows/build-msi.ps1").read_text(encoding="utf-8")

    signing = script.index("/td SHA256 $_.FullName")
    manifest = script.index("generate-release-manifest.py') @ManifestArgs")
    assert signing < manifest


def test_windows_builder_embeds_product_version_before_signing() -> None:
    script = Path("scripts/mdm/windows/build-msi.ps1").read_text(encoding="utf-8")

    version_file = script.index("write-version-info.py")
    pyinstaller = script.index("uv run --no-sync pyinstaller")
    signing = script.index("signtool sign")
    assert version_file < pyinstaller < signing


def test_windows_version_resource_preserves_alpha_version(tmp_path: Path) -> None:
    output = tmp_path / "version-info.txt"
    subprocess.run(
        [
            sys.executable,
            "scripts/mdm/windows/write-version-info.py",
            "--version",
            "3.1.0a7",
            "--output",
            str(output),
        ],
        check=True,
    )

    payload = output.read_text()
    assert "prodvers=(3, 1, 0, 7)" in payload
    assert "StringStruct('ProductVersion', '3.1.0a7')" in payload


def test_windows_active_setup_expands_user_environment() -> None:
    root = ElementTree.parse("scripts/mdm/windows/hol-guard.wxs").getroot()
    registry_values = root.findall(".//{http://wixtoolset.org/schemas/v4/wxs}RegistryValue")
    stub_path = next(value for value in registry_values if value.attrib.get("Name") == "StubPath")

    assert stub_path.attrib["Type"] == "expandable"


def test_windows_installer_creates_machine_log_surface() -> None:
    root = ElementTree.parse("scripts/mdm/windows/hol-guard.wxs").getroot()
    namespace = "{http://wixtoolset.org/schemas/v4/wxs}"
    directories = root.findall(f".//{namespace}Directory")
    component_refs = root.findall(f".//{namespace}ComponentRef")

    assert any(item.attrib.get("Id") == "LogsFolder" and item.attrib.get("Name") == "Logs" for item in directories)
    assert any(item.attrib.get("Id") == "MachineLogs" for item in component_refs)


def test_windows_installer_applies_protected_machine_acls() -> None:
    root = ElementTree.parse("scripts/mdm/windows/hol-guard.wxs").getroot()
    namespace = "{http://wixtoolset.org/schemas/v4/wxs}"
    components = {item.attrib["Id"]: item for item in root.findall(f".//{namespace}Component")}
    expected = {
        "RuntimeAcl": "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
        "MachineState": "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        "MachineLogs": "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
    }

    for component_id, sddl in expected.items():
        permission = components[component_id].find(f"{namespace}CreateFolder/{namespace}PermissionEx")
        assert permission is not None
        assert permission.attrib["Sddl"] == sddl


def test_windows_builder_verifies_acl_records_in_built_msi() -> None:
    builder = Path("scripts/mdm/windows/build-msi.ps1").read_text(encoding="utf-8")
    verifier = Path("scripts/mdm/windows/verify-msi-acls.ps1").read_text(encoding="utf-8")

    assert "verify-msi-acls.ps1') -MsiPath $Msi" in builder
    assert "SELECT `LockObject`, `Table`, `SDDLText`, `Condition`" in verifier
    assert "InstallFolder =" in verifier
    assert "StateFolder =" in verifier
    assert "LogsFolder =" in verifier
    assert "$Expected.Remove($Row.LockObject)" in verifier


def test_windows_installer_registers_system_machine_health_task() -> None:
    root = ElementTree.parse("scripts/mdm/windows/hol-guard.wxs").getroot()
    namespace = "{http://wixtoolset.org/schemas/v4/wxs}"
    actions = {item.attrib["Id"]: item for item in root.findall(f".//{namespace}CustomAction")}
    sequence = {
        item.attrib["Action"]: item for item in root.findall(f".//{namespace}InstallExecuteSequence/{namespace}Custom")
    }

    install = actions["InstallMachineHealthTask"]
    provision_key = actions["ProvisionMachineDeviceKey"]
    provision_continuity = actions["ProvisionMachineContinuity"]
    rollback_install = actions["RollbackInstallMachineHealthTask"]
    remove = actions["RemoveMachineHealthTask"]
    rollback_remove = actions["RollbackRemoveMachineHealthTask"]
    assert install.attrib["ExeCommand"].endswith("mdm supervisor-install --json")
    assert provision_key.attrib["ExeCommand"].endswith("mdm device-key-provision --json")
    assert provision_key.attrib["Execute"] == "deferred"
    assert provision_key.attrib["Impersonate"] == "no"
    assert provision_key.attrib["Return"] == "check"
    assert provision_continuity.attrib["ExeCommand"].endswith("mdm continuity-provision --json")
    assert provision_continuity.attrib["Execute"] == "deferred"
    assert provision_continuity.attrib["Impersonate"] == "no"
    assert provision_continuity.attrib["Return"] == "check"
    assert remove.attrib["ExeCommand"].endswith("mdm supervisor-remove --json")
    assert install.attrib["Execute"] == remove.attrib["Execute"] == "deferred"
    assert rollback_install.attrib["Execute"] == rollback_remove.attrib["Execute"] == "rollback"
    assert install.attrib["Return"] == remove.attrib["Return"] == "check"
    assert rollback_install.attrib["Return"] == rollback_remove.attrib["Return"] == "ignore"
    assert install.attrib["Impersonate"] == remove.attrib["Impersonate"] == "no"
    assert sequence["ProvisionMachineDeviceKey"].attrib["After"] == "InstallFiles"
    assert sequence["ProvisionMachineContinuity"].attrib["After"] == "ProvisionMachineDeviceKey"
    assert sequence["RollbackInstallMachineHealthTask"].attrib["After"] == "ProvisionMachineContinuity"
    assert sequence["InstallMachineHealthTask"].attrib["After"] == "RollbackInstallMachineHealthTask"
    assert sequence["RollbackRemoveMachineHealthTask"].attrib["Before"] == "RemoveMachineHealthTask"
    assert sequence["RemoveMachineHealthTask"].attrib["Before"] == "RemoveFiles"
    assert "RevokeMachineDeviceKey" not in actions
    assert install.attrib["Directory"] == "InstallFolder"
    assert "[InstallFolder]" in install.attrib["ExeCommand"]
    assert "[INSTALLFOLDER]" not in install.attrib["ExeCommand"]


def test_windows_builder_verifies_supervisor_actions_in_built_msi() -> None:
    builder = Path("scripts/mdm/windows/build-msi.ps1").read_text(encoding="utf-8")
    verifier = Path("scripts/mdm/windows/verify-msi-supervisor.ps1").read_text(encoding="utf-8")

    assert "verify-msi-supervisor.ps1') -MsiPath $Msi" in builder
    assert "FROM `CustomAction`" in verifier
    assert "FROM `InstallExecuteSequence`" in verifier
    assert "($Type -band 0xC00) -ne 0xC00" in verifier
    assert "($Type -band 0x100)" in verifier
    assert "($Type -band 0x40)" in verifier
    assert "ProvisionMachineDeviceKey" in verifier
    assert "$Source -ne 'InstallFolder'" in verifier


def test_macos_installer_stages_protected_state_and_log_surfaces() -> None:
    script = Path("scripts/mdm/macos/build-pkg.sh").read_text(encoding="utf-8")

    assert 'readonly STATE="${STAGE}/Library/Application Support/HOL Guard State"' in script
    assert 'readonly LOGS="${STAGE}/Library/Logs/HOL Guard"' in script
    assert 'mkdir -p "${RUNTIME}" "${STATE}" "${LOGS}"' in script
    assert "--ownership recommended" in script


def test_macos_installer_registers_machine_health_launch_daemon() -> None:
    build = Path("scripts/mdm/macos/build-pkg.sh").read_text(encoding="utf-8")
    preinstall = Path("scripts/mdm/macos/pkg-scripts/preinstall").read_text(encoding="utf-8")
    postinstall = Path("scripts/mdm/macos/pkg-scripts/postinstall").read_text(encoding="utf-8")
    payload = plistlib.loads(Path("scripts/mdm/macos/org.hol.guard.machine-health.plist").read_bytes())

    assert '"${STAGE}/Library/LaunchDaemons"' in build
    assert "org.hol.guard.machine-health.plist" in build
    assert payload["StartInterval"] == 300
    assert payload["ProgramArguments"][-5:] == ["mdm", "integrity-snapshot", "--scope", "machine", "--json"]
    assert "/bin/launchctl bootstrap system" in postinstall
    assert "/bin/launchctl bootout" not in preinstall
    assert 'install -o root -g wheel -m 0600 "${LAUNCH_DAEMON}" "${ROLLBACK_PLIST}"' in preinstall
    assert postinstall.index("/bin/launchctl bootout") < postinstall.index("/bin/launchctl bootstrap")
    assert "trap restore_previous_supervisor ZERR EXIT" in postinstall
    assert "trap - ZERR EXIT" in postinstall
    armed = postinstall.index("trap restore_previous_supervisor ZERR EXIT")
    disarmed = postinstall.rindex("trap - ZERR EXIT")
    for command in (
        '/bin/launchctl bootstrap system "${LAUNCH_DAEMON}"',
        "/bin/launchctl enable system/org.hol.guard.machine-health",
        "/bin/launchctl kickstart -k system/org.hol.guard.machine-health",
    ):
        assert armed < postinstall.rindex(command) < disarmed
    assert postinstall.count("/bin/launchctl bootstrap") == 2
    assert 'install -o root -g wheel -m 0644 "${ROLLBACK_PLIST}" "${LAUNCH_DAEMON}"' in postinstall
    assert "/bin/launchctl enable system/org.hol.guard.machine-health" in postinstall
    assert postinstall.index("mdm device-key-provision") < postinstall.index("rollback_armed=1")
    assert postinstall.index("mdm device-key-provision") < postinstall.index("mdm continuity-provision")
    assert postinstall.index("mdm continuity-provision") < postinstall.index("rollback_armed=1")
    assert "device-key-revoke" not in postinstall


def test_native_installers_stage_device_key_helpers_before_manifest() -> None:
    macos = Path("scripts/mdm/macos/build-pkg.sh").read_text(encoding="utf-8")
    windows = Path("scripts/mdm/windows/build-msi.ps1").read_text(encoding="utf-8")

    assert macos.index("device-key-helper.swift") < macos.index("generate-release-manifest.py")
    assert macos.index("codesign --force --options runtime") < macos.index("generate-release-manifest.py")
    assert windows.index("device-key-helper.ps1") < windows.index("generate-release-manifest.py")


def test_macos_activation_preserves_spaced_home_paths() -> None:
    script = Path("scripts/mdm/macos/activate-current-user.sh").read_text(encoding="utf-8")

    assert "sed -n 's/^NFSHomeDirectory: //p'" in script
    assert "awk '{print $2}'" not in script


def test_platform_adapters_split_user_lifecycle_from_machine_coverage() -> None:
    macos_register = Path("scripts/mdm/macos/register-current-user-coverage.sh").read_text(encoding="utf-8")
    macos_deactivate = Path("scripts/mdm/macos/deactivate-user.sh").read_text(encoding="utf-8")
    windows_register = Path("scripts/mdm/windows/register-user-coverage.ps1").read_text(encoding="utf-8")
    windows_unregister = Path("scripts/mdm/windows/unregister-user-coverage.ps1").read_text(encoding="utf-8")

    assert '[[ "$(id -u)" -eq 0 ]] || exit 3' in macos_register
    assert "mdm harness-coverage-register" in macos_register
    assert macos_deactivate.index("mdm deactivate") < macos_deactivate.index("mdm harness-coverage-unregister")
    assert "mdm harness-coverage-register" in windows_register
    assert "mdm harness-coverage-unregister" in windows_unregister


def test_macos_signed_package_requires_inner_application_signature() -> None:
    script = Path("scripts/mdm/macos/build-pkg.sh").read_text(encoding="utf-8")

    assert "HOL_GUARD_APPLICATION_SIGN_IDENTITY" in script
    assert "--codesign-identity" in script
    assert script.index('pyinstaller "${pyinstaller_args[@]}"') < script.index("generate-release-manifest.py")


def test_windows_machine_paths_ignore_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROGRAMFILES", r"C:\Users\attacker\runtime")
    monkeypatch.setenv("PROGRAMDATA", r"C:\Users\attacker\state")

    paths = default_machine_paths(system_name="Windows")

    assert paths.runtime_root == Path(r"C:\Program Files") / "HOL Guard"
    assert paths.state_root == Path(r"C:\ProgramData") / "HOL Guard"


def test_windows_native_verification_uses_pinned_powershell_and_safe_process_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(
        return_value=subprocess.CompletedProcess(
            ["powershell.exe"],
            0,
            '{"Status":"Valid","Thumbprint":"0123456789ABCDEF0123456789ABCDEF01234567","Version":"3.1.0a1"}',
            "",
        )
    )

    monkeypatch.setattr(native, "_windows_directory", lambda: r"D:\Windows")
    monkeypatch.setattr(native.subprocess, "run", run)
    monkeypatch.setenv("PATH", r"C:\attacker")

    result = native._verify_windows(
        tmp_path,
        expected_thumbprints=("0123456789ABCDEF0123456789ABCDEF01234567",),
    )

    assert result.healthy
    command = run.call_args.args[0]
    kwargs = run.call_args.kwargs
    assert command[0] == r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert kwargs["cwd"] == r"D:\Windows\System32"
    assert kwargs["env"] == {
        "ComSpec": r"D:\Windows\System32\cmd.exe",
        "SystemRoot": r"D:\Windows",
        "WINDIR": r"D:\Windows",
    }
    assert result.version == "3.1.0a1"


def test_windows_native_verification_fails_closed_without_publisher_pin(tmp_path: Path) -> None:
    result = native._verify_windows(tmp_path, expected_thumbprints=())

    assert not result.healthy
    assert result.reason_code == "native_publisher_pin_absent"


def test_macos_native_verification_fails_closed_without_team_id(tmp_path: Path) -> None:
    result = native._verify_macos(tmp_path, expected_team_id=None)

    assert not result.healthy
    assert result.reason_code == "native_publisher_pin_absent"


def test_macos_native_verification_requires_matching_team_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = Mock(
        side_effect=[
            subprocess.CompletedProcess(["pkgutil"], 0, plistlib.dumps({"pkg-version": "3.1.0a1"}), b""),
            subprocess.CompletedProcess(["codesign", "--verify"], 0, b"", b""),
            subprocess.CompletedProcess(
                ["codesign", "-d"],
                0,
                "",
                "Executable=/path/hol-guard\nTeamIdentifier=TEAM123\n",
            ),
        ]
    )
    monkeypatch.setattr(native.subprocess, "run", run)

    result = native._verify_macos(tmp_path, expected_team_id="TEAM123")

    assert result.healthy
    assert result.version == "3.1.0a1"


def test_macos_native_verification_rejects_missing_receipt_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(
        side_effect=[
            subprocess.CompletedProcess(["pkgutil"], 0, plistlib.dumps({}), b""),
            subprocess.CompletedProcess(["codesign", "--verify"], 0, b"", b""),
            subprocess.CompletedProcess(["codesign", "-d"], 0, "", "TeamIdentifier=TEAM123\n"),
        ]
    )
    monkeypatch.setattr(native.subprocess, "run", run)

    result = native._verify_macos(tmp_path, expected_team_id="TEAM123")

    assert not result.healthy
    assert result.reason_code == "native_package_version_invalid"


def test_macos_native_verification_rejects_missing_team_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(
        side_effect=[
            subprocess.CompletedProcess(["pkgutil"], 0, plistlib.dumps({"pkg-version": "3.1.0a1"}), b""),
            subprocess.CompletedProcess(["codesign", "--verify"], 0, b"", b""),
            subprocess.CompletedProcess(["codesign", "-d"], 0, "", "Executable=/path/hol-guard\n"),
        ]
    )
    monkeypatch.setattr(native.subprocess, "run", run)

    result = native._verify_macos(tmp_path, expected_team_id="TEAM123")

    assert not result.healthy
    assert result.reason_code == "native_publisher_signature_invalid"


def test_windows_native_verification_rejects_unpinned_valid_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(
        return_value=subprocess.CompletedProcess(
            ["powershell.exe"],
            0,
            '{"Status":"Valid","Thumbprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","Version":"3.1.0a1"}',
            "",
        )
    )
    monkeypatch.setattr(native, "_windows_directory", lambda: r"D:\Windows")
    monkeypatch.setattr(native.subprocess, "run", run)

    result = native._verify_windows(
        tmp_path,
        expected_thumbprints=("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",),
    )

    assert not result.healthy
    assert result.reason_code == "native_publisher_signature_invalid"
