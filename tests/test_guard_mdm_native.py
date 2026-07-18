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


def test_macos_activation_preserves_spaced_home_paths() -> None:
    script = Path("scripts/mdm/macos/activate-current-user.sh").read_text(encoding="utf-8")

    assert "sed -n 's/^NFSHomeDirectory: //p'" in script
    assert "awk '{print $2}'" not in script


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
