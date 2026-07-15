from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

import pytest

from codex_plugin_scanner.guard.mdm import native


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


def test_windows_active_setup_expands_user_environment() -> None:
    root = ElementTree.parse("scripts/mdm/windows/hol-guard.wxs").getroot()
    registry_values = root.findall(".//{http://wixtoolset.org/schemas/v4/wxs}RegistryValue")
    stub_path = next(value for value in registry_values if value.attrib.get("Name") == "StubPath")

    assert stub_path.attrib["Type"] == "expandable"


def test_macos_activation_preserves_spaced_home_paths() -> None:
    script = Path("scripts/mdm/macos/activate-current-user.sh").read_text(encoding="utf-8")

    assert "sed -n 's/^NFSHomeDirectory: //p'" in script
    assert "awk '{print $2}'" not in script
