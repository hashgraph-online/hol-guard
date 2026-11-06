from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]

_NATIVE_INSTALL_RUNTIME_FILES = (
    ROOT / "scripts/mdm/macos/pkg-scripts/preinstall",
    ROOT / "scripts/mdm/macos/pkg-scripts/postinstall",
    ROOT / "scripts/mdm/macos/activate-current-user.sh",
    ROOT / "scripts/mdm/macos/deactivate-user.sh",
    ROOT / "scripts/mdm/macos/register-current-user-coverage.sh",
    ROOT / "scripts/mdm/windows/hol-guard.wxs",
    ROOT / "scripts/mdm/windows/register-user-coverage.ps1",
    ROOT / "scripts/mdm/windows/unregister-user-coverage.ps1",
)

_OFFLINE_LIFECYCLE_MODULES = (
    ROOT / "src/codex_plugin_scanner/guard/mdm/lifecycle.py",
    ROOT / "src/codex_plugin_scanner/guard/mdm/native.py",
    ROOT / "src/codex_plugin_scanner/guard/mdm/removal.py",
    ROOT / "src/codex_plugin_scanner/guard/mdm/supervisor.py",
    ROOT / "src/codex_plugin_scanner/guard/mdm/continuity.py",
    ROOT / "src/codex_plugin_scanner/guard/mdm/device_key.py",
    ROOT / "src/codex_plugin_scanner/guard/mdm/manifest.py",
)

_NETWORK_COMMAND_PATTERN = re.compile(
    r"(?ix)"
    r"(?:https?://|\bcurl\b|\bwget\b|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|"
    r"\bStart-BitsTransfer\b|\bbitsadmin\b)"
)
_ALLOWED_STATIC_URLS = ("http://wixtoolset.org/schemas/v4/wxs",)
_FORBIDDEN_GUARD_NETWORK_PREFIX = "codex_plugin_scanner.guard.mdm.network"


def _is_forbidden_guard_network_import(module: str, *, relative: bool = False) -> bool:
    if module.startswith(_FORBIDDEN_GUARD_NETWORK_PREFIX):
        return True
    return relative and (module == "network" or module.startswith("network_"))


def test_native_install_upgrade_rollback_and_uninstall_scripts_have_no_network_dependency() -> None:
    for path in _NATIVE_INSTALL_RUNTIME_FILES:
        text = path.read_text(encoding="utf-8")
        for allowed in _ALLOWED_STATIC_URLS:
            text = text.replace(allowed, "")
        assert _NETWORK_COMMAND_PATTERN.search(text) is None, path


def test_mdm_lifecycle_modules_do_not_import_network_clients() -> None:
    forbidden_roots = {"http", "requests", "socket", "urllib"}

    for path in _OFFLINE_LIFECYCLE_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".", 1)[0] not in forbidden_roots, (path, alias.name)
                    assert not _is_forbidden_guard_network_import(alias.name), (path, alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert module.split(".", 1)[0] not in forbidden_roots, (path, module)
                assert not _is_forbidden_guard_network_import(module, relative=node.level > 0), (path, module)


def test_native_package_builders_stage_runtime_before_packaging() -> None:
    macos = (ROOT / "scripts/mdm/macos/build-pkg.sh").read_text(encoding="utf-8")
    windows = (ROOT / "scripts/mdm/windows/build-msi.ps1").read_text(encoding="utf-8")

    assert "pyinstaller" in macos
    assert "pkgbuild" in macos
    assert macos.index("pyinstaller") < macos.index("pkgbuild")
    assert "pyinstaller" in windows
    assert "wix build" in windows
    assert windows.index("pyinstaller") < windows.index("wix build")
