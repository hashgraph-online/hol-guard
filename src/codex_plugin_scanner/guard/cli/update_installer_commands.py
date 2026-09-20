"""Installed runtime classification and installer command construction."""

from __future__ import annotations

from pathlib import Path


def _binary_diagnostics(command: list[str], installer: str) -> dict[str, object]:
    resolved_binary = _update.shutil.which("hol-guard")
    installer_binary = command[0] if command else ""
    expected_script_dir = _update._expected_script_dir(installer_binary, installer)
    path_status = "unknown"
    if resolved_binary is None:
        path_status = "not_on_path"
    elif installer == "pipx":
        path_status = "pipx_shim_detected"
    elif installer == "uv":
        path_status = "uv_tool_shim_detected"
    elif expected_script_dir is not None and _update._script_dir(resolved_binary) == expected_script_dir:
        path_status = "matches_installer"
    else:
        path_status = "path_mismatch"
    return {
        "resolved_hol_guard": resolved_binary,
        "installer_binary": installer_binary,
        "expected_script_dir": str(expected_script_dir) if expected_script_dir is not None else None,
        "path_status": path_status,
    }


def _expected_script_dir(installer_binary: str, installer: str) -> Path | None:
    if installer != "pip" or not installer_binary:
        return None
    try:
        scripts_dir = _update.sysconfig.get_path("scripts")
    except Exception:
        scripts_dir = None
    if scripts_dir:
        return _update._directory_path(scripts_dir)
    return _update._script_dir(installer_binary)


def build_guard_install_surface_payload() -> dict[str, object]:
    if _update._is_desktop_managed_runtime():
        return {
            "installer": "desktop",
            "binary_diagnostics": {
                "resolved_hol_guard": str(_update.Path(_update.sys.executable).resolve()),
                "installer_binary": None,
                "expected_script_dir": None,
                "path_status": "bundled",
            },
        }
    installer = _update._installer_kind()
    return {
        "installer": installer,
        "binary_diagnostics": _update._binary_diagnostics(
            _update._update_command(installer, use_pypi=False), installer
        ),
    }


def _script_dir(path: str) -> Path:
    return _update._directory_path(_update.Path(path).expanduser().parent)


def _directory_path(path: str | Path) -> Path:
    directory = _update.Path(path).expanduser()
    if not directory.is_absolute():
        directory = _update.Path.cwd() / directory
    return directory.absolute()


def _current_version() -> str:
    try:
        return _update.importlib.metadata.version("hol-guard")
    except _update.importlib.metadata.PackageNotFoundError:
        return _update.package_version.__version__ if _update._is_frozen_runtime() else "unknown"


def _is_frozen_runtime() -> bool:
    return getattr(_update.sys, "frozen", False) is True


def _is_desktop_managed_runtime() -> bool:
    return _update.is_desktop_managed_runtime()


def _runtime_package_path() -> Path:
    return _update.Path(_update.__file__).resolve()


def _runtime_installer_kind() -> str | None:
    for parent in _update._runtime_package_path().parents:
        normalized_parent = _update.os.fspath(parent).replace(_update.os.sep, "/").lower()
        if "/pipx/venvs/" in normalized_parent and (parent / "pipx_metadata.json").is_file():
            return "pipx"
        if "/uv/tools/" in normalized_parent and (parent / "pyvenv.cfg").is_file():
            return "uv"
    return None


def _installer_kind() -> str:
    prefix_path = _update.Path(_update.sys.prefix).resolve()
    normalized_prefix = prefix_path.as_posix().lower()
    if "/uv/tools/" in normalized_prefix:
        return "uv"
    if (prefix_path / "pipx_metadata.json").exists():
        return "pipx"
    if "/pipx/venvs/" in normalized_prefix:
        return "pipx"
    return _update._runtime_installer_kind() or "pip"


def _should_upgrade_from_pypi(
    *,
    current_version: str,
    version_check: dict[str, object],
    vcs_install: dict[str, object] | None,
    local_source_install: dict[str, object] | None,
) -> bool:
    if local_source_install is not None and not bool(local_source_install.get("path_exists")):
        latest_version = version_check.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip():
            newer_than_pypi = _update._is_newer_version(current_version, latest_version.strip())
            if newer_than_pypi is True:
                return False
        return True
    if version_check.get("update_available") is not True:
        return False
    return vcs_install is not None


def _hol_guard_package_spec(target_version: str | None = None) -> str:
    if isinstance(target_version, str) and target_version.strip() and target_version.strip() not in {"unknown"}:
        return f"hol-guard=={target_version.strip()}"
    return "hol-guard"


def _target_version_is_prerelease(target_version: str | None) -> bool:
    if not isinstance(target_version, str) or not target_version.strip():
        return False
    try:
        return _update.Version(target_version.strip()).is_prerelease
    except _update.InvalidVersion:
        return False


def _installer_output_text(stdout: object, stderr: object) -> str:
    return "\n".join(part.strip() for part in (str(stdout or "").strip(), str(stderr or "").strip()) if part.strip())


def _contains_any(value: str, candidates: tuple[str, ...]) -> bool:
    return any(candidate in value for candidate in candidates)


def _is_pypi_propagation_failure(installer_output: str) -> bool:
    if not _update._contains_any(installer_output, _update._PYPI_PROPAGATION_FAILURE_HINTS):
        return False
    lowered = installer_output.lower()
    return not _update._contains_any(
        lowered, _update._PYPI_PROPAGATION_EXCLUSION_HINTS
    ) and not _update._PYPI_AUTH_STATUS_RE.search(installer_output)


def _dependency_conflict_message(installer_output: str) -> str | None:
    lowered = installer_output.lower()
    if "resolutionimpossible" not in lowered and "conflicting dependencies" not in lowered:
        return None
    if "rich" in lowered and "cisco-ai-skill-scanner" in lowered:
        return (
            "PyPI cannot install the latest HOL Guard release because hol-guard and "
            "cisco-ai-skill-scanner require incompatible rich versions. Wait for a fixed "
            "HOL Guard release, then run hol-guard update again."
        )
    return (
        "PyPI cannot install the latest HOL Guard release because of conflicting package "
        "dependencies. Check installer output for details."
    )


def _update_command(
    installer: str,
    *,
    use_pypi: bool = False,
    target_version: str | None = None,
    wheel_path: Path | None = None,
) -> list[str]:
    if wheel_path is not None:
        wheel = str(wheel_path)
        if installer == "uv":
            return ["uv", "tool", "install", "--force", wheel]
        if installer == "pipx":
            return ["pipx", "runpip", "hol-guard", "install", "--force-reinstall", wheel]
        return [_update.sys.executable, "-m", "pip", "install", "--force-reinstall", wheel]
    package = _update._hol_guard_package_spec(target_version)
    allow_prerelease = _update._target_version_is_prerelease(target_version)
    if use_pypi:
        if installer == "uv":
            command = ["uv", "tool", "install", "--force", "--refresh-package", "hol-guard"]
            if allow_prerelease:
                command.append("--prerelease=allow")
            command.append(package)
            return command
        if installer == "pipx":
            command = ["pipx", "runpip", "hol-guard", "install", "--upgrade", "--force-reinstall"]
            if allow_prerelease:
                command.append("--pre")
            command.append(package)
            return command
        command = [_update.sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall"]
        if allow_prerelease:
            command.append("--pre")
        command.append(package)
        return command
    if installer == "uv":
        return ["uv", "tool", "upgrade", "hol-guard"]
    if installer == "pipx":
        return ["pipx", "upgrade", "hol-guard"]
    return [_update.sys.executable, "-m", "pip", "install", "--upgrade", "hol-guard"]


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
