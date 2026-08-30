"""Signed Core feed updates for frozen HOL Guard Desktop installs."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from packaging.version import InvalidVersion, Version

from ..macos_code_signing import verified_macos_signing_team
from ..mdm.contracts import ManagedNetworkPolicy
from ..mdm.network import ManagedNetworkError, managed_urlopen

UPDATE_SCHEMA = "hol-guard-core-update.v1"
INSTALL_SCHEMA = "hol-guard-core-install.v1"
BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
_RELEASE_DOWNLOAD_PREFIX = "https://github.com/hashgraph-online/hol-guard/releases/download/"
_DESKTOP_APP_ID = "org.hol.guard.desktop"
_MAX_MANIFEST_BYTES = 128 * 1024
_MAX_BINARY_BYTES = 300 * 1024 * 1024
_USER_AGENT = "HOL-Guard-Core-Updater"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
FetchBytes = Callable[[str, int], bytes]


class DesktopCoreUpdateError(RuntimeError):
    reason_code: str

    def __init__(self, reason_code: str, message: str | None = None) -> None:
        self.reason_code = reason_code
        super().__init__(message or reason_code)


class _ParsedCoreManifest(TypedDict):
    version: str
    source_commit: str
    target: str
    sha256: str
    size: int
    minimum_desktop_version: str


@dataclass(frozen=True, slots=True)
class DesktopCoreApplyResult:
    executable: Path
    version: str
    changed: bool


def is_frozen_runtime() -> bool:
    return getattr(sys, "frozen", False) is True


def is_desktop_managed_runtime() -> bool:
    if not is_frozen_runtime():
        return False
    if os.environ.get("HOL_GUARD_DESKTOP", "").strip() == "1":
        return True
    return executable_is_desktop_core(Path(sys.executable))


def desktop_core_updates_supported() -> bool:
    return platform_target() == "aarch64-apple-darwin"


def desktop_core_uses_alpha_channel(current_version: str, *, requested_alpha: bool) -> bool:
    _ = current_version
    return requested_alpha


def desktop_core_release_series(version: str) -> tuple[int, int] | None:
    try:
        parsed = Version(version)
    except InvalidVersion:
        return None
    return (parsed.major, parsed.minor)


def pypi_desktop_core_versions(payload: object, *, include_alpha: bool) -> list[str]:
    if not isinstance(payload, dict):
        return []
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        return []
    versions: list[str] = []
    for version_text, files in releases.items():
        if not isinstance(version_text, str) or not version_text.strip():
            continue
        try:
            parsed_version = Version(version_text)
        except InvalidVersion:
            continue
        if not _version_matches_channel(parsed_version, include_alpha=include_alpha):
            continue
        if _release_files_are_available(files):
            versions.append(version_text.strip())
    return versions


def pypi_alpha_versions(payload: object) -> list[str]:
    return pypi_desktop_core_versions(payload, include_alpha=True)


def _release_files_are_available(files: object) -> bool:
    if not isinstance(files, list):
        return False
    return any(isinstance(item, dict) and not item.get("yanked") for item in files)


def select_desktop_core_latest(
    current_version: str,
    candidates: list[str],
    *,
    include_alpha: bool = True,
) -> str | None:
    series = desktop_core_release_series(current_version)
    if series is None:
        return None
    matching: list[tuple[Version, str]] = []
    for text in candidates:
        candidate = text.strip()
        if not candidate:
            continue
        try:
            parsed = Version(candidate)
        except InvalidVersion:
            continue
        if (parsed.major, parsed.minor) != series:
            continue
        if not _version_matches_channel(parsed, include_alpha=include_alpha):
            continue
        matching.append((parsed, candidate))
    if not matching:
        return None
    return max(matching, key=lambda item: item[0])[1]


def platform_target() -> str | None:
    system = sys.platform
    machine = platform.machine().lower()
    if system == "darwin" and machine in {"arm64", "aarch64"}:
        return "aarch64-apple-darwin"
    return None


def apply_desktop_core_update(
    *,
    current_version: str,
    target_version: str,
    include_alpha: bool,
    network_policy: ManagedNetworkPolicy | None = None,
    fetch_bytes: FetchBytes | None = None,
) -> DesktopCoreApplyResult:
    target = platform_target()
    if target is None:
        raise DesktopCoreUpdateError("desktop_core_platform_unsupported")
    normalized_target = _safe_version_component(target_version)
    if _version_is_not_newer(target_version, current_version):
        return DesktopCoreApplyResult(
            executable=Path(sys.executable).resolve(),
            version=current_version,
            changed=False,
        )
    try:
        parsed_target = Version(target_version)
    except InvalidVersion as error:
        raise DesktopCoreUpdateError("desktop_core_channel_unsupported") from error
    if not _version_matches_channel(parsed_target, include_alpha=include_alpha):
        raise DesktopCoreUpdateError("desktop_core_channel_unsupported")
    target_is_alpha = parsed_target.pre is not None and parsed_target.pre[0] == "a"
    channel = "alpha" if target_is_alpha else "stable"
    tag = f"alpha/v{normalized_target}" if target_is_alpha else f"v{normalized_target}"
    artifact = f"hol-guard-core-{normalized_target}-{target}"

    def _default_download(url: str, limit: int) -> bytes:
        return _download_bytes(url, limit, network_policy=network_policy)

    downloader: FetchBytes = fetch_bytes or _default_download
    manifest = _parse_manifest(
        downloader(_release_url(tag, f"{artifact}.json"), _MAX_MANIFEST_BYTES),
        expected_version=normalized_target,
        expected_tag=tag,
        expected_target=target,
        expected_artifact=artifact,
        expected_channel=channel,
    )
    _enforce_minimum_desktop_version(manifest["minimum_desktop_version"])
    binary = downloader(_release_url(tag, artifact), _MAX_BINARY_BYTES)
    if len(binary) != manifest["size"] or _sha256_hex(binary) != manifest["sha256"]:
        raise DesktopCoreUpdateError("desktop_core_integrity_mismatch")
    trusted_team = _macos_signing_team(Path(sys.executable)) if sys.platform == "darwin" else None
    try:
        with tempfile.TemporaryDirectory(prefix="hol-guard-core-update-") as scratch_root:
            staged = Path(scratch_root) / _executable_name()
            _ = staged.write_bytes(binary)
            _make_executable(staged)
            _verify_candidate(staged, expected_team=trusted_team, expected_sha256=manifest["sha256"])
            installed = _install_managed_core(staged, manifest, target)
    except OSError as error:
        raise DesktopCoreUpdateError("desktop_core_install_failed") from error
    return DesktopCoreApplyResult(executable=installed, version=normalized_target, changed=True)


def desktop_core_root() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / _DESKTOP_APP_ID / "core"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "").strip()
        if not appdata:
            raise DesktopCoreUpdateError("desktop_core_home_unavailable")
        return Path(appdata) / _DESKTOP_APP_ID / "core"
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / _DESKTOP_APP_ID / "core"


def executable_is_desktop_core(executable: Path) -> bool:
    try:
        resolved = executable.expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    posix = resolved.as_posix().lower()
    if f"{_DESKTOP_APP_ID.lower()}/core/versions/" in posix:
        return True
    if "hol guard.app/" in posix:
        return True
    parent = resolved.parent
    return any((parent / sibling).is_file() for sibling in ("hol-guard-desktop", "hol-guard-desktop.exe"))


def _version_matches_channel(version: Version, *, include_alpha: bool) -> bool:
    if not version.is_prerelease:
        return True
    return include_alpha and version.pre is not None and version.pre[0] == "a"


def _version_is_not_newer(target_version: str, current_version: str) -> bool:
    try:
        return Version(target_version) <= Version(current_version)
    except InvalidVersion:
        return False


def _safe_version_component(value: str) -> str:
    candidate = value.strip()
    if _SAFE_VERSION_RE.fullmatch(candidate) is None:
        raise DesktopCoreUpdateError("desktop_core_version_invalid")
    return candidate


def _executable_name() -> str:
    return "hol-guard.exe" if sys.platform == "win32" else "hol-guard"


def _release_url(tag: str, name: str) -> str:
    encoded_tag = tag.replace("/", "%2F")
    return f"{_RELEASE_DOWNLOAD_PREFIX}{encoded_tag}/{name}"


def _download_bytes(url: str, limit: int, *, network_policy: ManagedNetworkPolicy | None) -> bytes:
    if not url.startswith(_RELEASE_DOWNLOAD_PREFIX):
        raise DesktopCoreUpdateError("desktop_core_source_untrusted")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/octet-stream"},
    )
    try:
        with managed_urlopen(request, timeout=60.0, policy=network_policy) as response:
            payload = response.read(limit + 1)
    except (ManagedNetworkError, OSError, TimeoutError, urllib.error.URLError) as error:
        raise DesktopCoreUpdateError("desktop_core_download_failed") from error
    if not payload or len(payload) > limit:
        raise DesktopCoreUpdateError("desktop_core_download_failed")
    return payload


def _parse_manifest(
    raw: bytes,
    *,
    expected_version: str,
    expected_tag: str,
    expected_target: str,
    expected_artifact: str,
    expected_channel: str,
) -> _ParsedCoreManifest:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DesktopCoreUpdateError("desktop_core_manifest_invalid") from error
    if not isinstance(decoded, dict):
        raise DesktopCoreUpdateError("desktop_core_manifest_invalid")
    payload: dict[object, object] = {key: value for key, value in decoded.items()}
    sha256 = payload.get("sha256")
    source_commit = payload.get("sourceCommit")
    size = payload.get("size")
    minimum_desktop_version = payload.get("minimumDesktopVersion")
    if (
        payload.get("schema") != UPDATE_SCHEMA
        or payload.get("channel") != expected_channel
        or payload.get("version") != expected_version
        or payload.get("sourceTag") != expected_tag
        or payload.get("target") != expected_target
        or payload.get("artifact") != expected_artifact
        or payload.get("bootstrapSchema") != BOOTSTRAP_SCHEMA
        or not isinstance(sha256, str)
        or _SHA256_RE.fullmatch(sha256.lower()) is None
        or not isinstance(source_commit, str)
        or _COMMIT_RE.fullmatch(source_commit.lower()) is None
        or type(size) is not int
        or size <= 0
        or size > _MAX_BINARY_BYTES
        or not isinstance(minimum_desktop_version, str)
        or not minimum_desktop_version.strip()
    ):
        raise DesktopCoreUpdateError("desktop_core_manifest_invalid")
    try:
        _ = Version(minimum_desktop_version.strip())
    except InvalidVersion as error:
        raise DesktopCoreUpdateError("desktop_core_manifest_invalid") from error
    return {
        "version": expected_version,
        "source_commit": source_commit.lower(),
        "target": expected_target,
        "sha256": sha256.lower(),
        "size": size,
        "minimum_desktop_version": minimum_desktop_version.strip(),
    }


def _enforce_minimum_desktop_version(minimum: str) -> None:
    installed = os.environ.get("HOL_GUARD_DESKTOP_VERSION", "").strip()
    if not installed:
        return
    try:
        if Version(installed) < Version(minimum):
            raise DesktopCoreUpdateError("desktop_core_desktop_too_old")
    except InvalidVersion as error:
        raise DesktopCoreUpdateError("desktop_core_desktop_version_invalid") from error


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _make_executable(path: Path) -> None:
    if os.name == "nt":
        return
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _verify_candidate(path: Path, *, expected_team: str | None, expected_sha256: str) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise DesktopCoreUpdateError("desktop_core_integrity_mismatch")
    if sys.platform != "darwin":
        return
    if not _macos_codesign_ok(path):
        raise DesktopCoreUpdateError("desktop_core_signature_invalid")
    actual_team = _macos_signing_team(path)
    if expected_team is None or actual_team != expected_team:
        raise DesktopCoreUpdateError("desktop_core_signature_mismatch")


def _macos_codesign_ok(path: Path) -> bool:
    return verified_macos_signing_team(path) is not None


def _macos_signing_team(path: Path) -> str:
    team = verified_macos_signing_team(path)
    if team is None:
        raise DesktopCoreUpdateError("desktop_core_signature_invalid")
    return team


def _reject_symlink(path: Path) -> None:
    try:
        if path.is_symlink():
            raise DesktopCoreUpdateError("desktop_core_path_untrusted")
    except OSError as error:
        raise DesktopCoreUpdateError("desktop_core_path_untrusted") from error


def _install_managed_core(staged: Path, manifest: _ParsedCoreManifest, target: str) -> Path:
    root = desktop_core_root()
    versions_root = root / "versions"
    version_dir = versions_root / manifest["version"]
    installed = version_dir / _executable_name()
    current = root / "current.json"
    for path in (root, versions_root, version_dir, installed, current):
        _reject_symlink(path)
    version_dir.mkdir(parents=True, exist_ok=True)
    for path in (root, versions_root, version_dir, installed):
        _reject_symlink(path)
    _ = shutil.copy2(staged, installed)
    _reject_symlink(installed)
    _make_executable(installed)
    _verify_candidate(
        installed,
        expected_team=_macos_signing_team(Path(sys.executable)) if sys.platform == "darwin" else None,
        expected_sha256=manifest["sha256"],
    )
    pointer = {
        "schema": INSTALL_SCHEMA,
        "version": manifest["version"],
        "sourceCommit": manifest["source_commit"],
        "target": target,
        "relativePath": f"versions/{manifest['version']}/{_executable_name()}",
        "sha256": manifest["sha256"],
        "installedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    _reject_symlink(current)
    temporary = current.with_name(f".current.{os.getpid()}.tmp")
    _reject_symlink(temporary)
    _ = temporary.write_text(json.dumps(pointer, indent=2) + "\n", encoding="utf-8")
    _ = temporary.replace(current)
    _reject_symlink(current)
    return installed


__all__ = [
    "DesktopCoreApplyResult",
    "DesktopCoreUpdateError",
    "apply_desktop_core_update",
    "desktop_core_release_series",
    "desktop_core_root",
    "desktop_core_updates_supported",
    "desktop_core_uses_alpha_channel",
    "executable_is_desktop_core",
    "is_desktop_managed_runtime",
    "is_frozen_runtime",
    "platform_target",
    "pypi_alpha_versions",
    "pypi_desktop_core_versions",
    "select_desktop_core_latest",
]
