"""Signed Core feed updates for frozen HOL Guard Desktop installs."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TypedDict

from packaging.version import InvalidVersion, Version

from ..macos_code_signing import verified_macos_signing_team
from ..mdm.contracts import ManagedNetworkPolicy
from ..mdm.network import ManagedNetworkError, managed_urlopen
from .desktop_core_paths import executable_is_desktop_core

UPDATE_SCHEMA = "hol-guard-core-update.v1"
ONEDIR_UPDATE_SCHEMA = "hol-guard-core-update.v2"
INSTALL_SCHEMA = "hol-guard-core-install.v1"
BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
_ONEDIR_FORMAT = "onedir-zip"
_ONEDIR_TREE_ROOT = "hol-guard"
_MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
    b"\xbe\xba\xfe\xca",
    b"\xbf\xba\xfe\xca",
}
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


class _ParsedOnedirManifest(TypedDict):
    version: str
    source_commit: str
    target: str
    artifact: str
    sha256: str
    size: int
    launcher: str
    launcher_sha256: str
    file_count: int
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
    return platform_target() is not None


def desktop_core_uses_alpha_channel(current_version: str, *, requested_alpha: bool) -> bool:
    _ = current_version
    if platform_target() == "x86_64-unknown-linux-gnu":
        return False
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
        if parsed.major != series[0] or (include_alpha and parsed.minor != series[1]):
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
    if system == "linux" and machine in {"x86_64", "amd64"}:
        libc, _libc_version = platform.libc_ver()
        if libc.lower() == "glibc":
            return "x86_64-unknown-linux-gnu"
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
    if sys.platform == "darwin":
        onedir_executable = _try_apply_onedir(
            downloader,
            tag=tag,
            artifact=artifact,
            channel=channel,
            expected_version=normalized_target,
            expected_target=target,
        )
        if onedir_executable is not None:
            return DesktopCoreApplyResult(executable=onedir_executable, version=normalized_target, changed=True)
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
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise DesktopCoreUpdateError("desktop_core_asset_missing") from error
        raise DesktopCoreUpdateError("desktop_core_download_failed") from error
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


def _parse_onedir_manifest(
    raw: bytes,
    *,
    expected_version: str,
    expected_tag: str,
    expected_target: str,
    expected_artifact: str,
    expected_channel: str,
) -> _ParsedOnedirManifest:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DesktopCoreUpdateError("desktop_core_manifest_invalid") from error
    if not isinstance(decoded, dict):
        raise DesktopCoreUpdateError("desktop_core_manifest_invalid")
    payload: dict[object, object] = {key: value for key, value in decoded.items()}
    sha256 = payload.get("sha256")
    launcher_sha256 = payload.get("launcherSha256")
    source_commit = payload.get("sourceCommit")
    size = payload.get("size")
    file_count = payload.get("fileCount")
    minimum_desktop_version = payload.get("minimumDesktopVersion")
    if (
        payload.get("schema") != ONEDIR_UPDATE_SCHEMA
        or payload.get("channel") != expected_channel
        or payload.get("version") != expected_version
        or payload.get("sourceTag") != expected_tag
        or payload.get("target") != expected_target
        or payload.get("format") != _ONEDIR_FORMAT
        or payload.get("artifact") != expected_artifact
        or payload.get("launcher") != f"{_ONEDIR_TREE_ROOT}/{_executable_name()}"
        or payload.get("bootstrapSchema") != BOOTSTRAP_SCHEMA
        or not isinstance(sha256, str)
        or _SHA256_RE.fullmatch(sha256.lower()) is None
        or not isinstance(launcher_sha256, str)
        or _SHA256_RE.fullmatch(launcher_sha256.lower()) is None
        or not isinstance(source_commit, str)
        or _COMMIT_RE.fullmatch(source_commit.lower()) is None
        or type(size) is not int
        or size <= 0
        or size > _MAX_BINARY_BYTES
        or type(file_count) is not int
        or file_count <= 0
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
        "artifact": expected_artifact,
        "sha256": sha256.lower(),
        "size": size,
        "launcher": f"{_ONEDIR_TREE_ROOT}/{_executable_name()}",
        "launcher_sha256": launcher_sha256.lower(),
        "file_count": file_count,
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


def _try_apply_onedir(
    downloader: FetchBytes,
    *,
    tag: str,
    artifact: str,
    channel: str,
    expected_version: str,
    expected_target: str,
) -> Path | None:
    if not os.environ.get("HOL_GUARD_DESKTOP_VERSION", "").strip():
        return None
    try:
        raw = downloader(_release_url(tag, f"{artifact}.onedir.json"), _MAX_MANIFEST_BYTES)
    except DesktopCoreUpdateError as error:
        if error.reason_code == "desktop_core_asset_missing":
            return None
        raise
    manifest = _parse_onedir_manifest(
        raw,
        expected_version=expected_version,
        expected_tag=tag,
        expected_target=expected_target,
        expected_artifact=f"{artifact}.onedir.zip",
        expected_channel=channel,
    )
    try:
        _enforce_minimum_desktop_version(manifest["minimum_desktop_version"])
    except DesktopCoreUpdateError as error:
        if error.reason_code == "desktop_core_desktop_too_old":
            return None
        raise
    archive = downloader(_release_url(tag, manifest["artifact"]), _MAX_BINARY_BYTES)
    if len(archive) != manifest["size"] or _sha256_hex(archive) != manifest["sha256"]:
        raise DesktopCoreUpdateError("desktop_core_integrity_mismatch")
    trusted_team = _macos_signing_team(Path(sys.executable))
    root = desktop_core_root()
    _reject_symlink(root)
    root.mkdir(parents=True, exist_ok=True)
    _reject_symlink(root)
    try:
        with tempfile.TemporaryDirectory(prefix=".onedir-update-", dir=root) as scratch:
            scratch_root = Path(scratch)
            archive_path = scratch_root / manifest["artifact"]
            _ = archive_path.write_bytes(archive)
            _validate_onedir_zip_members(archive_path)
            extracted = scratch_root / "tree"
            extracted.mkdir()
            _extract_onedir_zip(archive_path, extracted)
            tree = extracted / _ONEDIR_TREE_ROOT
            launcher = tree / _executable_name()
            if not launcher.is_file() or _onedir_file_count(extracted) != manifest["file_count"]:
                raise DesktopCoreUpdateError("desktop_core_install_failed")
            _verify_candidate(launcher, expected_team=trusted_team, expected_sha256=manifest["launcher_sha256"])
            _require_sealed_onedir(launcher)
            _verify_onedir_tree_signatures(tree, expected_team=trusted_team)
            installed = _install_managed_core_onedir(tree, manifest, expected_target)
    except OSError as error:
        raise DesktopCoreUpdateError("desktop_core_install_failed") from error
    return installed


def _onedir_file_count(extracted: Path) -> int:
    """R5/R6: count non-directory entries (files plus links, never followed) and
    require every link to be a relative in-tree path."""
    tree_real = os.path.realpath(extracted / _ONEDIR_TREE_ROOT)
    count = 0
    for entry in extracted.rglob("*"):
        if entry.parts[len(extracted.parts)] != _ONEDIR_TREE_ROOT:
            raise DesktopCoreUpdateError("desktop_core_install_failed")
        if entry.is_symlink():
            _check_onedir_tree_link(entry, extracted, tree_real)
            count += 1
        elif entry.is_dir():
            continue
        elif not entry.is_file():
            raise DesktopCoreUpdateError("desktop_core_install_failed")
        else:
            count += 1
    return count


def _check_onedir_tree_link(link: Path, extracted: Path, tree_real: str) -> None:
    """R6: an extracted link must readlink to a short relative in-tree target."""
    try:
        target = os.readlink(link)
        encoded = os.fsencode(target)
        relative = link.relative_to(extracted).as_posix()
    except (OSError, UnicodeEncodeError, ValueError) as error:
        raise DesktopCoreUpdateError("desktop_core_install_failed") from error
    if (
        not encoded
        or len(encoded) > _ONEDIR_SYMLINK_TARGET_MAX
        or b"\x00" in encoded
        or PurePosixPath(target).is_absolute()
    ):
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
    if not resolved.startswith(f"{_ONEDIR_TREE_ROOT}/"):
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    if not link.exists():
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    if not os.path.realpath(link).startswith(tree_real + os.sep):
        raise DesktopCoreUpdateError("desktop_core_install_failed")


_ONEDIR_REQUIRED_MEMBERS = (
    f"{_ONEDIR_TREE_ROOT}/Info.plist",
    f"{_ONEDIR_TREE_ROOT}/_CodeSignature/CodeResources",
)
_ONEDIR_INTERNAL_PREFIX = f"{_ONEDIR_TREE_ROOT}/_internal/"
_ONEDIR_SYMLINK_TARGET_MAX = 1024
_ZIP_SYMLINK_MODE = 0o120000
_ZIP_MODE_MASK = 0o170000


def _fold(name: str) -> list[str]:
    return unicodedata.normalize("NFC", name.rstrip("/")).casefold().split("/")


def _check_onedir_zip_symlink(zipped: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    """R2: a symlink member's target must be a short relative path that stays in-tree."""
    name = info.filename
    try:
        raw = zipped.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise DesktopCoreUpdateError("desktop_core_install_failed") from error
    if not raw or len(raw) > _ONEDIR_SYMLINK_TARGET_MAX or b"\x00" in raw:
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    try:
        target = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DesktopCoreUpdateError("desktop_core_install_failed") from error
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    if PurePosixPath(target).is_absolute() or not resolved.startswith(f"{_ONEDIR_TREE_ROOT}/"):
        raise DesktopCoreUpdateError("desktop_core_install_failed")


def _validate_onedir_zip_members(archive: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as zipped:
            names: set[str] = set()
            link_names: list[str] = []
            for info in zipped.infolist():
                name = info.filename
                member = PurePosixPath(name)
                if member.is_absolute() or ".." in member.parts:
                    raise DesktopCoreUpdateError("desktop_core_install_failed")
                # PurePosixPath folds "." and empty components away; check the raw
                # split so a "./" detour cannot dodge the nested-under-link rule.
                raw_parts = name.split("/")
                if "." in raw_parts or "" in raw_parts[:-1]:
                    raise DesktopCoreUpdateError("desktop_core_install_failed")
                if name != _ONEDIR_TREE_ROOT and not name.startswith(f"{_ONEDIR_TREE_ROOT}/"):
                    raise DesktopCoreUpdateError("desktop_core_install_failed")
                if member.name.startswith("._") or "__MACOSX" in member.parts:
                    raise DesktopCoreUpdateError("desktop_core_install_failed")
                if (info.external_attr >> 16) & _ZIP_MODE_MASK == _ZIP_SYMLINK_MODE:
                    _check_onedir_zip_symlink(zipped, info)
                    link_names.append(name)
                names.add(name)
    except (OSError, zipfile.BadZipFile) as error:
        raise DesktopCoreUpdateError("desktop_core_install_failed") from error
    folded = [tuple(_fold(name)) for name in names]
    if len(set(folded)) != len(folded):
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    # R3: nothing may sit beneath a symlink member, so extraction can never
    # write through a link.
    link_parts = [_fold(name) for name in link_names]
    for name in names:
        parts = _fold(name)
        if any(len(link) < len(parts) and parts[: len(link)] == link for link in link_parts):
            raise DesktopCoreUpdateError("desktop_core_install_failed")
    # R4: the launcher and sealed-bundle anchors must be regular files, never links.
    launcher_member = f"{_ONEDIR_TREE_ROOT}/{_executable_name()}"
    required = (launcher_member, *_ONEDIR_REQUIRED_MEMBERS)
    if any(name not in names or name in link_names for name in required):
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    if not any(name.startswith(_ONEDIR_INTERNAL_PREFIX) for name in names):
        raise DesktopCoreUpdateError("desktop_core_install_failed")


def _extract_onedir_zip(archive: Path, destination: Path) -> None:
    if sys.platform == "darwin":
        result = subprocess.run(
            ["/usr/bin/ditto", "-x", "-k", str(archive), str(destination)],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise DesktopCoreUpdateError("desktop_core_install_failed")
        return
    _extract_onedir_zip_portable(archive, destination)


def _extract_onedir_zip_portable(archive: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as zipped:
            for info in zipped.infolist():
                name = info.filename
                if name.startswith("/") or ".." in Path(name).parts:
                    raise DesktopCoreUpdateError("desktop_core_install_failed")
                zipped.extract(info, destination)
                extracted = destination / name
                if info.external_attr >> 16 & stat.S_IXUSR and extracted.is_file():
                    extracted.chmod(extracted.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except zipfile.BadZipFile as error:
        raise DesktopCoreUpdateError("desktop_core_install_failed") from error


def _is_macho_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) in _MACHO_MAGICS
    except OSError:
        return False


def _require_sealed_onedir(launcher: Path) -> None:
    if sys.platform != "darwin":
        return
    resources = launcher.parent / "_CodeSignature" / "CodeResources"
    if not resources.is_file():
        raise DesktopCoreUpdateError("desktop_core_signature_invalid")
    result = subprocess.run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(launcher)],
        check=False,
        capture_output=True,
        text=True,
    )
    output = result.stderr + result.stdout
    if result.returncode != 0 or "Format=app bundle" not in output or "Sealed Resources version=2" not in output:
        raise DesktopCoreUpdateError("desktop_core_signature_invalid")


def _verify_onedir_tree_signatures(tree: Path, *, expected_team: str) -> None:
    internal = tree / "_internal"
    if not internal.is_dir():
        raise DesktopCoreUpdateError("desktop_core_install_failed")
    for path in sorted(tree.rglob("*")):
        if path.is_symlink() or not path.is_file() or not _is_macho_file(path):
            continue
        if _macos_signing_team(path) != expected_team:
            raise DesktopCoreUpdateError("desktop_core_signature_mismatch")


def _install_managed_core_onedir(tree: Path, manifest: _ParsedOnedirManifest, target: str) -> Path:
    root = desktop_core_root()
    versions_root = root / "versions"
    version_dir = versions_root / manifest["version"]
    installed = version_dir / _executable_name()
    current = root / "current.json"
    for path in (root, versions_root, version_dir, installed, current):
        _reject_symlink(path)
    versions_root.mkdir(parents=True, exist_ok=True)
    for path in (root, versions_root, version_dir, installed):
        _reject_symlink(path)
    partial = versions_root / f"{manifest['version']}.partial-{os.getpid()}"
    _reject_symlink(partial)
    if partial.exists():
        shutil.rmtree(partial)
    _ = shutil.move(str(tree), str(partial))
    staged_launcher = partial / _executable_name()
    retired: Path | None = None
    replaced = False
    temporary = current.with_name(f".current.{os.getpid()}.tmp")
    try:
        _reject_symlink(staged_launcher)
        _make_executable(staged_launcher)
        _verify_candidate(
            staged_launcher,
            expected_team=_macos_signing_team(Path(sys.executable)) if sys.platform == "darwin" else None,
            expected_sha256=manifest["launcher_sha256"],
        )
        _require_sealed_onedir(staged_launcher)
        if version_dir.exists():
            retired = versions_root / f".{manifest['version']}.replaced-{os.getpid()}"
            _reject_symlink(retired)
            version_dir.rename(retired)
        _ = partial.replace(version_dir)
        replaced = True
        _reject_symlink(installed)
        pointer = {
            "schema": INSTALL_SCHEMA,
            "version": manifest["version"],
            "sourceCommit": manifest["source_commit"],
            "target": target,
            "relativePath": f"versions/{manifest['version']}/{_executable_name()}",
            "sha256": manifest["launcher_sha256"],
            "installedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        _reject_symlink(current)
        _reject_symlink(temporary)
        _ = temporary.write_text(json.dumps(pointer, indent=2) + "\n", encoding="utf-8")
        _ = temporary.replace(current)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)
        if replaced:
            shutil.rmtree(version_dir, ignore_errors=True)
        if retired is not None and not version_dir.exists():
            with contextlib.suppress(OSError):
                _ = retired.rename(version_dir)
        shutil.rmtree(partial, ignore_errors=True)
        raise
    _reject_symlink(current)
    if retired is not None:
        shutil.rmtree(retired, ignore_errors=True)
    return installed


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
