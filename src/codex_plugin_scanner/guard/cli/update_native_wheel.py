"""Install the platform-native wheel from the GitHub release.

PyPI does not carry every native wheel. Alpha publication uploads only the
pure ``py3-none-any`` wheel, and stable publication keeps the platforms with
few users (Intel macOS, Windows ARM64 and Linux ARM64) off PyPI to stay inside the project
storage quota. A pure wheel has no bundled ``_native/hol-guard-runtime``, so
this module picks the platform wheel that matches the running interpreter,
downloads it from the ``v<version>`` release (``alpha/v<version>`` for
alphas), and verifies its digest before the existing wheel installer runs.

Trust model: stable digests come from ``native-wheels.json``, which the
release workflow embeds in the pure wheel it uploads to PyPI. That pure wheel
is either the installed package (when repairing the same version) or a fresh
PyPI download checked against the sha256 PyPI publishes, so a GitHub asset is
accepted only when PyPI vouches for its bytes. Alpha digests come from the
build-provenance bundle on the same prerelease; the statement is checked for
the expected repository and workflow, but the Sigstore signature chain is not
verified here, so for alphas this guards against corrupted or mismatched
downloads and binds the wheel to the release's own attestation.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from packaging.tags import sys_tags
from packaging.version import InvalidVersion, Version

from ..mdm.contracts import ManagedNetworkPolicy
from ..native_runtime import _bundled_runtime_candidate
from .native_wheel_sources import (
    SAFE_VERSION_RE,
    NativeWheelError,
    Opener,
    default_opener,
    download_to_file,
    is_alpha_version,
    native_wheel_platform_tag,
    published_native_digests,
    pypi_native_wheel_tags,
    release_url,
)

ALPHA_UPDATE_COMMAND = "hol-guard update --alpha"
STABLE_UPDATE_COMMAND = "hol-guard update"
PUBLISHED_PLATFORM_TAGS = frozenset(
    {
        "macosx_11_0_arm64",
        "macosx_13_0_x86_64",
        "manylinux_2_17_aarch64",
        "manylinux_2_17_x86_64",
        "win_amd64",
        "win_arm64",
    }
)
# Stable native wheels for these platforms are attached to the GitHub release and never uploaded to PyPI.
GITHUB_ONLY_PLATFORM_TAGS = frozenset({"macosx_13_0_x86_64", "manylinux_2_17_aarch64", "win_arm64"})
# The marker keeps its alpha-era name so installs recorded by earlier updaters stay managed.
_MARKER_NAME = "alpha-native-wheel.json"
_MARKER_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class NativeWheelPlan:
    """Why an update must install the native wheel from the GitHub release."""

    version: str
    reason: Literal["upgrade", "repair"]


@dataclass(frozen=True, slots=True)
class NativeWheelDownload:
    path: Path
    directory: Path
    sha256: str
    version: str

    def cleanup(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def bundled_native_runtime_missing(candidate: Path | None = None) -> bool:
    return not (candidate or _bundled_runtime_candidate()).is_file()


def native_platform_supported(tags: Iterable[str] | None = None) -> bool:
    """True when this interpreter can install a platform wheel the release publishes."""

    return any(tag in PUBLISHED_PLATFORM_TAGS for tag in (tags if tags is not None else _platform_tags()))


def github_only_platform(tags: Iterable[str] | None = None) -> bool:
    """True when this interpreter's stable native wheel is on the GitHub release but not on PyPI."""

    host = set(tags if tags is not None else _platform_tags())
    return bool(host & GITHUB_ONLY_PLATFORM_TAGS) and not host & (PUBLISHED_PLATFORM_TAGS - GITHUB_ONLY_PLATFORM_TAGS)


def pypi_serves_native_wheel(
    version: str,
    *,
    network_policy: ManagedNetworkPolicy | None = None,
    opener: Opener | None = None,
    tags: Iterable[str] | None = None,
) -> bool:
    """True when PyPI already has a native wheel for this host, so pip can install it directly."""

    if SAFE_VERSION_RE.fullmatch(version) is None:
        return False
    try:
        served = pypi_native_wheel_tags(opener or default_opener(network_policy), version)
    except NativeWheelError:
        return False
    return any(tag in served for tag in (tags if tags is not None else _platform_tags()))


def update_command_for(version: str | None) -> str:
    return ALPHA_UPDATE_COMMAND if is_alpha_version(version) else STABLE_UPDATE_COMMAND


def plan_native_wheel_update(
    *,
    include_alpha: bool,
    current_version: str,
    target_version: str | None,
    runtime_missing: bool,
    platform_supported: bool,
    github_only: bool = False,
) -> NativeWheelPlan | None:
    """Decide whether the update must install the native wheel from the GitHub release."""

    if not platform_supported:
        # Hosts without a published native wheel keep the ordinary PyPI path.
        return None
    if target_version is not None:
        if is_alpha_version(target_version):
            return NativeWheelPlan(version=target_version, reason="upgrade") if include_alpha else None
        # PyPI already serves the stable native wheel unless this platform is GitHub-only.
        return NativeWheelPlan(version=target_version, reason="upgrade") if github_only else None
    if runtime_missing:
        return NativeWheelPlan(version=current_version.strip(), reason="repair")
    return None


def _windows_short_path(path: str) -> str:
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetShortPathNameW(path, buffer, len(buffer))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return path
    return buffer.value if 0 < length < len(buffer) else path


def _manual_installer_prefix(installer: str) -> str:
    # Point the command at the environment running Guard, not whichever Python is first on PATH.
    if installer == "pipx":
        return "pipx runpip hol-guard install"
    executable = sys.executable or "python"
    if any(character.isspace() for character in executable) and os.name == "nt":
        # The 8.3 short path has no spaces, so the command pastes into PowerShell, cmd.exe and Git Bash alike.
        executable = _windows_short_path(executable)
    if any(character.isspace() for character in executable):
        executable = f'"{executable}"'
        if os.name == "nt" and installer != "uv":
            # Without a short path, PowerShell (the default Windows shell) needs the call operator.
            executable = f"& {executable}"
    if installer == "uv":
        return f"uv pip install --python {executable}"
    return f"{executable} -m pip install"


def manual_install_command(
    version: str,
    *,
    tags: Iterable[str] | None = None,
    installer: str = "pip",
) -> str | None:
    """Return the command that installs this host's native wheel when the download is blocked."""

    if SAFE_VERSION_RE.fullmatch(version) is None:
        return None
    for tag in tags if tags is not None else _platform_tags():
        if tag in PUBLISHED_PLATFORM_TAGS:
            url = release_url(version, f"hol_guard-{version}-py3-none-{tag}.whl")
            reinstall = "--reinstall-package hol-guard" if installer == "uv" else "--force-reinstall"
            return f'{_manual_installer_prefix(installer)} {reinstall} --no-deps "{url}"'
    return None


def native_runtime_payload(
    runtime_missing: bool,
    *,
    platform_supported: bool = True,
    version: str | None = None,
    installer: str = "pip",
) -> dict[str, object]:
    if not runtime_missing:
        return {"status": "present", "bundled": True}
    payload: dict[str, object] = {"status": "missing", "bundled": False}
    if platform_supported:
        fix = update_command_for(version)
        payload["fix"] = fix
        payload["message"] = (
            "This install has no bundled native runtime (PyPI only carries the pure wheel for this platform). "
            f"Run `{fix}` to install the native wheel from the GitHub release."
        )
        manual = manual_install_command(version, installer=installer) if version is not None else None
        if manual is not None:
            payload["manual_install"] = manual
    return payload


def failure_payload(
    payload: dict[str, object],
    error: NativeWheelError,
    *,
    version: str | None = None,
    installer: str = "pip",
) -> None:
    message = error.message
    manual = manual_install_command(version, installer=installer) if version is not None else None
    if manual is not None:
        payload["manual_install"] = manual
        message = f"{message} To install it by hand, run: {manual}"
    payload.update(
        {
            "status": "failed",
            "changed": False,
            "reason_code": error.reason_code,
            "error": error.reason_code,
            "message": message,
        }
    )


def prepare_native_wheel(
    plan: NativeWheelPlan,
    *,
    network_policy: ManagedNetworkPolicy | None,
) -> tuple[NativeWheelDownload | None, str | None]:
    """Download the native wheel for ``plan``; a retracted repair target is a note, not a failure."""

    try:
        return download_native_wheel(plan.version, network_policy=network_policy), None
    except NativeWheelError as error:
        if (
            plan.reason == "upgrade"
            and not is_alpha_version(plan.version)
            and error.reason_code in {"native_wheel_release_unavailable", "native_wheel_asset_missing"}
        ):
            # PyPI lists a stable version a few minutes before its GitHub release exists.
            return None, (
                f"HOL Guard {plan.version} is on PyPI, but its GitHub release is not available yet, "
                "so the current version stays installed. Run the update again later."
            )
        if plan.reason == "repair" and error.reason_code in {
            "native_wheel_release_unavailable",
            "native_wheel_platform_unsupported",
            "native_wheel_asset_missing",
            # Releases published before the digest manifest existed cannot be repaired from GitHub.
            "native_wheel_manifest_invalid",
        }:
            return None, f"Could not repair the native runtime: {error.message}"
        raise


def select_native_wheel(
    subjects: dict[str, str],
    version: str,
    *,
    tags: Iterable[str] | None = None,
) -> tuple[str, str]:
    """Pick the best-matching platform wheel for ``version`` from the published digests."""

    ranked_tags = list(tags if tags is not None else _platform_tags())
    best: tuple[int, str] | None = None
    for name in sorted(subjects):
        platform_tag = native_wheel_platform_tag(name, version)
        if platform_tag is None or platform_tag not in ranked_tags:
            continue
        rank = ranked_tags.index(platform_tag)
        if best is None or rank < best[0]:
            best = (rank, name)
    if best is None:
        has_wheel = any(native_wheel_platform_tag(name, version) is not None for name in subjects)
        raise NativeWheelError("native_wheel_platform_unsupported" if has_wheel else "native_wheel_asset_missing")
    return best[1], subjects[best[1]]


def download_native_wheel(
    version: str,
    *,
    network_policy: ManagedNetworkPolicy | None = None,
    opener: Opener | None = None,
    tags: Iterable[str] | None = None,
    package_root: Path | None = None,
) -> NativeWheelDownload:
    """Fetch, verify, and place the native wheel in a private temporary directory."""

    if SAFE_VERSION_RE.fullmatch(version) is None:
        raise NativeWheelError("native_wheel_release_unavailable")
    try:
        _ = Version(version)
    except InvalidVersion as error:
        raise NativeWheelError("native_wheel_release_unavailable") from error
    open_url = opener or default_opener(network_policy)
    digests = published_native_digests(open_url, version, package_root=package_root)
    name, expected_sha256 = select_native_wheel(digests, version, tags=tags)
    # mkdtemp creates the directory owner-only (0700).
    directory = Path(tempfile.mkdtemp(prefix="hol-guard-native-"))
    try:
        target = directory / name
        actual = download_to_file(open_url, release_url(version, name), target)
        if actual != expected_sha256:
            raise NativeWheelError("native_wheel_digest_mismatch")
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return NativeWheelDownload(path=target, directory=directory, sha256=expected_sha256, version=version)


def record_native_wheel_install(guard_home: Path, *, version: str, sha256: str) -> None:
    """Remember the verified native wheel so later updates keep managing this install."""

    payload = json.dumps(
        {"schema_version": _MARKER_SCHEMA_VERSION, "version": version, "wheel_sha256": sha256},
        sort_keys=True,
    )
    temporary = guard_home / f".{_MARKER_NAME}.{os.getpid()}.tmp"
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, guard_home / _MARKER_NAME)
    except OSError:
        temporary.unlink(missing_ok=True)


_NATIVE_PAYLOAD_PREFIX = "codex_plugin_scanner/_native/"


def install_native_payload(wheel: Path, *, package_root: Path | None = None) -> None:
    """Copy the runtime files of a same-version native wheel into the installed package.

    The native wheel differs from the pure wheel only by ``codex_plugin_scanner/_native``, so the
    repair adds those files instead of reinstalling the package. That keeps it working on Windows,
    where pip cannot replace the package of the running ``hol-guard.exe``. Every file is checked
    against the wheel's RECORD and written beside its target before any target changes. The files
    then move into place with the runtime last, and the installed RECORD lists them so uninstalling
    removes them. A failure at any step removes what this call placed, so a later repair starts clean.
    """

    root = package_root or _bundled_runtime_candidate().parent.parent
    payload, record_name = _read_native_payload(wheel)
    installed_record = root.parent / record_name
    staged: list[tuple[Path, Path]] = []
    placed: list[Path] = []
    try:
        existing_record = installed_record.read_text(encoding="utf-8")
        for relative, data, mode in payload:
            target = root / "_native" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{relative}.{os.getpid()}.tmp")
            staged.append((temporary, target))
            temporary.write_bytes(data)
            temporary.chmod(mode | stat.S_IRUSR | stat.S_IWUSR if mode else 0o644)
        for temporary, target in staged:
            os.replace(temporary, target)
            placed.append(target)
        _write_record(installed_record, existing_record, [row for _relative, row in _payload_rows(payload)])
    except OSError as error:
        for target in reversed(placed):
            target.unlink(missing_ok=True)
        raise NativeWheelError("native_wheel_payload_install_failed") from error
    finally:
        for temporary, _target in staged:
            temporary.unlink(missing_ok=True)


def _read_native_payload(wheel: Path) -> tuple[list[tuple[str, bytes, int]], str]:
    """Return the verified ``_native`` files of ``wheel``, runtime last, and its RECORD name."""

    try:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            record_name = next(
                (name for name in names if name.endswith(".dist-info/RECORD") and name.count("/") == 1), None
            )
            if record_name is None:
                raise NativeWheelError("native_wheel_payload_invalid")
            hashes = {
                row[0]: row[1]
                for row in csv.reader(io.StringIO(archive.read(record_name).decode("utf-8")))
                if len(row) >= 2
            }
            # The runtime goes last: Guard treats it as present once the executable exists.
            members = sorted(
                (name for name in names if name.startswith(_NATIVE_PAYLOAD_PREFIX) and not name.endswith("/")),
                key=lambda name: name.rsplit("/", 1)[-1].startswith("hol-guard-runtime"),
            )
            if not members:
                raise NativeWheelError("native_wheel_payload_invalid")
            payload: list[tuple[str, bytes, int]] = []
            for name in members:
                relative = name[len(_NATIVE_PAYLOAD_PREFIX) :]
                if not relative or "/" in relative or "\\" in relative or relative in {".", ".."}:
                    raise NativeWheelError("native_wheel_payload_invalid")
                data = archive.read(name)
                if hashes.get(name) != _record_digest(data):
                    raise NativeWheelError("native_wheel_payload_invalid")
                payload.append((relative, data, (archive.getinfo(name).external_attr >> 16) & 0o777))
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, csv.Error) as error:
        raise NativeWheelError("native_wheel_payload_install_failed") from error
    return payload, record_name


def _record_digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _payload_rows(payload: list[tuple[str, bytes, int]]) -> list[tuple[str, list[str]]]:
    return [
        (relative, [_NATIVE_PAYLOAD_PREFIX + relative, _record_digest(data), str(len(data))])
        for relative, data, _mode in payload
    ]


def _write_record(record: Path, existing: str, rows: list[list[str]]) -> None:
    """Add the payload files to the installed RECORD so uninstalling removes them."""

    listed = {row[0] for row in csv.reader(io.StringIO(existing)) if row}
    added = [row for row in rows if row[0] not in listed]
    if not added:
        return
    buffer = io.StringIO()
    csv.writer(buffer, lineterminator="\n").writerows(added)
    separator = "" if not existing or existing.endswith("\n") else "\n"
    temporary = record.with_name(f".RECORD.{os.getpid()}.tmp")
    try:
        temporary.write_text(existing + separator + buffer.getvalue(), encoding="utf-8")
        os.replace(temporary, record)
    finally:
        temporary.unlink(missing_ok=True)


def native_wheel_install_recorded(guard_home: Path, *, archive_sha256: str | None) -> bool:
    """True when the installed wheel's digest matches a native wheel this updater installed."""

    if not archive_sha256:
        return False
    try:
        payload = json.loads((guard_home / _MARKER_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema_version") == _MARKER_SCHEMA_VERSION
        and payload.get("wheel_sha256") == archive_sha256
    )


def _platform_tags() -> list[str]:
    tags: list[str] = []
    for tag in sys_tags():
        if (
            tag.interpreter.startswith("py3")
            and tag.abi == "none"
            and tag.platform != "any"
            and tag.platform not in tags
        ):
            tags.append(tag.platform)
    return tags
