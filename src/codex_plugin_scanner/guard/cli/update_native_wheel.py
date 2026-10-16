"""Install the platform-native wheel from the GitHub release.

PyPI does not carry every native wheel. Alpha publication uploads only the
pure ``py3-none-any`` wheel, and stable publication keeps the platforms with
few users (Intel macOS and Windows ARM64) off PyPI to stay inside the project
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

import json
import os
import shutil
import tempfile
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
        "manylinux_2_17_x86_64",
        "win_amd64",
        "win_arm64",
    }
)
# Stable native wheels for these platforms are attached to the GitHub release and never uploaded to PyPI.
GITHUB_ONLY_PLATFORM_TAGS = frozenset({"macosx_13_0_x86_64", "win_arm64"})
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


def manual_install_command(version: str, *, tags: Iterable[str] | None = None) -> str | None:
    """Return the pip command that installs this host's native wheel when the download is blocked."""

    if SAFE_VERSION_RE.fullmatch(version) is None:
        return None
    for tag in tags if tags is not None else _platform_tags():
        if tag in PUBLISHED_PLATFORM_TAGS:
            url = release_url(version, f"hol_guard-{version}-py3-none-{tag}.whl")
            return f'python -m pip install --force-reinstall --no-deps "{url}"'
    return None


def native_runtime_payload(
    runtime_missing: bool,
    *,
    platform_supported: bool = True,
    version: str | None = None,
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
        manual = manual_install_command(version) if version is not None else None
        if manual is not None:
            payload["manual_install"] = manual
    return payload


def failure_payload(payload: dict[str, object], error: NativeWheelError, *, version: str | None = None) -> None:
    message = error.message
    manual = manual_install_command(version) if version is not None else None
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
