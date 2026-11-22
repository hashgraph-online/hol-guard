"""Marker for the native wheel an update installed from the GitHub release.

Later updates read it to tell their own install apart from a wheel the user installed by hand.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

# The marker keeps its alpha-era name so installs recorded by earlier updaters stay managed.
_MARKER_NAME = "alpha-native-wheel.json"
_MARKER_SCHEMA_VERSION = 1


def record_native_wheel_install(
    guard_home: Path, *, version: str, sha256: str, staged_path: Path | None = None
) -> None:
    """Remember the verified native wheel so later updates keep managing this install.

    ``staged_path`` is the file the installer read. uv records no archive hash in
    ``direct_url.json``, so that path is what ties a uv install back to this marker.
    """

    document: dict[str, object] = {"schema_version": _MARKER_SCHEMA_VERSION, "version": version, "wheel_sha256": sha256}
    if staged_path is not None:
        document["staged_path"] = str(staged_path)
    payload = json.dumps(document, sort_keys=True)
    temporary = guard_home / f".{_MARKER_NAME}.{os.getpid()}.tmp"
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, guard_home / _MARKER_NAME)
    except OSError:
        temporary.unlink(missing_ok=True)


def forget_native_wheel_install(guard_home: Path) -> None:
    """Drop the marker once a wheel the user supplied replaces the one this updater installed."""

    with contextlib.suppress(OSError):
        (guard_home / _MARKER_NAME).unlink(missing_ok=True)


def native_wheel_install_recorded(
    guard_home: Path,
    *,
    archive_sha256: str | None,
    archive_path: str | None = None,
    installed_version: str | None = None,
) -> bool:
    """True when the installed wheel is a native wheel this updater installed.

    pip records the wheel's digest, which must match the marker. uv records only the
    path it installed from, and the updater deletes that staged file afterwards. Without
    a digest the install matches when the marker names the same version and either
    the same staged path, or (for markers written before the path was recorded) a
    wheel of that version inside this home's private update staging directory.
    """

    try:
        payload = json.loads((guard_home / _MARKER_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(payload, dict) or payload.get("schema_version") != _MARKER_SCHEMA_VERSION:
        return False
    if archive_sha256:
        return payload.get("wheel_sha256") == archive_sha256
    version = payload.get("version")
    if not archive_path or not isinstance(version, str) or not version or installed_version != version:
        return False
    recorded_path = payload.get("staged_path")
    if isinstance(recorded_path, str):
        return _same_path(recorded_path, archive_path)
    if recorded_path is not None:
        return False
    return _staged_update_wheel(guard_home, Path(archive_path), version)


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _staged_update_wheel(guard_home: Path, archive: Path, version: str) -> bool:
    """A wheel of ``version`` directly inside one ``update-runtime/wheels/artifact-*`` directory."""

    if not archive.is_absolute() or archive.suffix.lower() != ".whl":
        return False
    artifact = archive.parent
    if not artifact.name.startswith("artifact-") or not archive.name.startswith(f"hol_guard-{version}-"):
        return False
    wheels = artifact.parent
    for home in {guard_home, guard_home.resolve()}:
        if _same_path(str(wheels), str(home / "update-runtime" / "wheels")):
            return True
    return False
