"""Observe which harness version is installed, without trusting one PATH hit.

Discovery reads trusted package metadata first and only falls back to a
bounded, fixed-argument ``--version`` probe for a standalone binary. When more
than one installation is found and they disagree, the result is ambiguous: the
caller must not pick the most favorable version.

Observations carry an opaque installation id and a bounded reason code. Raw
paths and raw command output never leave this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ..adapters.base import HarnessContext, _run_command_probe
from .versions import HarnessVersion, parse_version, parse_version_banner

PROBE_TIMEOUT_SECONDS = 3
MAX_PACKAGE_JSON_BYTES = 256 * 1024
MAX_PACKAGE_ROOT_DEPTH = 6

ProbeRunner = Callable[..., Mapping[str, object]]


@dataclass(frozen=True, slots=True)
class PackageVersionSource:
    """Where a harness publishes its version: an npm package and its executable."""

    package: str
    executable: str


# Harnesses with a reliable version source. Every other harness reports an
# explicit ``discovery_unsupported`` unknown instead of an invented version.
VERSION_SOURCES: dict[str, PackageVersionSource] = {
    "omp": PackageVersionSource(package="@oh-my-pi/pi-coding-agent", executable="omp"),
}


@dataclass(frozen=True, slots=True)
class VersionObservation:
    harness: str
    state: str  # observed | unavailable | ambiguous
    version: HarnessVersion | None
    source: str  # package-metadata | version-probe | none
    installation_id: str | None
    reason: str | None
    observed_at: float
    identity: tuple[tuple[str, int, int, int], ...] = ()
    candidates: tuple[str, ...] = ()


def current_platform() -> str:
    system = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(platform.system().lower(), "unknown")
    machine = platform.machine().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64"}.get(machine, "unknown")
    return f"{system}-{arch}"


def _hash(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:24]


def _stat_identity(path: Path) -> tuple[str, int, int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (str(path), stat.st_ino, stat.st_size, stat.st_mtime_ns)


def candidate_executables(harness: str, context: HarnessContext, *, which: Callable[[str], str | None]) -> list[Path]:
    """Return distinct real paths of every plausible user installation."""

    source = VERSION_SOURCES[harness]
    raw: list[Path] = []
    found = which(source.executable)
    if found:
        raw.append(Path(found))
    raw.append(context.home_dir / ".local" / "bin" / source.executable)
    raw.append(context.home_dir / ".bun" / "bin" / source.executable)
    guard_home = context.guard_home.resolve() if context.guard_home.exists() else context.guard_home
    distinct: list[Path] = []
    for candidate in raw:
        if not candidate.is_file():
            continue
        try:
            real = candidate.resolve(strict=True)
        except OSError:
            continue
        # A Guard launcher shim is not the harness; following it would probe Guard itself.
        if real == guard_home or guard_home in real.parents:
            continue
        if real not in distinct:
            distinct.append(real)
    return distinct


def _package_version(executable: Path, package: str) -> tuple[HarnessVersion | None, str | None, Path | None]:
    """Find the owning package.json above ``executable`` and read its version."""

    directory = executable.parent
    for _ in range(MAX_PACKAGE_ROOT_DEPTH):
        manifest = directory / "package.json"
        if manifest.is_file():
            try:
                raw = manifest.read_bytes()
                if len(raw) > MAX_PACKAGE_JSON_BYTES:
                    return None, "metadata_malformed", manifest
                payload = json.loads(raw.decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                return None, "metadata_malformed", manifest
            if isinstance(payload, dict) and payload.get("name") == package:
                version = parse_version(payload.get("version"))
                return version, (None if version else "metadata_malformed"), manifest
        if directory.parent == directory:
            break
        directory = directory.parent
    return None, "metadata_unavailable", None


def _probe_environment(context: HarnessContext) -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(context.home_dir), "NO_COLOR": "1"}
    for key in ("SYSTEMROOT", "TEMP", "TMP"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _probe_version(
    harness: str, executable: Path, context: HarnessContext, run_probe: ProbeRunner
) -> tuple[HarnessVersion | None, str | None]:
    probe_cwd = context.guard_home / "runtime" / "harness-version-probe"
    try:
        probe_cwd.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        return None, "probe_failed"
    result = run_probe(
        [str(executable), "--version"],
        timeout_seconds=PROBE_TIMEOUT_SECONDS,
        cwd=probe_cwd,
        env=_probe_environment(context),
    )
    if result.get("timed_out"):
        return None, "probe_timeout"
    if not result.get("ok"):
        return None, "probe_failed"
    version = parse_version_banner(harness, str(result.get("stdout") or ""))
    return version, (None if version else "banner_malformed")


def _observe_one(
    harness: str, executable: Path, context: HarnessContext, run_probe: ProbeRunner
) -> tuple[HarnessVersion | None, str, str | None, Path]:
    source = VERSION_SOURCES[harness]
    version, reason, manifest = _package_version(executable, source.package)
    if manifest is not None:
        return version, "package-metadata", reason, manifest
    # No owning package: a standalone binary. Only now run the bounded probe.
    if executable.suffix.lower() in {".js", ".mjs", ".cjs", ".ts"}:
        return None, "none", "metadata_unavailable", executable
    version, reason = _probe_version(harness, executable, context, run_probe)
    return version, "version-probe", reason, executable


def observe_harness_version(
    harness: str,
    context: HarnessContext,
    *,
    run_probe: ProbeRunner = _run_command_probe,
    which: Callable[[str], str | None] = shutil.which,
    clock: Callable[[], float] = time.time,
) -> VersionObservation:
    """Observe one harness's installed version with provenance."""

    now = clock()
    if harness not in VERSION_SOURCES:
        return VersionObservation(harness, "unavailable", None, "none", None, "discovery_unsupported", now)
    executables = candidate_executables(harness, context, which=which)
    if not executables:
        return VersionObservation(harness, "unavailable", None, "none", None, "executable_missing", now)
    results = [_observe_one(harness, executable, context, run_probe) for executable in executables]
    identity = tuple(item for item in (_stat_identity(path) for *_, path in results) if item is not None)
    candidates = tuple(sorted(str(path) for path in executables))
    installation_id = _hash(harness, *candidates)
    failures = [reason for version, _, reason, _ in results if version is None]
    if failures:
        return VersionObservation(
            harness, "unavailable", None, "none", installation_id, failures[0], now, identity, candidates
        )
    versions = {version.canonical for version, *_ in results if version is not None}
    if len(versions) != 1:
        return VersionObservation(
            harness, "ambiguous", None, "none", installation_id, "multiple_installations", now, identity, candidates
        )
    version, source, _, _ = results[0]
    return VersionObservation(harness, "observed", version, source, installation_id, None, now, identity, candidates)


def observation_identity_changed(
    observation: VersionObservation,
    context: HarnessContext | None = None,
    *,
    which: Callable[[str], str | None] = shutil.which,
) -> bool:
    """Cheaply detect a replaced executable or package, or a changed set of installs."""

    if context is not None and observation.harness in VERSION_SOURCES:
        current = tuple(sorted(str(path) for path in candidate_executables(observation.harness, context, which=which)))
        if current != observation.candidates:
            return True
    for path_text, inode, size, mtime in observation.identity:
        current = _stat_identity(Path(path_text))
        if current != (path_text, inode, size, mtime):
            return True
    return False
