"""Protected per-user harness registry and aggregate integrity projection."""

from __future__ import annotations

import json
import os
import platform
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from .contracts import HarnessCoverage, MachinePaths, ManagedPolicyState
from .harness_coverage_artifacts import artifact_digest, managed_manifest_paths
from .machine_state_lock import protected_machine_state_lock

_SCHEMA_VERSION = "hol-guard-harness-coverage-registry.v1"
_REGISTRY_NAME = "harness-coverage-registry.json"
_MAX_REGISTRY_BYTES = 256 * 1024
_MAX_USERS = 256
_MAX_HARNESSES_PER_USER = 32
_MAX_ARTIFACTS_PER_HARNESS = 64


@dataclass(frozen=True, slots=True)
class HarnessCoverageVerification:
    state: str
    reason_code: str
    coverage: HarnessCoverage


class _Shell32(Protocol):
    def IsUserAnAdmin(self) -> int: ...  # noqa: N802 - Windows API name


def _registry_path(paths: MachinePaths) -> Path:
    return paths.state_root / _REGISTRY_NAME


def _administrator_context() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0
    import ctypes

    shell32 = cast(_Shell32, cast(object, ctypes.windll.shell32))
    return shell32.IsUserAnAdmin() != 0


def _registry_owner_is_trusted(metadata: os.stat_result) -> bool:
    return platform.system() == "Windows" or metadata.st_uid == 0


def _validate_registry_users(users: list[object]) -> None:
    seen_homes: set[str] = set()
    for raw_user in users:
        if not isinstance(raw_user, dict):
            raise ValueError("harness_coverage_registry_invalid")
        user = cast(dict[str, object], raw_user)
        home = user.get("home")
        harnesses_value = user.get("harnesses")
        if (
            set(user) != {"harnesses", "home"}
            or not isinstance(home, str)
            or not Path(home).is_absolute()
            or not 1 <= len(home) <= 4096
            or home in seen_homes
            or not isinstance(harnesses_value, list)
        ):
            raise ValueError("harness_coverage_registry_invalid")
        seen_homes.add(home)
        harnesses = cast(list[object], harnesses_value)
        if len(harnesses) > _MAX_HARNESSES_PER_USER:
            raise ValueError("harness_coverage_registry_invalid")
        seen_harnesses: set[str] = set()
        for raw_harness in harnesses:
            if not isinstance(raw_harness, dict):
                raise ValueError("harness_coverage_registry_invalid")
            harness = cast(dict[str, object], raw_harness)
            name = harness.get("name")
            artifacts_value = harness.get("artifacts")
            if (
                set(harness) != {"artifacts", "name"}
                or not isinstance(name, str)
                or not 1 <= len(name) <= 128
                or name in seen_harnesses
                or not isinstance(artifacts_value, list)
            ):
                raise ValueError("harness_coverage_registry_invalid")
            seen_harnesses.add(name)
            artifacts = cast(list[object], artifacts_value)
            if len(artifacts) > _MAX_ARTIFACTS_PER_HARNESS:
                raise ValueError("harness_coverage_registry_invalid")
            for raw_artifact in artifacts:
                if not isinstance(raw_artifact, dict):
                    raise ValueError("harness_coverage_registry_invalid")
                artifact = cast(dict[str, object], raw_artifact)
                path = artifact.get("path")
                kind = artifact.get("kind")
                digest = artifact.get("sha256")
                if (
                    set(artifact) not in ({"kind", "path"}, {"kind", "path", "sha256"})
                    or not isinstance(path, str)
                    or not 1 <= len(path) <= 4096
                    or Path(path).is_absolute()
                    or ".." in Path(path).parts
                    or kind not in {"file", "directory", "missing", "mutable-file"}
                    or (
                        kind in {"file", "directory"}
                        and (
                            not isinstance(digest, str)
                            or len(digest) != 64
                            or any(character not in "0123456789abcdef" for character in digest)
                        )
                    )
                    or (kind in {"missing", "mutable-file"} and digest is not None)
                ):
                    raise ValueError("harness_coverage_registry_invalid")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_registry(paths: MachinePaths) -> dict[str, object] | None:
    target = _registry_path(paths)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_REGISTRY_BYTES:
            raise ValueError("harness_coverage_registry_invalid")
        if os.name != "nt" and (metadata.st_mode & 0o077 or not _registry_owner_is_trusted(metadata)):
            raise PermissionError("harness_coverage_registry_acl_invalid")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("harness_coverage_registry_invalid")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) != metadata.st_size:
            raise ValueError("harness_coverage_registry_invalid")
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(metadata, field) != getattr(after, field) for field in stable_fields):
            raise ValueError("harness_coverage_registry_invalid")
    finally:
        os.close(descriptor)
    try:
        parsed = cast(object, json.loads(payload))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("harness_coverage_registry_invalid") from exc
    if not isinstance(parsed, dict):
        raise ValueError("harness_coverage_registry_invalid")
    registry = cast(dict[str, object], parsed)
    if set(registry) != {"schemaVersion", "users"} or registry.get("schemaVersion") != _SCHEMA_VERSION:
        raise ValueError("harness_coverage_registry_invalid")
    users_raw = registry.get("users")
    if not isinstance(users_raw, list):
        raise ValueError("harness_coverage_registry_invalid")
    users = cast(list[object], users_raw)
    if len(users) > _MAX_USERS:
        raise ValueError("harness_coverage_registry_invalid")
    _validate_registry_users(users)
    return registry


def _write_registry(paths: MachinePaths, registry: dict[str, object]) -> None:
    payload = json.dumps(registry, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(payload) > _MAX_REGISTRY_BYTES:
        raise ValueError("harness_coverage_registry_capacity_exceeded")
    paths.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_metadata = paths.state_root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise PermissionError("harness_coverage_registry_acl_invalid")
    paths.state_root.chmod(0o700)
    target = _registry_path(paths)
    temporary = paths.state_root / f".{_REGISTRY_NAME}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        target.chmod(0o600)
        _fsync_directory(paths.state_root)
    finally:
        temporary.unlink(missing_ok=True)


def register_user_harnesses(
    paths: MachinePaths,
    home: Path,
    installs: list[dict[str, object]],
) -> None:
    if not _administrator_context():
        raise PermissionError("harness_coverage_administrator_context_required")
    resolved_home = home.resolve(strict=True)
    if not resolved_home.is_dir():
        raise ValueError("harness_coverage_home_invalid")
    with protected_machine_state_lock(paths, "harness-coverage"):
        _register_user_harnesses_unlocked(paths, resolved_home, installs)


def _register_user_harnesses_unlocked(
    paths: MachinePaths,
    resolved_home: Path,
    installs: list[dict[str, object]],
) -> None:
    registry = _read_registry(paths) or {"schemaVersion": _SCHEMA_VERSION, "users": []}
    users = cast(list[object], registry["users"])
    records: list[dict[str, object]] = []
    seen_harnesses: set[str] = set()
    if len(installs) > _MAX_HARNESSES_PER_USER:
        raise ValueError("harness_coverage_registry_capacity_exceeded")
    for install in installs:
        if not bool(install.get("active")):
            continue
        name = install.get("harness")
        manifest = install.get("manifest")
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or not isinstance(manifest, dict):
            raise ValueError("harness_coverage_registry_invalid")
        if name in seen_harnesses:
            raise ValueError("harness_coverage_registry_invalid")
        seen_harnesses.add(name)
        artifacts: list[dict[str, object]] = []
        for artifact_path in managed_manifest_paths(
            cast(dict[str, object], manifest),
            resolved_home,
            limit=_MAX_ARTIFACTS_PER_HARNESS - 1,
        ):
            try:
                kind, digest = artifact_digest(artifact_path)
            except OSError:
                kind, digest = "missing", None
            artifact: dict[str, object] = {
                "kind": kind,
                "path": str(artifact_path.relative_to(resolved_home)),
            }
            if digest is not None:
                artifact["sha256"] = digest
            artifacts.append(artifact)
        guard_home = resolved_home / ".hol-guard"
        state_path = guard_home / "guard.db"
        try:
            guard_home_metadata = guard_home.lstat()
            state_metadata = state_path.lstat()
        except OSError:
            guard_home_metadata = None
            state_metadata = None
        if guard_home_metadata is not None:
            state_kind = (
                "mutable-file"
                if stat.S_ISDIR(guard_home_metadata.st_mode)
                and not stat.S_ISLNK(guard_home_metadata.st_mode)
                and state_metadata is not None
                and stat.S_ISREG(state_metadata.st_mode)
                else "missing"
            )
            artifacts.append({"kind": state_kind, "path": str(state_path.relative_to(resolved_home))})
        records.append({"artifacts": artifacts, "name": name})
    user_record: dict[str, object] = {
        "harnesses": sorted(records, key=lambda item: str(item["name"])),
        "home": str(resolved_home),
    }
    retained: list[dict[str, object]] = [
        cast(dict[str, object], item)
        for item in users
        if isinstance(item, dict) and cast(dict[object, object], item).get("home") != str(resolved_home)
    ]
    retained.append(user_record)
    if len(retained) > _MAX_USERS:
        raise ValueError("harness_coverage_registry_capacity_exceeded")
    registry["users"] = sorted(retained, key=lambda item: str(cast(dict[object, object], item).get("home")))
    _write_registry(paths, registry)


def unregister_user_harnesses(paths: MachinePaths, home: Path) -> None:
    if not _administrator_context():
        raise PermissionError("harness_coverage_administrator_context_required")
    with protected_machine_state_lock(paths, "harness-coverage"):
        _unregister_user_harnesses_unlocked(paths, home)


def _unregister_user_harnesses_unlocked(paths: MachinePaths, home: Path) -> None:
    registry = _read_registry(paths)
    if registry is None:
        return
    resolved_home = str(home.resolve(strict=False))
    users = cast(list[object], registry["users"])
    registry["users"] = [
        item
        for item in users
        if isinstance(item, dict) and cast(dict[object, object], item).get("home") != resolved_home
    ]
    _write_registry(paths, registry)


def _artifact_state(home: Path, artifact: dict[str, object]) -> str:
    if set(artifact) not in ({"kind", "path"}, {"kind", "path", "sha256"}):
        raise ValueError("harness_coverage_registry_invalid")
    relative = artifact.get("path")
    kind = artifact.get("kind")
    if not isinstance(relative, str) or not relative or kind not in {
        "file",
        "directory",
        "missing",
        "mutable-file",
    }:
        raise ValueError("harness_coverage_registry_invalid")
    target = (home / relative).resolve(strict=False)
    if not target.is_relative_to(home):
        raise ValueError("harness_coverage_registry_invalid")
    try:
        actual_kind, actual_digest = artifact_digest(target)
    except OSError:
        return "missing"
    if kind == "missing" or actual_kind == "missing":
        return "missing"
    if kind == "mutable-file":
        return "protected" if actual_kind == "file" else "degraded"
    if kind != actual_kind:
        return "degraded"
    if kind in {"file", "directory"} and artifact.get("sha256") != actual_digest:
        return "degraded"
    return "protected"


def verify_harness_coverage(paths: MachinePaths, policy: ManagedPolicyState) -> HarnessCoverageVerification:
    required_harnesses = policy.policy.required_harnesses if policy.policy is not None else ()
    if not required_harnesses:
        return HarnessCoverageVerification(
            "healthy",
            "harness_coverage_not_required",
            HarnessCoverage(required=0, protected=0, degraded=0, missing=0),
        )
    try:
        registry = _read_registry(paths)
        if registry is None:
            return HarnessCoverageVerification(
                "unknown",
                "harness_coverage_registry_absent",
                HarnessCoverage(required=None, protected=None, degraded=None, missing=None),
            )
        users = cast(list[object], registry["users"])
        protected = degraded = missing = 0
        for raw_user in users:
            if not isinstance(raw_user, dict):
                raise ValueError("harness_coverage_registry_invalid")
            user = cast(dict[str, object], raw_user)
            if set(user) != {"harnesses", "home"} or not isinstance(user.get("home"), str):
                raise ValueError("harness_coverage_registry_invalid")
            home = Path(cast(str, user["home"])).resolve(strict=False)
            harnesses_value = user.get("harnesses")
            if not isinstance(harnesses_value, list):
                raise ValueError("harness_coverage_registry_invalid")
            harnesses_raw = cast(list[object], harnesses_value)
            if len(harnesses_raw) > _MAX_HARNESSES_PER_USER:
                raise ValueError("harness_coverage_registry_invalid")
            harnesses = {
                str(cast(dict[str, object], item).get("name")): cast(dict[str, object], item)
                for item in harnesses_raw
                if isinstance(item, dict)
            }
            for required in required_harnesses:
                harness = harnesses.get(required)
                if harness is None:
                    missing += 1
                    continue
                if set(harness) != {"artifacts", "name"} or harness.get("name") != required:
                    raise ValueError("harness_coverage_registry_invalid")
                artifacts_value = harness.get("artifacts")
                if not isinstance(artifacts_value, list):
                    raise ValueError("harness_coverage_registry_invalid")
                artifacts = cast(list[object], artifacts_value)
                if len(artifacts) > _MAX_ARTIFACTS_PER_HARNESS:
                    raise ValueError("harness_coverage_registry_invalid")
                if not artifacts:
                    degraded += 1
                    continue
                states = [
                    _artifact_state(home, cast(dict[str, object], artifact))
                    if isinstance(artifact, dict)
                    else "invalid"
                    for artifact in artifacts
                ]
                if "invalid" in states:
                    raise ValueError("harness_coverage_registry_invalid")
                if "missing" in states:
                    missing += 1
                elif "degraded" in states:
                    degraded += 1
                else:
                    protected += 1
        required = len(users) * len(required_harnesses)
        coverage = HarnessCoverage(required=required, protected=protected, degraded=degraded, missing=missing)
        if missing:
            return HarnessCoverageVerification("degraded", "harness_coverage_missing", coverage)
        if degraded:
            return HarnessCoverageVerification("degraded", "harness_coverage_degraded", coverage)
        return HarnessCoverageVerification("healthy", "harness_coverage_healthy", coverage)
    except (OSError, PermissionError, ValueError):
        return HarnessCoverageVerification(
            "unknown",
            "harness_coverage_probe_failed",
            HarnessCoverage(required=None, protected=None, degraded=None, missing=None),
        )


__all__ = [
    "HarnessCoverageVerification",
    "register_user_harnesses",
    "unregister_user_harnesses",
    "verify_harness_coverage",
]
