"""Exact launch evidence for bounded local Bun package scripts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import stat
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal, cast
from urllib.parse import urlsplit

from .containment_executor import file_sha256

PackageScriptOperation = Literal["test", "lint", "build", "typecheck"]
EvidenceStatus = Literal["complete", "incomplete"]

_OPERATIONS: Final = frozenset({"test", "lint", "build", "typecheck"})
_RUNNER_PACKAGE: Final = {"vitest": "vitest", "eslint": "eslint", "vite": "vite", "tsc": "typescript"}
_VERSION = re.compile(r"^(?:[~^])?(\d+)\.(\d+)\.(\d+)$")
_MAX_JSON_BYTES: Final = 16 * 1024 * 1024
_ALTERNATE_LOCKS: Final = ("bun.lock", "bun.lockb", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
_TEST_SUFFIXES: Final = (
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
)
_LINT_SUFFIXES: Final = (".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx")


@dataclass(frozen=True, slots=True)
class LocalPackageScriptEvidence:
    schema_version: int
    status: EvidenceStatus
    reasons: tuple[str, ...]
    binding_digest: str
    operation_id: PackageScriptOperation
    runner: str
    runner_args: tuple[str, ...]
    input_files: tuple[str, ...]
    executable_path: str | None
    executable_hash: str | None
    root_manifest_hash: str | None
    lockfile_hash: str | None
    package_manifest_hash: str | None
    package_version: str | None
    evidence_scope: Literal["launch_identity"] = "launch_identity"
    review_disposition: Literal["review_required"] = "review_required"
    direct_silent_verification: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_local_package_script_evidence(
    manager: str,
    argv: tuple[str, ...],
    *,
    workspace: Path,
) -> LocalPackageScriptEvidence | None:
    """Bind one exact Bun script to package, lock, executable, and inputs."""

    if manager != "bun" or len(argv) != 2 or argv[0] != "run" or argv[1] not in _OPERATIONS:
        return None
    operation = cast(PackageScriptOperation, argv[1])
    root_manifest = workspace / "package.json"
    lockfile = workspace / "package-lock.json"
    root_payload, root_hash = _read_json(root_manifest)
    lock_payload, lock_hash = _read_json(lockfile)
    reasons: list[str] = []
    script = _package_script(root_payload, operation)
    launch = _script_launch(operation, script, workspace, reasons)
    if launch is None:
        runner, runner_args, input_files = "invalid", (), ()
    else:
        runner, runner_args, input_files = launch
    package = _RUNNER_PACKAGE.get(runner)
    package_root = workspace / "node_modules" / (package or "invalid")
    package_manifest = package_root / "package.json"
    package_payload, package_hash = _read_json(package_manifest)

    _require(root_payload is not None and root_hash is not None, "manifest_identity_incomplete", reasons)
    _require(lock_payload is not None and lock_hash is not None, "lock_identity_incomplete", reasons)
    _require(not any((workspace / name).exists() for name in _ALTERNATE_LOCKS), "lock_source_ambiguous", reasons)
    _require(package is not None, "script_runner_unsupported", reasons)
    _require(not _has_lifecycle_script(root_payload, operation), "lifecycle_script_present", reasons)

    declared = _dependency_version(root_payload, package)
    locked, source_ok = _locked_version(lock_payload, package)
    installed_name = _string_value(package_payload, "name")
    installed_version = _string_value(package_payload, "version")
    _require(declared is not None, "manifest_dependency_missing", reasons)
    _require(locked is not None, "lock_dependency_missing", reasons)
    _require(source_ok, "lock_source_drift", reasons)
    _require(installed_name == package, "installed_package_name_mismatch", reasons)
    _require(installed_version is not None, "installed_package_missing", reasons)
    _require(_version_spec_matches(declared, locked), "manifest_lock_version_drift", reasons)
    _require(locked == installed_version, "lock_install_version_drift", reasons)

    bin_target = _package_bin_target(package_payload, runner)
    executable = _resolved_bin_target(package_root, bin_target)
    executable_path: str | None = None
    executable_hash: str | None = None
    if executable is not None:
        try:
            canonical = executable.resolve(strict=True)
            if executable.is_symlink() or not canonical.is_file():
                raise ValueError("runner executable must be a regular file")
            executable_path = str(canonical)
            executable_hash = f"sha256:{file_sha256(executable_path)}"
        except (OSError, ValueError):
            pass
    _require(bin_target is not None, "package_bin_missing", reasons)
    _require(executable_path is not None and executable_hash is not None, "executable_identity_incomplete", reasons)

    normalized_reasons = tuple(dict.fromkeys(reasons))
    binding_digest = _digest(
        {
            "schema_version": 1,
            "manager": manager,
            "operation": operation,
            "script": script,
            "runner": runner,
            "runner_args": runner_args,
            "input_files": input_files,
            "manifest_hash": root_hash,
            "lock_hash": lock_hash,
            "package_manifest_hash": package_hash,
            "declared_version": declared,
            "locked_version": locked,
            "installed_name": installed_name,
            "installed_version": installed_version,
            "executable_path": executable_path,
            "executable_hash": executable_hash,
            "reasons": normalized_reasons,
        }
    )
    return LocalPackageScriptEvidence(
        schema_version=1,
        status="complete" if not normalized_reasons else "incomplete",
        reasons=normalized_reasons,
        binding_digest=binding_digest,
        operation_id=operation,
        runner=runner,
        runner_args=runner_args,
        input_files=input_files,
        executable_path=executable_path,
        executable_hash=executable_hash,
        root_manifest_hash=root_hash,
        lockfile_hash=lock_hash,
        package_manifest_hash=package_hash,
        package_version=installed_version,
    )


def _script_launch(
    operation: PackageScriptOperation,
    script: str | None,
    workspace: Path,
    reasons: list[str],
) -> tuple[str, tuple[str, ...], tuple[str, ...]] | None:
    if script is None or any(marker in script for marker in ("\n", "\r", ";", "&", "|", ">", "<", "$", "`")):
        reasons.append("script_not_exact")
        return None
    try:
        tokens = tuple(shlex.split(script, posix=True))
    except ValueError:
        reasons.append("script_not_exact")
        return None
    expected_runner = {"test": "vitest", "lint": "eslint", "build": "vite", "typecheck": "tsc"}[operation]
    if not tokens or tokens[0] != expected_runner:
        reasons.append("script_runner_mismatch")
        return None
    args = tokens[1:]
    raw_files: tuple[str, ...] = ()
    if operation == "test":
        if not args or args[0] != "run" or any(value.startswith("-") for value in args[1:]):
            reasons.append("script_arguments_not_result_only")
        raw_files = args[1:]
    elif operation == "lint":
        if args.count("--no-cache") != 1 or any(value.startswith("-") and value != "--no-cache" for value in args):
            reasons.append("script_arguments_not_result_only")
        raw_files = tuple(value for value in args if value != "--no-cache")
    elif (operation == "build" and args != ("build",)) or (operation == "typecheck" and not _typecheck_args(args)):
        reasons.append("script_arguments_not_result_only")
    input_files = _validated_inputs(workspace, operation, raw_files, reasons)
    return expected_runner, args, input_files


def _typecheck_args(args: tuple[str, ...]) -> bool:
    return args in {("--noEmit",), ("--noEmit", "--pretty")}


def _validated_inputs(
    workspace: Path,
    operation: PackageScriptOperation,
    raw_files: tuple[str, ...],
    reasons: list[str],
) -> tuple[str, ...]:
    if operation not in {"test", "lint"}:
        return ()
    if not raw_files:
        reasons.append("explicit_inputs_missing")
        return ()
    suffixes = _TEST_SUFFIXES if operation == "test" else _LINT_SUFFIXES
    result: list[str] = []
    for raw_file in raw_files:
        candidate = workspace / raw_file
        try:
            canonical = candidate.resolve(strict=True)
            relative = canonical.relative_to(workspace)
        except (OSError, ValueError):
            reasons.append("input_outside_workspace")
            continue
        portable = relative.as_posix()
        if candidate.is_symlink() or not canonical.is_file() or not portable.endswith(suffixes):
            reasons.append("input_not_exact_regular_source")
        elif raw_file.replace("\\", "/") != portable or any(
            part.lower().startswith(".env") or part.lower() in {".git", ".guard"} for part in relative.parts
        ):
            reasons.append("input_alias_or_protected")
        else:
            result.append(portable)
    if len(result) != len(set(result)):
        reasons.append("input_alias_or_duplicate")
    return tuple(result)


def _read_json(path: Path) -> tuple[dict[str, object] | None, str | None]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_JSON_BYTES:
            return None, None
        content = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            content.extend(chunk)
            if len(content) > _MAX_JSON_BYTES:
                return None, None
        after = os.fstat(descriptor)
    except OSError:
        return None, None
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        return None, None
    try:
        encoded = bytes(content)
        payload = _object_mapping(cast(object, json.loads(encoded.decode("utf-8"))))
    except (UnicodeDecodeError, ValueError):
        return None, None
    return payload, f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _package_script(payload: dict[str, object] | None, operation: str) -> str | None:
    scripts = _object_mapping(payload.get("scripts")) if payload is not None else None
    value = scripts.get(operation) if scripts is not None else None
    return value.strip() if isinstance(value, str) and value.strip() else None


def _has_lifecycle_script(payload: dict[str, object] | None, operation: str) -> bool:
    return (
        _package_script(payload, f"pre{operation}") is not None
        or _package_script(payload, f"post{operation}") is not None
    )


def _dependency_version(payload: dict[str, object] | None, package: str | None) -> str | None:
    if payload is None or package is None:
        return None
    for group in ("dependencies", "devDependencies", "optionalDependencies"):
        values = _object_mapping(payload.get(group))
        value = values.get(package) if values is not None else None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _locked_version(payload: dict[str, object] | None, package: str | None) -> tuple[str | None, bool]:
    packages = _object_mapping(payload.get("packages")) if payload is not None else None
    item = _object_mapping(packages.get(f"node_modules/{package}")) if packages is not None and package else None
    version = item.get("version") if item is not None else None
    resolved = item.get("resolved") if item is not None else None
    integrity = item.get("integrity") if item is not None else None
    valid_version = version.strip() if isinstance(version, str) and version.strip() else None
    return valid_version, bool(
        item is not None
        and item.get("link") is not True
        and valid_version is not None
        and package is not None
        and _canonical_resolution(package, valid_version, resolved)
        and _valid_integrity(integrity)
    )


def _canonical_resolution(package: str, version: str, resolved: object) -> bool:
    if not isinstance(resolved, str):
        return False
    parsed = urlsplit(resolved)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "registry.npmjs.org"
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and parsed.path == f"/{package}/-/{package}-{version}.tgz"
        and not parsed.query
        and not parsed.fragment
    )


def _valid_integrity(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        decoded = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 64


def _package_bin_target(payload: dict[str, object] | None, runner: str) -> str | None:
    value = payload.get("bin") if payload is not None else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    mapping = _object_mapping(value)
    target = mapping.get(runner) if mapping is not None else None
    return target.strip() if isinstance(target, str) and target.strip() else None


def _resolved_bin_target(package_root: Path, target: str | None) -> Path | None:
    if target is None:
        return None
    portable = PurePosixPath(target.replace("\\", "/"))
    if portable.is_absolute() or not portable.parts or ".." in portable.parts:
        return None
    candidate = package_root.joinpath(*portable.parts).resolve(strict=False)
    try:
        _ = candidate.relative_to(package_root)
    except ValueError:
        return None
    return candidate


def _version_spec_matches(specifier: str | None, version: str | None) -> bool:
    if specifier is None or version is None:
        return False
    spec = _VERSION.fullmatch(specifier)
    actual = _VERSION.fullmatch(version)
    if spec is None or actual is None:
        return False
    floor = tuple(int(value) for value in spec.groups())
    observed = tuple(int(value) for value in actual.groups())
    if specifier.startswith("^"):
        return observed >= floor and observed[0] == floor[0] if floor[0] else observed == floor
    if specifier.startswith("~"):
        return observed >= floor and observed[:2] == floor[:2]
    return observed == floor


def _string_value(payload: dict[str, object] | None, key: str) -> str | None:
    value = payload.get(key) if payload is not None else None
    return value.strip() if isinstance(value, str) and value.strip() else None


def _object_mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        return None
    return {str(key): item for key, item in raw.items()}


def _require(condition: bool, reason: str, reasons: list[str]) -> None:
    if not condition:
        reasons.append(reason)


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = ("LocalPackageScriptEvidence", "build_local_package_script_evidence")
