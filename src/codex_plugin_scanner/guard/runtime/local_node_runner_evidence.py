"""Typed launch evidence for exact result-only local Node runners."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, cast
from urllib.parse import urlsplit

from .containment_executor import file_sha256
from .package_intent_common import LocalPackageExecutionEvidence, PackageExecutionFileEvidence

RunnerKind = Literal["vitest", "eslint"]
EvidenceStatus = Literal["complete", "incomplete"]

_VERSION_RE = re.compile(r"^(?:[~^])?(\d+)\.(\d+)\.(\d+)$")
_RUNNER_OPERATION = {"vitest": "test", "eslint": "lint"}
_SOURCE_PREFIXES = ("file:", "git+", "git://", "github:", "http://", "https://", "npm:", "workspace:")
_TEST_SUFFIXES = (".test.js", ".test.jsx", ".test.ts", ".test.tsx", ".spec.js", ".spec.jsx", ".spec.ts", ".spec.tsx")
_LINT_SUFFIXES = (".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx")
_MAX_JSON_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class LocalNodeRunnerEvidence:
    schema_version: int
    status: EvidenceStatus
    reasons: tuple[str, ...]
    binding_digest: str
    runner: RunnerKind
    operation_id: str
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


def build_local_node_runner_evidence(
    manager: str,
    argv: tuple[str, ...],
    execution: LocalPackageExecutionEvidence,
    *,
    workspace: Path,
) -> LocalNodeRunnerEvidence | None:
    """Build exact launch evidence without authorizing execution."""

    parsed = _runner_arguments(manager, argv, workspace)
    if parsed is None:
        return None
    runner, runner_args, input_files, argument_reasons = parsed
    reasons = list(argument_reasons)
    _require(manager == "npx", "manager_mismatch", reasons)
    _require(execution.manager_name == manager, "manager_evidence_mismatch", reasons)
    _require(execution.local_only_requested, "remote_install_not_disabled", reasons)
    _require(execution.package_name == runner, "package_mismatch", reasons)
    _require(execution.executable_name == runner, "executable_mismatch", reasons)
    _require(
        execution.manager is not None and execution.manager.status == "available",
        "manager_identity_incomplete",
        reasons,
    )

    executable = execution.local_executable
    executable_path = executable.resolved_path if executable is not None else None
    executable_hash = executable.content_hash if executable is not None else None
    _require(
        executable is not None
        and executable.status == "available"
        and executable_path is not None
        and executable_hash is not None,
        "executable_identity_incomplete",
        reasons,
    )

    root_manifest = workspace / "package.json"
    lockfile = workspace / "package-lock.json"
    package_root = workspace / "node_modules" / runner
    package_manifest = package_root / "package.json"
    root_payload, root_hash = _read_json(root_manifest)
    lock_payload, lock_hash = _read_json(lockfile)
    package_payload, package_hash = _read_json(package_manifest)
    _require(_evidence_contains(execution.manifests, root_manifest, root_hash), "manifest_identity_drift", reasons)
    _require(_evidence_contains(execution.lockfiles, lockfile, lock_hash), "lock_identity_drift", reasons)
    _require(_has_only_package_lock(execution), "lock_source_ambiguous", reasons)

    declared_version = _dependency_version(root_payload, runner)
    locked_version, lock_source_ok = _locked_version(lock_payload, runner)
    installed_name = _string_value(package_payload, "name")
    installed_version = _string_value(package_payload, "version")
    _require(declared_version is not None, "manifest_dependency_missing", reasons)
    _require(not str(declared_version or "").lower().startswith(_SOURCE_PREFIXES), "manifest_source_drift", reasons)
    _require(locked_version is not None, "lock_dependency_missing", reasons)
    _require(lock_source_ok, "lock_source_drift", reasons)
    _require(installed_name == runner, "installed_package_name_mismatch", reasons)
    _require(installed_version is not None, "installed_package_missing", reasons)
    _require(_version_spec_matches(declared_version, locked_version), "manifest_lock_version_drift", reasons)
    _require(locked_version == installed_version, "lock_install_version_drift", reasons)
    _require(execution.declared_version == declared_version, "declared_dependency_mismatch", reasons)

    bin_target = _package_bin_target(package_payload, runner)
    expected_executable = _resolved_bin_target(package_root, bin_target)
    _require(bin_target is not None, "package_bin_missing", reasons)
    _require(
        executable_path is not None
        and expected_executable is not None
        and Path(executable_path) == expected_executable,
        "wrong_local_executable",
        reasons,
    )
    if executable_path is not None and executable_hash is not None:
        try:
            observed_hash = f"sha256:{file_sha256(executable_path)}"
        except (OSError, ValueError):
            observed_hash = None
        _require(observed_hash == executable_hash, "executable_identity_drift", reasons)

    normalized_reasons = tuple(dict.fromkeys(reasons))
    binding_payload = {
        "schema_version": 1,
        "manager": manager,
        "manager_identity": execution.manager.to_dict() if execution.manager is not None else None,
        "runner": runner,
        "runner_args": runner_args,
        "input_files": input_files,
        "context_hash": execution.context_hash,
        "manifest_hash": root_hash,
        "lock_hash": lock_hash,
        "package_manifest_hash": package_hash,
        "declared_version": declared_version,
        "locked_version": locked_version,
        "installed_name": installed_name,
        "installed_version": installed_version,
        "executable_path": executable_path,
        "executable_hash": executable_hash,
        "reasons": normalized_reasons,
    }
    encoded = json.dumps(binding_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    binding_digest = hashlib.sha256(
        b"hol-guard:local-node-runner-evidence:v1\0" + len(encoded).to_bytes(8, "big") + encoded
    ).hexdigest()
    return LocalNodeRunnerEvidence(
        schema_version=1,
        status="complete" if not normalized_reasons else "incomplete",
        reasons=normalized_reasons,
        binding_digest=binding_digest,
        runner=runner,
        operation_id=_RUNNER_OPERATION[runner],
        runner_args=runner_args,
        input_files=input_files,
        executable_path=executable_path,
        executable_hash=executable_hash,
        root_manifest_hash=root_hash,
        lockfile_hash=lock_hash,
        package_manifest_hash=package_hash,
        package_version=installed_version,
    )


def _runner_arguments(
    manager: str,
    argv: tuple[str, ...],
    workspace: Path,
) -> tuple[RunnerKind, tuple[str, ...], tuple[str, ...], tuple[str, ...]] | None:
    if manager != "npx":
        return None
    index = 0
    while index < len(argv) and argv[index] in {"--no", "--no-install"}:
        index += 1
    if index >= len(argv) or argv[index] not in _RUNNER_OPERATION:
        return None
    runner = cast(RunnerKind, argv[index])
    tail = argv[index + 1 :]
    reasons: list[str] = []
    if any(token == "--package" or token.startswith("--package=") for token in argv):
        reasons.append("explicit_package_source")
    raw_files: tuple[str, ...]
    if runner == "vitest":
        if not tail or tail[0] != "run" or any(token.startswith("-") for token in tail[1:]):
            reasons.append("runner_arguments_not_result_only")
            raw_files = ()
        else:
            raw_files = tail[1:]
    else:
        if tail.count("--no-cache") != 1 or any(token.startswith("-") and token != "--no-cache" for token in tail):
            reasons.append("runner_arguments_not_result_only")
        raw_files = tuple(token for token in tail if token != "--no-cache")
    input_files = _validated_input_files(workspace, runner, raw_files, reasons)
    return runner, tail, input_files, tuple(reasons)


def _validated_input_files(
    workspace: Path,
    runner: RunnerKind,
    raw_files: tuple[str, ...],
    reasons: list[str],
) -> tuple[str, ...]:
    if not raw_files:
        reasons.append("explicit_inputs_missing")
        return ()
    suffixes = _TEST_SUFFIXES if runner == "vitest" else _LINT_SUFFIXES
    result: list[str] = []
    for raw_file in raw_files:
        candidate = workspace / raw_file
        try:
            canonical = candidate.resolve(strict=True)
            relative = canonical.relative_to(workspace)
        except (OSError, ValueError):
            reasons.append("input_outside_workspace")
            continue
        if candidate.is_symlink() or not candidate.is_file() or not relative.as_posix().endswith(suffixes):
            reasons.append("input_not_exact_regular_source")
            continue
        if any(part.lower().startswith(".env") or part.lower() in {".git", ".guard"} for part in relative.parts):
            reasons.append("input_protected")
            continue
        if raw_file.replace("\\", "/") != relative.as_posix():
            reasons.append("input_alias_or_duplicate")
            continue
        result.append(relative.as_posix())
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
        payload = cast(object, json.loads(encoded.decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        return None, None
    return _object_mapping(payload), f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _evidence_contains(
    values: Sequence[PackageExecutionFileEvidence],
    path: Path,
    content_hash: str | None,
) -> bool:
    canonical = str(path.resolve(strict=False))
    return any(
        getattr(item, "status", None) == "available"
        and getattr(item, "resolved_path", None) == canonical
        and getattr(item, "content_hash", None) == content_hash
        for item in values
    )


def _has_only_package_lock(execution: LocalPackageExecutionEvidence) -> bool:
    available = tuple(item for item in execution.lockfiles if item.status == "available")
    return len(available) == 1 and Path(available[0].resolved_path or "").name == "package-lock.json"


def _dependency_version(payload: dict[str, object] | None, package: str) -> str | None:
    if payload is None:
        return None
    for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = _object_mapping(payload.get(group))
        version = values.get(package) if values is not None else None
        if isinstance(version, str) and version.strip():
            return version.strip()
    return None


def _locked_version(payload: dict[str, object] | None, package: str) -> tuple[str | None, bool]:
    packages = _object_mapping(payload.get("packages")) if payload is not None else None
    item = _object_mapping(packages.get(f"node_modules/{package}")) if packages is not None else None
    version = item.get("version") if item is not None else None
    resolved = item.get("resolved") if item is not None else None
    integrity = item.get("integrity") if item is not None else None
    source_ok = (
        item is not None
        and item.get("link") is not True
        and isinstance(version, str)
        and _canonical_registry_resolution(package, version, resolved)
        and _valid_sha512_integrity(integrity)
    )
    return (version.strip() if isinstance(version, str) and version.strip() else None), source_ok


def _canonical_registry_resolution(package: str, version: str, resolved: object) -> bool:
    if not isinstance(resolved, str):
        return False
    parsed = urlsplit(resolved)
    expected_path = f"/{package}/-/{package}-{version}.tgz"
    return (
        parsed.scheme == "https"
        and parsed.hostname == "registry.npmjs.org"
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and parsed.path == expected_path
        and not parsed.query
        and not parsed.fragment
    )


def _valid_sha512_integrity(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        decoded = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 64


def _package_bin_target(payload: dict[str, object] | None, runner: str) -> str | None:
    if payload is None:
        return None
    value = payload.get("bin")
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


def _string_value(payload: dict[str, object] | None, key: str) -> str | None:
    value = payload.get(key) if payload is not None else None
    return value.strip() if isinstance(value, str) and value.strip() else None


def _version_spec_matches(specifier: str | None, version: str | None) -> bool:
    if specifier is None or version is None:
        return False
    spec_match = _VERSION_RE.fullmatch(specifier)
    version_match = _VERSION_RE.fullmatch(version)
    if spec_match is None or version_match is None:
        return False
    spec_parts = tuple(int(value) for value in spec_match.groups())
    version_parts = tuple(int(value) for value in version_match.groups())
    if specifier.startswith("^"):
        if spec_parts[0] > 0:
            return version_parts >= spec_parts and version_parts[0] == spec_parts[0]
        if spec_parts[1] > 0:
            return version_parts >= spec_parts and version_parts[:2] == spec_parts[:2]
        return version_parts == spec_parts
    if specifier.startswith("~"):
        return version_parts >= spec_parts and version_parts[:2] == spec_parts[:2]
    return version_parts == spec_parts


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


__all__ = ("LocalNodeRunnerEvidence", "build_local_node_runner_evidence")
