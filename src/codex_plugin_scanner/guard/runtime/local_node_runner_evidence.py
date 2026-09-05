"""Typed launch evidence for exact result-only local Node runners."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlsplit

from .containment_executor import file_sha256
from .package_evidence_common import (
    object_mapping,
    read_json_with_integrity,
    require,
    resolved_package_bin_target,
    valid_sha512_integrity,
    version_spec_matches,
)
from .package_intent_common import LocalPackageExecutionEvidence, PackageExecutionFileEvidence

RunnerKind = Literal["vitest", "eslint", "tsx"]
EvidenceStatus = Literal["complete", "incomplete"]

_VERSION_RE = re.compile(r"^(?:[~^])?(\d+)\.(\d+)\.(\d+)$")
_RUNNER_OPERATION = {"vitest": "test", "eslint": "lint", "tsx": "diagnostic"}
_SOURCE_PREFIXES = ("file:", "git+", "git://", "github:", "http://", "https://", "npm:", "workspace:")
_TEST_SUFFIXES = (".test.js", ".test.jsx", ".test.ts", ".test.tsx", ".spec.js", ".spec.jsx", ".spec.ts", ".spec.tsx")
_LINT_SUFFIXES = (".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx")


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
    require(manager == "npx", "manager_mismatch", reasons)
    require(execution.manager_name == manager, "manager_evidence_mismatch", reasons)
    require(execution.local_only_requested or runner == "tsx", "remote_install_not_disabled", reasons)
    require(execution.package_name == runner, "package_mismatch", reasons)
    require(execution.executable_name == runner, "executable_mismatch", reasons)
    require(
        execution.manager is not None and execution.manager.status == "available",
        "manager_identity_incomplete",
        reasons,
    )

    executable = execution.local_executable
    executable_path = executable.resolved_path if executable is not None else None
    executable_hash = executable.content_hash if executable is not None else None
    require(
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
    root_payload, root_hash = read_json_with_integrity(root_manifest)
    lock_payload, lock_hash = read_json_with_integrity(lockfile)
    package_payload, package_hash = read_json_with_integrity(package_manifest)
    require(_evidence_contains(execution.manifests, root_manifest, root_hash), "manifest_identity_drift", reasons)
    require(_evidence_contains(execution.lockfiles, lockfile, lock_hash), "lock_identity_drift", reasons)
    require(_has_only_package_lock(execution), "lock_source_ambiguous", reasons)

    declared_version = _dependency_version(root_payload, runner)
    locked_version, lock_source_ok = _locked_version(lock_payload, runner)
    installed_name = _string_value(package_payload, "name")
    installed_version = _string_value(package_payload, "version")
    require(declared_version is not None, "manifest_dependency_missing", reasons)
    require(
        declared_version is not None and not declared_version.lower().startswith(_SOURCE_PREFIXES),
        "manifest_source_drift",
        reasons,
    )
    require(locked_version is not None, "lock_dependency_missing", reasons)
    require(lock_source_ok, "lock_source_drift", reasons)
    require(installed_name == runner, "installed_package_name_mismatch", reasons)
    require(installed_version is not None, "installed_package_missing", reasons)
    require(
        version_spec_matches(declared_version, locked_version, version_re=_VERSION_RE, caret_pins_zero_major=True),
        "manifest_lock_version_drift",
        reasons,
    )
    require(locked_version == installed_version, "lock_install_version_drift", reasons)
    require(execution.declared_version == declared_version, "declared_dependency_mismatch", reasons)

    bin_target = _package_bin_target(package_payload, runner)
    expected_executable = _resolved_bin_target(package_root, bin_target)
    require(bin_target is not None, "package_bin_missing", reasons)
    require(
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
        require(observed_hash == executable_hash, "executable_identity_drift", reasons)

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
    elif runner == "eslint":
        if tail.count("--no-cache") != 1 or any(token.startswith("-") and token != "--no-cache" for token in tail):
            reasons.append("runner_arguments_not_result_only")
        raw_files = tuple(token for token in tail if token != "--no-cache")
    else:
        if len(tail) != 1 or tail[0].startswith("-"):
            reasons.append("runner_arguments_not_result_only")
        raw_files = tail if len(tail) == 1 else ()
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
        values = object_mapping(payload.get(group))
        version = values.get(package) if values is not None else None
        if isinstance(version, str) and version.strip():
            return version.strip()
    return None


def _locked_version(payload: dict[str, object] | None, package: str) -> tuple[str | None, bool]:
    packages = object_mapping(payload.get("packages")) if payload is not None else None
    item = object_mapping(packages.get(f"node_modules/{package}")) if packages is not None else None
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


_valid_sha512_integrity = valid_sha512_integrity


def _package_bin_target(payload: dict[str, object] | None, runner: str) -> str | None:
    if payload is None:
        return None
    value = payload.get("bin")
    if isinstance(value, str) and value.strip():
        return value.strip()
    mapping = object_mapping(value)
    target = mapping.get(runner) if mapping is not None else None
    return target.strip() if isinstance(target, str) and target.strip() else None


_resolved_bin_target = resolved_package_bin_target


def _string_value(payload: dict[str, object] | None, key: str) -> str | None:
    value = payload.get(key) if payload is not None else None
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ("LocalNodeRunnerEvidence", "build_local_node_runner_evidence")
