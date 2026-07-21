"""Typed evidence for reviewable local TypeScript compiler launches."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, cast

TypeScriptLaunchStatus = Literal["complete", "incomplete"]

_SAFE_COMPILER_FLAGS = frozenset(
    {
        "--diagnostics",
        "--extendedDiagnostics",
        "--explainFiles",
        "--listFiles",
        "--listFilesOnly",
        "--noEmit",
        "--noErrorTruncation",
        "--pretty",
        "--skipLibCheck",
        "--traceResolution",
    }
)
_UNSAFE_SOURCE_PREFIXES = ("file:", "git+", "git://", "github:", "http://", "https://", "npm:", "workspace:")
_VERSION_RE = re.compile(r"^(?:[~^])?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")


@dataclass(frozen=True, slots=True)
class TypeScriptLaunchInputs:
    """Normalized inputs captured by the package-runner parser."""

    tokens: tuple[str, ...]
    manager_name: str
    local_only_requested: bool
    package_name: str | None
    executable_name: str | None
    declared_version: str | None
    manager_path: str | None
    manager_hash: str | None
    executable_path: str | None
    executable_hash: str | None
    manifest_paths: tuple[str, ...]
    manifest_hashes: tuple[str, ...]
    lockfile_paths: tuple[str, ...]
    lockfile_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TypeScriptLaunchEvidence:
    """Complete launch identity evidence that never grants a silent allow."""

    schema_version: int
    status: TypeScriptLaunchStatus
    reasons: tuple[str, ...]
    binding_digest: str
    manager_name: str
    package_name: str | None
    executable_name: str | None
    declared_version: str | None
    locked_version: str | None
    installed_version: str | None
    config_mode: str
    source_files: tuple[str, ...]
    evidence_scope: Literal["launch_identity"] = "launch_identity"
    review_disposition: Literal["review_required"] = "review_required"
    direct_silent_verification: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_typescript_launch_evidence(inputs: TypeScriptLaunchInputs) -> TypeScriptLaunchEvidence | None:
    """Return immutable evidence for a TypeScript launch, without authorizing it."""

    if inputs.package_name not in {"tsc", "typescript"} and inputs.executable_name != "tsc":
        return None

    reasons: list[str] = []
    _require(inputs.manager_name == "npx", "manager_mismatch", reasons)
    _require(inputs.local_only_requested, "remote_install_not_disabled", reasons)
    _require(inputs.package_name in {"tsc", "typescript"}, "package_mismatch", reasons)
    _require(inputs.executable_name == "tsc", "executable_mismatch", reasons)
    _require(bool(inputs.manager_path and inputs.manager_hash), "manager_identity_incomplete", reasons)
    _require(bool(inputs.executable_path and inputs.executable_hash), "executable_identity_incomplete", reasons)

    compiler_args, explicit_package = _compiler_args(inputs.tokens)
    if explicit_package:
        reasons.append("explicit_package_source")
    source_files, arguments_valid = _read_only_compiler_arguments(compiler_args)
    _require(arguments_valid, "compiler_arguments_not_read_only", reasons)
    _require(bool(source_files), "implicit_or_config_driven_launch", reasons)

    manifest_version, manifest_source_ok, manifest_identity_ok = _manifest_typescript_version(
        inputs.manifest_paths,
        inputs.manifest_hashes,
    )
    locked_version, lock_source_ok, lock_identity_ok = _locked_typescript_version(
        inputs.lockfile_paths,
        inputs.lockfile_hashes,
    )
    installed_version, executable_matches, installed_manifest_hash = _installed_typescript_identity(
        inputs.executable_path
    )
    _require(manifest_version is not None, "manifest_dependency_missing", reasons)
    _require(manifest_source_ok, "manifest_source_drift", reasons)
    _require(manifest_identity_ok, "manifest_identity_drift", reasons)
    _require(locked_version is not None, "lock_dependency_missing", reasons)
    _require(lock_source_ok, "lock_source_drift", reasons)
    _require(lock_identity_ok, "lock_identity_drift", reasons)
    _require(installed_version is not None, "installed_package_missing", reasons)
    _require(executable_matches, "wrong_typescript_executable", reasons)
    _require(inputs.declared_version == manifest_version, "declared_dependency_mismatch", reasons)
    _require(_version_spec_matches(manifest_version, locked_version), "manifest_lock_version_drift", reasons)
    _require(locked_version == installed_version, "lock_install_version_drift", reasons)
    _require(len(inputs.manifest_paths) == len(inputs.manifest_hashes), "manifest_identity_incomplete", reasons)
    _require(len(inputs.lockfile_paths) == len(inputs.lockfile_hashes), "lock_identity_incomplete", reasons)

    normalized_reasons = tuple(dict.fromkeys(reasons))
    binding_payload = {
        "schema_version": 1,
        "inputs": asdict(inputs),
        "locked_version": locked_version,
        "installed_version": installed_version,
        "installed_manifest_hash": installed_manifest_hash,
        "config_mode": "explicit_sources" if source_files else "implicit_or_config_driven",
        "source_files": source_files,
        "reasons": normalized_reasons,
    }
    binding_digest = hashlib.sha256(
        b"hol-guard:typescript-launch-evidence:v1\0"
        + json.dumps(binding_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return TypeScriptLaunchEvidence(
        schema_version=1,
        status="complete" if not normalized_reasons else "incomplete",
        reasons=normalized_reasons,
        binding_digest=f"sha256:{binding_digest}",
        manager_name=inputs.manager_name,
        package_name=inputs.package_name,
        executable_name=inputs.executable_name,
        declared_version=inputs.declared_version,
        locked_version=locked_version,
        installed_version=installed_version,
        config_mode="explicit_sources" if source_files else "implicit_or_config_driven",
        source_files=source_files,
    )


def _require(condition: bool, reason: str, reasons: list[str]) -> None:
    if not condition:
        reasons.append(reason)


def _compiler_args(tokens: tuple[str, ...]) -> tuple[tuple[str, ...], bool]:
    explicit_package = any(token == "--package" or token.startswith("--package=") for token in tokens[1:])
    try:
        executable_index = tokens.index("tsc", 1)
    except ValueError:
        return (), explicit_package
    return tokens[executable_index + 1 :], explicit_package


def _read_only_compiler_arguments(arguments: tuple[str, ...]) -> tuple[tuple[str, ...], bool]:
    if "--noEmit" not in arguments:
        return (), False
    sources: list[str] = []
    for argument in arguments:
        if argument in _SAFE_COMPILER_FLAGS:
            continue
        if argument.endswith((".cts", ".mts", ".ts", ".tsx")) and not argument.startswith("-"):
            sources.append(argument)
            continue
        return tuple(sources), False
    return tuple(sources), True


def _manifest_typescript_version(
    paths: tuple[str, ...],
    hashes: tuple[str, ...],
) -> tuple[str | None, bool, bool]:
    identity_ok = len(paths) == len(hashes)
    for raw_path, expected_hash in zip(paths, hashes, strict=False):
        if Path(raw_path).name != "package.json":
            continue
        payload, observed_hash = _read_json(Path(raw_path))
        if payload is None:
            continue
        identity_ok = identity_ok and observed_hash == expected_hash
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            dependencies = _object_mapping(payload.get(group))
            value = dependencies.get("typescript") if dependencies is not None else None
            if isinstance(value, str) and value.strip():
                normalized = value.strip()
                return normalized, not normalized.lower().startswith(_UNSAFE_SOURCE_PREFIXES), identity_ok
    return None, False, identity_ok


def _locked_typescript_version(
    paths: tuple[str, ...],
    hashes: tuple[str, ...],
) -> tuple[str | None, bool, bool]:
    identity_ok = len(paths) == len(hashes)
    for raw_path, expected_hash in zip(paths, hashes, strict=False):
        if Path(raw_path).name != "package-lock.json":
            continue
        payload, observed_hash = _read_json(Path(raw_path))
        identity_ok = identity_ok and observed_hash == expected_hash
        packages = _object_mapping(payload.get("packages")) if payload is not None else None
        entry = _object_mapping(packages.get("node_modules/typescript")) if packages is not None else None
        if entry is None:
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version.strip():
            continue
        resolved = entry.get("resolved")
        source_ok = entry.get("link") is not True and (
            resolved is None
            or (isinstance(resolved, str) and not resolved.lower().startswith(("file:", "git+", "git://")))
        )
        return version.strip(), source_ok, identity_ok
    return None, False, identity_ok


def _installed_typescript_identity(executable_path: str | None) -> tuple[str | None, bool, str | None]:
    if executable_path is None:
        return None, False, None
    executable = Path(executable_path)
    if executable.name != "tsc" or executable.parent.name != "bin" or executable.parent.parent.name != "typescript":
        return None, False, None
    package_manifest = executable.parent.parent / "package.json"
    payload, manifest_hash = _read_json(package_manifest)
    if payload is None:
        return None, False, manifest_hash
    version = payload.get("version")
    bin_value = _object_mapping(payload.get("bin"))
    bin_target = bin_value.get("tsc") if bin_value is not None else None
    target_ok = isinstance(bin_target, str) and (package_manifest.parent / bin_target).resolve() == executable.resolve()
    return (version.strip() if isinstance(version, str) and version.strip() else None), target_ok, manifest_hash


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
        return version_parts >= spec_parts and version_parts[0] == spec_parts[0]
    if specifier.startswith("~"):
        return version_parts >= spec_parts and version_parts[:2] == spec_parts[:2]
    return version_parts == spec_parts


def _read_json(path: Path) -> tuple[dict[str, object] | None, str | None]:
    try:
        content = path.read_bytes()
        raw_payload = cast(object, json.loads(content.decode("utf-8")))
    except (OSError, UnicodeDecodeError, ValueError):
        return None, None
    return _object_mapping(raw_payload), f"sha256:{hashlib.sha256(content).hexdigest()}"


def _object_mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw_mapping = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw_mapping):
        return None
    return {str(key): item for key, item in raw_mapping.items()}
