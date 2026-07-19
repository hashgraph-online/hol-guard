"""Typed contract for execution-enforced Guard containment."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Final, cast

from .effect_contract import ProofRequirement, ProofRoute
from .effect_decision import PositiveProof

CONTAINMENT_SCHEMA_VERSION: Final = "guard.containment.v1"
CONTAINMENT_POLICY_VERSION: Final = "guard.containment-policy.v1"
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_STABLE_ID: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_SECRET_ENV: Final = re.compile(
    r"(?:^|_)(?:auth|credential|key|password|secret|token)(?:_|$)|^(?:aws|azure|gcp|github|gitlab|npm|pypi)_",
    re.IGNORECASE,
)
_PROTECTED_PARTS: Final = frozenset(
    {".git", ".ssh", ".aws", ".gnupg", ".guard", "guard-home", "credentials", "credentials.json", "secrets.json"}
)


class ContainmentBackend(str, Enum):
    UNSUPPORTED = "unsupported"
    MACOS_SANDBOX = "macos-sandbox"
    LINUX_BWRAP = "linux-bwrap"


class ContainmentFailure(str, Enum):
    UNSUPPORTED_PLATFORM = "unsupported-platform"
    BACKEND_UNAVAILABLE = "backend-unavailable"
    BACKEND_IDENTITY_MISMATCH = "backend-identity-mismatch"
    POLICY_MISMATCH = "policy-mismatch"
    LAUNCH_MISMATCH = "launch-mismatch"
    APPLY_FAILED = "apply-failed"
    ATTESTATION_INVALID = "attestation-invalid"


@dataclass(frozen=True, slots=True)
class ContainmentInput:
    """One exact workspace file copied into the isolated execution snapshot."""

    source_path: str
    snapshot_path: str
    content_digest: str

    def __post_init__(self) -> None:
        source = _canonical_file(self.source_path, "containment input")
        snapshot = PurePosixPath(self.snapshot_path)
        if (
            snapshot.is_absolute()
            or not snapshot.parts
            or any(part in {"", ".", ".."} for part in snapshot.parts)
            or any(part.lower() in _PROTECTED_PARTS or part.lower().startswith(".env") for part in snapshot.parts)
        ):
            raise ValueError("snapshot_path must be a safe relative workspace path")
        if _SHA256.fullmatch(self.content_digest) is None:
            raise ValueError("content_digest must be a lowercase SHA-256 digest")
        object.__setattr__(self, "source_path", source)
        object.__setattr__(self, "snapshot_path", snapshot.as_posix())


@dataclass(frozen=True, slots=True)
class ContainmentPolicy:
    """Exact deny-by-default policy for one contained launch."""

    workspace: str
    allowed_write_paths: tuple[str, ...]
    network_allowed: bool = False
    policy_version: str = CONTAINMENT_POLICY_VERSION

    def __post_init__(self) -> None:
        if self.policy_version != CONTAINMENT_POLICY_VERSION:
            raise ValueError("unsupported containment policy version")
        workspace = _canonical_directory(self.workspace, "workspace")
        if self.network_allowed:
            raise ValueError("routine containment cannot allow network access")
        writes = _canonical_paths(self.allowed_write_paths, workspace=workspace)
        if any(_is_protected(path, workspace=workspace) for path in writes):
            raise ValueError("allowed write paths cannot include protected Guard, VCS, or secret paths")
        object.__setattr__(self, "workspace", workspace)
        object.__setattr__(self, "allowed_write_paths", writes)

    @property
    def digest(self) -> str:
        return _framed_digest(
            {
                "schema_version": CONTAINMENT_SCHEMA_VERSION,
                "policy_version": self.policy_version,
                "workspace": _path_digest(self.workspace),
                "allowed_write_paths": [_path_digest(path) for path in self.allowed_write_paths],
                "network_allowed": self.network_allowed,
                "secret_reads": "deny",
                "external_writes": "deny",
                "guard_controls": "deny",
            }
        )


@dataclass(frozen=True, slots=True)
class ContainmentRequest:
    """Path-pinned execution request whose identity is checked immediately before spawn."""

    argv: tuple[str, ...]
    cwd: str
    environment: tuple[tuple[str, str], ...]
    policy: ContainmentPolicy
    inputs: tuple[ContainmentInput, ...]
    launch_digest: str
    executable_digest: str
    operation_id: str
    schema_version: str = CONTAINMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONTAINMENT_SCHEMA_VERSION:
            raise ValueError("unsupported containment schema version")
        raw_argv = cast(object, self.argv)
        if (
            not isinstance(raw_argv, tuple)
            or not raw_argv
            or any(not isinstance(arg, str) or "\x00" in arg for arg in cast(tuple[object, ...], raw_argv))
        ):
            raise ValueError("argv must contain non-NUL strings")
        executable = _canonical_executable(self.argv[0])
        cwd = _canonical_directory(self.cwd, "cwd")
        _require_within(cwd, self.policy.workspace, "cwd")
        if _SHA256.fullmatch(self.launch_digest) is None:
            raise ValueError("launch_digest must be a lowercase SHA-256 digest")
        if _SHA256.fullmatch(self.executable_digest) is None:
            raise ValueError("executable_digest must be a lowercase SHA-256 digest")
        if _STABLE_ID.fullmatch(self.operation_id) is None:
            raise ValueError("operation_id must be a stable identifier")
        environment = _validated_environment(self.environment)
        inputs = _validated_inputs(self.inputs, workspace=self.policy.workspace)
        object.__setattr__(self, "argv", (executable, *self.argv[1:]))
        object.__setattr__(self, "cwd", cwd)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "inputs", inputs)

    @property
    def binding_digest(self) -> str:
        return _framed_digest(
            {
                "schema_version": self.schema_version,
                "operation_id": self.operation_id,
                "argv": list(self.argv),
                "cwd": _path_digest(self.cwd),
                "environment": [[key, _value_digest(value)] for key, value in self.environment],
                "inputs": [
                    {
                        "source_path": _path_digest(item.source_path),
                        "snapshot_path": item.snapshot_path,
                        "content_digest": item.content_digest,
                    }
                    for item in self.inputs
                ],
                "policy_digest": self.policy.digest,
                "launch_digest": self.launch_digest,
                "executable_digest": self.executable_digest,
            }
        )

    def environment_dict(self) -> dict[str, str]:
        return dict(self.environment)


@dataclass(frozen=True, slots=True)
class ContainmentAttestation:
    """Privacy-safe statement that an exact launch ran under an exact backend policy."""

    backend: ContainmentBackend
    backend_digest: str
    request_digest: str
    policy_digest: str
    launch_digest: str
    executable_digest: str
    enforced: bool
    failure: ContainmentFailure | None
    schema_version: str = CONTAINMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONTAINMENT_SCHEMA_VERSION:
            raise ValueError("unsupported containment attestation schema version")
        if not isinstance(cast(object, self.backend), ContainmentBackend):
            raise ValueError("backend must be an exact ContainmentBackend")
        digests = (
            ("backend_digest", self.backend_digest),
            ("request_digest", self.request_digest),
            ("policy_digest", self.policy_digest),
            ("launch_digest", self.launch_digest),
            ("executable_digest", self.executable_digest),
        )
        for name, value in digests:
            if _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if type(self.enforced) is not bool:
            raise ValueError("enforced must be a boolean")
        if self.failure is not None and not isinstance(cast(object, self.failure), ContainmentFailure):
            raise ValueError("failure must be an exact ContainmentFailure")
        if self.enforced == (self.failure is not None):
            raise ValueError("enforced attestations cannot fail and failed attestations cannot claim enforcement")

    def execution_bound_proof(
        self,
        request: ContainmentRequest,
        *,
        requirements: Sequence[ProofRequirement],
    ) -> PositiveProof:
        """Build the execution-bound portion of proof; runtime health must gate its caller."""

        if not self.enforced or self.failure is not None:
            raise ValueError("failed containment cannot mint positive proof")
        if self.request_digest != request.binding_digest:
            raise ValueError("containment request binding changed")
        if self.policy_digest != request.policy.digest:
            raise ValueError("containment policy binding changed")
        if self.launch_digest != request.launch_digest:
            raise ValueError("contained launch identity changed")
        if self.executable_digest != request.executable_digest:
            raise ValueError("contained executable identity changed")
        raw_requirements = cast(object, requirements)
        if not isinstance(raw_requirements, Sequence) or any(
            not isinstance(item, ProofRequirement) for item in raw_requirements
        ):
            raise ValueError("requirements must contain exact ProofRequirement values")
        typed = frozenset(cast(Sequence[ProofRequirement], raw_requirements))
        typed = typed | {ProofRequirement.CONTAINMENT_IDENTITY}
        return PositiveProof(
            route=ProofRoute.CONTAINED,
            binding_digest=_framed_digest(
                {
                    "attestation": self.request_digest,
                    "backend": self.backend.value,
                    "backend_digest": self.backend_digest,
                    "policy": self.policy_digest,
                    "launch": self.launch_digest,
                    "executable": self.executable_digest,
                }
            ),
            satisfied_requirements=typed,
            enforced=True,
        )


def _canonical_directory(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty path")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValueError(f"{name} must be an existing canonical directory")
    canonical = str(path.resolve(strict=True))
    if canonical != os.path.normpath(value):
        raise ValueError(f"{name} must not contain symlink or traversal aliases")
    return canonical


def _canonical_executable(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("executable must be a non-empty path")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("executable must be an existing path-pinned executable")
    canonical = str(path.resolve(strict=True))
    if canonical != os.path.normpath(value):
        raise ValueError("executable must not contain symlink or traversal aliases")
    return canonical


def _canonical_file(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty path")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError(f"{name} must be an existing canonical file")
    canonical = str(path.resolve(strict=True))
    if canonical != os.path.normpath(value):
        raise ValueError(f"{name} must not contain symlink or traversal aliases")
    return canonical


def _canonical_paths(values: object, *, workspace: str) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError("allowed_write_paths must be an immutable tuple")
    result: list[str] = []
    for value in cast(tuple[object, ...], values):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("allowed write paths must be non-empty paths")
        path = Path(value)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("allowed write paths must be absolute and non-symlinked")
        canonical = str(path.resolve(strict=False))
        if canonical != os.path.normpath(value):
            raise ValueError("allowed write paths must not contain aliases")
        _require_within(canonical, workspace, "allowed write path")
        result.append(canonical)
    if len(result) != len(set(result)):
        raise ValueError("allowed write paths cannot contain duplicates")
    return tuple(sorted(result))


def _validated_environment(values: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, tuple):
        raise ValueError("environment must be an immutable tuple")
    result: list[tuple[str, str]] = []
    for item in cast(tuple[object, ...], values):
        if not isinstance(item, tuple):
            raise ValueError("environment entries must be immutable key/value pairs")
        raw_item = cast(tuple[object, ...], item)
        if len(raw_item) != 2:
            raise ValueError("environment entries must be immutable key/value pairs")
        key, value = raw_item
        if not isinstance(key, str) or not isinstance(value, str) or "\x00" in key or "\x00" in value:
            raise ValueError("environment entries must be non-NUL strings")
        if not key or "=" in key or _SECRET_ENV.search(key):
            raise ValueError("contained environment cannot carry secret-bearing keys")
        result.append((key, value))
    if len(result) != len({key for key, _ in result}):
        raise ValueError("contained environment keys cannot repeat")
    return tuple(sorted(result))


def _validated_inputs(values: object, *, workspace: str) -> tuple[ContainmentInput, ...]:
    if not isinstance(values, tuple):
        raise ValueError("inputs must be an immutable tuple")
    typed: list[ContainmentInput] = []
    for value in cast(tuple[object, ...], values):
        if not isinstance(value, ContainmentInput):
            raise ValueError("inputs must contain exact ContainmentInput values")
        _require_within(value.source_path, workspace, "containment input")
        typed.append(value)
    destinations = [item.snapshot_path for item in typed]
    if len(destinations) != len(set(destinations)):
        raise ValueError("containment snapshot paths cannot repeat")
    return tuple(sorted(typed, key=lambda item: item.snapshot_path))


def _is_protected(path: str, *, workspace: str) -> bool:
    relative = Path(path).relative_to(workspace)
    return any(part.lower() in _PROTECTED_PARTS or part.lower().startswith(".env") for part in relative.parts)


def _require_within(path: str, root: str, name: str) -> None:
    try:
        _ = Path(path).relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{name} must remain inside the workspace") from exc


def _path_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _value_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _framed_digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = (
    "CONTAINMENT_POLICY_VERSION",
    "CONTAINMENT_SCHEMA_VERSION",
    "ContainmentAttestation",
    "ContainmentBackend",
    "ContainmentFailure",
    "ContainmentInput",
    "ContainmentPolicy",
    "ContainmentRequest",
)
