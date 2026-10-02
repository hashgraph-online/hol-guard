"""Non-destructive preflight and setup for bounded local evaluations.

This module only checks the declared evaluation environment and allocates an
owned temporary Guard home/workspace.  It does not execute evaluation cases,
read user configuration or credentials, install hooks, or change policy.
"""

from __future__ import annotations

import copy
import hashlib
import os
import platform
import re
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from . import evaluation_cleanup as _cleanup
from .evaluation_contracts import EvaluationContractError, EvaluationProfile, validate_evaluation_profile
from .evaluation_host_probe import check_host_version
from .evaluation_scope import _safe_temp_parent

EvaluationSetupStatus = Literal["passed", "blocked_environment", "not_run"]
EvaluationPhase = Literal["preflight", "setup"]
EvaluationExecutionMode = Literal["installed", "synthetic_adapter"]
EVALUATION_SETUP_SCHEMA_VERSION = "guard.evaluation-setup.v1"

_DESCRIPTOR_CLEANUP_UNAVAILABLE_REASON = "descriptor_cleanup_unavailable"


def _check(
    name: str,
    status: EvaluationSetupStatus,
    *,
    reason: str | None = None,
    expected: str | None = None,
    observed: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {"name": name, "status": status}
    if reason is not None:
        result["reason"] = reason
    if expected is not None:
        result["expected"] = expected
    if observed is not None:
        result["observed"] = observed
    return result


@dataclass(frozen=True, slots=True)
class EvaluationPreflightReport:
    """Machine-readable outcome for one preflight or setup phase."""

    status: EvaluationSetupStatus
    phase: EvaluationPhase
    profile_id: str | None
    checks: tuple[dict[str, object], ...]
    reason: str | None = None
    guard_home: str | None = None
    workspace: str | None = None
    owned_root: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible report without internal objects."""

        return {
            "schemaVersion": EVALUATION_SETUP_SCHEMA_VERSION,
            "phase": self.phase,
            "status": self.status,
            "profileId": self.profile_id,
            "checks": [copy.deepcopy(check) for check in self.checks],
            "reason": self.reason,
            "scope": {
                "guardHome": self.guard_home,
                "workspace": self.workspace,
                "ownedRoot": self.owned_root,
            },
        }


@dataclass(frozen=True, slots=True)
class EvaluationSetup:
    """An owned temporary setup, or a machine-readable blocked/not-run result."""

    report: EvaluationPreflightReport
    root_path: Path | None = None
    marker_token: str | None = None
    root_identity: tuple[int, int] | None = None
    workspace_identity: tuple[int, int] | None = None

    @property
    def guard_home(self) -> Path | None:
        return self.root_path / "guard-home" if self.root_path is not None else None

    @property
    def workspace(self) -> Path | None:
        return self.root_path / "workspace" if self.root_path is not None else None

    def to_dict(self) -> dict[str, object]:
        """Return the setup report without exposing the ownership token."""

        return self.report.to_dict()

    def cleanup(self) -> bool:
        """Remove this setup only after checking its temporary ownership marker.

        The method never follows a caller-provided profile path.  A mismatch
        raises ``EvaluationContractError`` so a foreign directory cannot be
        removed accidentally.
        """

        if self.root_path is None or self.marker_token is None:
            return False
        return _cleanup.remove_owned_root(
            self.root_path,
            self.marker_token,
            expected_root_identity=self.root_identity,
        )


def _profile_payload(profile: object) -> dict[str, object]:
    if isinstance(profile, EvaluationProfile):
        payload = profile.to_dict()
    elif isinstance(profile, Mapping):
        mapping = cast(Mapping[str, object], profile)
        payload = copy.deepcopy(dict(mapping))
    else:
        raise EvaluationContractError("evaluation profile must be an object")
    validate_evaluation_profile(payload)
    return payload


def _profile_id(payload: object) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    value = cast(Mapping[str, object], payload).get("profileId")
    return value if isinstance(value, str) else None


def _report(
    status: EvaluationSetupStatus,
    phase: EvaluationPhase,
    profile_id: str | None,
    checks: list[dict[str, object]],
    *,
    reason: str | None = None,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    owned_root: Path | None = None,
) -> EvaluationPreflightReport:
    return EvaluationPreflightReport(
        status=status,
        phase=phase,
        profile_id=profile_id,
        checks=tuple(copy.deepcopy(checks)),
        reason=reason,
        guard_home=str(guard_home) if guard_home is not None else None,
        workspace=str(workspace) if workspace is not None else None,
        owned_root=str(owned_root) if owned_root is not None else None,
    )


def _normalize_os(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    return {
        "darwin": "macos",
        "mac": "macos",
        "mac-os": "macos",
        "win32": "windows",
        "win": "windows",
    }.get(normalized, normalized)


def _normalize_architecture(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    return {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(normalized, normalized)


def _observed_privilege() -> str:
    if os.name == "nt":
        try:
            import ctypes

            return "administrator" if ctypes.windll.shell32.IsUserAnAdmin() else "standard_user"
        except (AttributeError, OSError):
            return "unknown"
    if hasattr(os, "geteuid"):
        return "administrator" if os.geteuid() == 0 else "standard_user"
    return "unknown"


def _resolve_host_executable(value: str) -> Path | None:
    if not value or value != value.strip() or "\x00" in value:
        return None
    if os.path.isabs(value):
        candidate = Path(value)
    else:
        found = shutil.which(value, path=os.environ.get("PATH", os.defpath))
        candidate = Path(found) if found is not None else None
    if candidate is None:
        return None
    try:
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            return None
        return candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _artifact_checks(
    payload: Mapping[str, object],
    artifact_paths: Mapping[str, str | Path] | None,
) -> tuple[list[dict[str, object]], EvaluationSetupStatus, str | None]:
    artifacts = cast(list[object], payload["installedArtifacts"])
    if artifact_paths is None:
        checks = [
            _check(
                "artifact:" + str(cast(Mapping[str, object], artifact)["artifactId"]),
                "not_run",
                reason="artifact_paths_not_supplied",
            )
            for artifact in artifacts
        ]
        return checks, "not_run", "artifact_paths_not_supplied"

    checks: list[dict[str, object]] = []
    for raw_artifact in artifacts:
        artifact = cast(Mapping[str, object], raw_artifact)
        artifact_id = str(artifact["artifactId"])
        raw_path = artifact_paths.get(artifact_id)
        if raw_path is None:
            checks.append(_check("artifact:" + artifact_id, "blocked_environment", reason="artifact_missing"))
            return checks, "blocked_environment", "artifact_missing"
        path = Path(raw_path)
        try:
            present = path.is_absolute() and path.is_file() and stat.S_ISREG(path.stat().st_mode)
        except (OSError, RuntimeError):
            present = False
        if not present:
            checks.append(_check("artifact:" + artifact_id, "blocked_environment", reason="artifact_missing"))
            return checks, "blocked_environment", "artifact_missing"
        try:
            digest = hashlib.sha256()
            with path.open("rb") as artifact_file:
                for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            checks.append(_check("artifact:" + artifact_id, "blocked_environment", reason="artifact_unreadable"))
            return checks, "blocked_environment", "artifact_unreadable"
        if "sha256:" + digest.hexdigest() != artifact["digest"]:
            checks.append(_check("artifact:" + artifact_id, "blocked_environment", reason="artifact_digest_mismatch"))
            return checks, "blocked_environment", "artifact_digest_mismatch"
        checks.append(_check("artifact:" + artifact_id, "passed"))
    return checks, "passed", None


def preflight_evaluation(
    profile: EvaluationProfile | Mapping[str, object],
    *,
    host_executable: str | Path | None = None,
    artifact_paths: Mapping[str, str | Path] | None = None,
    allow_host_execution: bool = False,
    execution_mode: EvaluationExecutionMode = "installed",
) -> EvaluationPreflightReport:
    """Validate a profile and its declared local prerequisites.

    A successful result means only that setup may be allocated. It does not
    run an evaluation scenario or establish a capability verdict. Version
    probing executes the supplied host binary and must be explicitly enabled
    inside an isolated evaluation VM; the redirected environment is not a
    filesystem or network sandbox.
    """

    if execution_mode not in ("installed", "synthetic_adapter"):
        return _report(
            "not_run",
            "preflight",
            _profile_id(profile),
            [_check("execution_mode", "not_run", reason="execution_mode_invalid")],
            reason="execution_mode_invalid",
        )

    profile_id = _profile_id(profile)
    try:
        payload = _profile_payload(profile)
    except EvaluationContractError:
        return _report(
            "not_run",
            "preflight",
            profile_id,
            [_check("profile", "not_run", reason="invalid_profile")],
            reason="invalid_profile",
        )

    profile_id = cast(str, payload["profileId"])
    checks: list[dict[str, object]] = [_check("profile", "passed")]
    host = cast(Mapping[str, object], payload["hostIdentity"])
    runtime_location = str(host["runtimeLocation"])
    if runtime_location != "local":
        checks.append(_check("runtime_location", "blocked_environment", reason="hosted_runtime_unsupported"))
        return _report("blocked_environment", "preflight", profile_id, checks, reason="hosted_runtime_unsupported")
    checks.append(_check("runtime_location", "passed"))

    expected_os = _normalize_os(str(host["os"]))
    observed_os = _normalize_os(platform.system())
    if expected_os != observed_os:
        checks.append(
            _check("os", "blocked_environment", reason="os_mismatch", expected=expected_os, observed=observed_os)
        )
        return _report("blocked_environment", "preflight", profile_id, checks, reason="os_mismatch")
    checks.append(_check("os", "passed", expected=expected_os, observed=observed_os))

    expected_architecture = _normalize_architecture(str(host["architecture"]))
    observed_architecture = _normalize_architecture(platform.machine())
    if expected_architecture != observed_architecture:
        checks.append(
            _check(
                "architecture",
                "blocked_environment",
                reason="architecture_mismatch",
                expected=expected_architecture,
                observed=observed_architecture,
            )
        )
        return _report("blocked_environment", "preflight", profile_id, checks, reason="architecture_mismatch")
    checks.append(
        _check(
            "architecture",
            "passed",
            expected=expected_architecture,
            observed=observed_architecture,
        )
    )

    expected_privilege = str(host["requiredPrivilege"])
    observed_privilege = _observed_privilege()
    if observed_privilege == "unknown":
        checks.append(_check("privilege", "not_run", reason="privilege_unobservable", expected=expected_privilege))
        return _report("not_run", "preflight", profile_id, checks, reason="privilege_unobservable")
    if expected_privilege != observed_privilege:
        checks.append(
            _check(
                "privilege",
                "blocked_environment",
                reason="privilege_mismatch",
                expected=expected_privilege,
                observed=observed_privilege,
            )
        )
        return _report("blocked_environment", "preflight", profile_id, checks, reason="privilege_mismatch")
    checks.append(_check("privilege", "passed", expected=expected_privilege, observed=observed_privilege))

    network = cast(Mapping[str, object], payload["network"])
    endpoint_count = len(cast(list[object], network["allowedEndpoints"]))
    checks.append(
        _check(
            "network_scope_declaration",
            "passed",
            expected=f"{network['mode']}; {endpoint_count} declared loopback endpoints",
            observed="scope validated; receiver connectivity requires a separate witness",
        )
    )

    if execution_mode == "synthetic_adapter":
        checks.append(_check("host_executable", "not_run", reason="synthetic_adapter_mode"))
        checks.append(_check("host_version", "not_run", reason="synthetic_adapter_mode"))
    else:
        declared_executable = host_executable
        if declared_executable is None:
            declared_executable = cast(str | None, host.get("executable"))
        if declared_executable is None or not str(declared_executable):
            checks.append(_check("host_executable", "not_run", reason="host_executable_not_declared"))
            return _report("not_run", "preflight", profile_id, checks, reason="host_executable_not_declared")
        executable = _resolve_host_executable(os.fspath(declared_executable))
        if executable is None:
            checks.append(_check("host_executable", "blocked_environment", reason="host_executable_missing"))
            return _report("blocked_environment", "preflight", profile_id, checks, reason="host_executable_missing")
        checks.append(_check("host_executable", "passed"))
        if not allow_host_execution:
            checks.append(_check("host_version", "not_run", reason="isolated_host_execution_not_enabled"))
            return _report("not_run", "preflight", profile_id, checks, reason="isolated_host_execution_not_enabled")

        version = str(host["version"])
        limits = cast(Mapping[str, object], payload["resourceLimits"])
        version_ok, version_reason = check_host_version(
            executable,
            version,
            timeout_seconds=float(cast(int, limits["maxDurationSeconds"])),
            output_limit_bytes=cast(int, limits["maxOutputBytes"]),
        )
        if not version_ok:
            checks.append(_check("host_version", "blocked_environment", reason=version_reason))
            return _report("blocked_environment", "preflight", profile_id, checks, reason=version_reason)
        checks.append(_check("host_version", "passed"))

    if execution_mode == "synthetic_adapter":
        checks.append(_check("artifacts", "not_run", reason="synthetic_adapter_mode"))
    else:
        artifact_results, artifact_status, artifact_reason = _artifact_checks(payload, artifact_paths)
        checks.extend(artifact_results)
        if artifact_status != "passed":
            return _report(artifact_status, "preflight", profile_id, checks, reason=artifact_reason)
    return _report("passed", "preflight", profile_id, checks)


def setup_evaluation(
    profile: EvaluationProfile | Mapping[str, object],
    *,
    host_executable: str | Path | None = None,
    artifact_paths: Mapping[str, str | Path] | None = None,
    parent_dir: str | Path | None = None,
    allow_host_execution: bool = False,
    execution_mode: EvaluationExecutionMode = "installed",
) -> EvaluationSetup:
    """Preflight and allocate a fresh private temporary evaluation setup."""

    from .evaluation_setup import setup_evaluation as allocate_setup

    return allocate_setup(
        profile,
        host_executable=host_executable,
        artifact_paths=artifact_paths,
        parent_dir=parent_dir,
        allow_host_execution=allow_host_execution,
        execution_mode=execution_mode,
    )


def cleanup_interrupted_evaluation_setup(
    profile: EvaluationProfile | Mapping[str, object],
    *,
    owned_root: str | Path,
    marker_token: str,
) -> bool:
    """Clean up one interrupted setup using its separately retained token.

    The caller must preserve the opaque token outside the owned setup before
    running host cases. This function does not scan for candidate directories,
    infer ownership from a filename, or read arbitrary user configuration.
    """

    payload = _profile_payload(profile)
    scope = cast(Mapping[str, object], payload["targetScope"])
    declared_parent = Path(cast(str, scope["rootPath"]))
    candidate = Path(owned_root)
    if not isinstance(marker_token, str) or re.fullmatch(r"[0-9a-f]{32}", marker_token) is None:
        raise EvaluationContractError("evaluation recovery token is invalid")
    if not candidate.is_absolute() or not _safe_temp_parent(declared_parent):
        raise EvaluationContractError("evaluation recovery path is outside a private temporary root")
    declared_path = os.path.normcase(os.path.realpath(declared_parent))
    candidate_parent = os.path.normcase(os.path.realpath(candidate.parent))
    if candidate_parent != declared_path:
        raise EvaluationContractError("evaluation recovery path is outside the profile target scope")
    if candidate.is_symlink():
        raise EvaluationContractError("evaluation setup path must not be a symlink")
    try:
        candidate_details = candidate.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise EvaluationContractError("unable to inspect evaluation setup path") from exc
    if not stat.S_ISDIR(candidate_details.st_mode):
        raise EvaluationContractError("evaluation setup path is not a directory")
    return _cleanup.remove_owned_root(
        candidate,
        marker_token,
        expected_root_identity=(candidate_details.st_dev, candidate_details.st_ino),
    )


__all__ = [
    "EVALUATION_SETUP_SCHEMA_VERSION",
    "EvaluationExecutionMode",
    "EvaluationPreflightReport",
    "EvaluationSetup",
    "cleanup_interrupted_evaluation_setup",
    "preflight_evaluation",
    "setup_evaluation",
]
