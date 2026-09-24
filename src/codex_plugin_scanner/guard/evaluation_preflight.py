"""Non-destructive preflight and setup for bounded local evaluations.

This module only checks the declared evaluation environment and allocates an
owned temporary Guard home/workspace.  It does not execute evaluation cases,
read user configuration or credentials, install hooks, or change policy.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal, cast

from .evaluation_contracts import (
    EvaluationContractError,
    EvaluationProfile,
    validate_evaluation_profile,
)

EvaluationSetupStatus = Literal["passed", "blocked_environment", "not_run"]
EvaluationPhase = Literal["preflight", "setup"]
EVALUATION_SETUP_SCHEMA_VERSION = "guard.evaluation-setup.v1"

_OWNED_ROOT_PREFIX = "hol-guard-eval-"
_MARKER_NAME = ".hol-guard-evaluation-owned"
_VERSION_TIMEOUT_SECONDS = 2.0


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
        return _remove_owned_root(self.root_path, self.marker_token)


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


def _safe_temp_parent(path: Path) -> bool:
    """Require a private owned directory below the process temporary root."""

    try:
        if "\x00" in str(path) or path.is_symlink() or not path.is_dir():
            return False
        candidate = os.path.realpath(os.fspath(path))
    except (OSError, RuntimeError):
        return False

    if os.name == "nt":
        if candidate.startswith("\\\\"):
            return False
        temp_root = os.path.normcase(os.path.normpath(os.path.realpath(tempfile.gettempdir())))
        candidate_normalized = os.path.normcase(os.path.normpath(candidate))
        try:
            return (
                candidate_normalized != temp_root and os.path.commonpath((candidate_normalized, temp_root)) == temp_root
            )
        except ValueError:
            return False

    root = os.path.realpath(tempfile.gettempdir())
    try:
        if os.path.commonpath((candidate, root)) != root or candidate == root:
            return False
        details = path.stat()
        return details.st_uid == os.getuid() and stat.S_IMODE(details.st_mode) & 0o077 == 0
    except (OSError, ValueError):
        return False


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


def _isolated_version_environment(probe_root: Path) -> dict[str, str]:
    """Build a minimal environment with all user-state locations redirected."""

    state_root = probe_root / "state"
    state_root.mkdir(mode=0o700)
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(state_root),
        "USERPROFILE": str(state_root),
        "XDG_CONFIG_HOME": str(state_root / "config"),
        "XDG_DATA_HOME": str(state_root / "data"),
        "XDG_STATE_HOME": str(state_root / "state"),
        "XDG_CACHE_HOME": str(state_root / "cache"),
        "TMPDIR": str(state_root / "tmp"),
        "TMP": str(state_root / "tmp"),
        "TEMP": str(state_root / "tmp"),
        "PYTHONNOUSERSITE": "1",
        "LC_ALL": "C",
        "LANG": "C",
    }
    for directory in ("config", "data", "state", "cache", "tmp"):
        (state_root / directory).mkdir(mode=0o700)
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR", "PATHEXT"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
    return environment


def _version_matches(output: str, expected_version: str) -> bool:
    core = (
        expected_version[1:]
        if expected_version[:1] in {"v", "V"} and expected_version[1:2].isdigit()
        else expected_version
    )
    prefix = "[vV]?" if core[0].isdigit() else ""
    pattern = rf"(?<![A-Za-z0-9_.-]){prefix}{re.escape(core)}(?![A-Za-z0-9_.-])"
    return re.search(pattern, output) is not None


def _check_host_version(executable: Path, expected_version: str) -> tuple[bool, str]:
    probe_root = Path(tempfile.mkdtemp(prefix="hol-guard-preflight-"))
    try:
        probe_root.chmod(0o700)
        environment = _isolated_version_environment(probe_root)
        try:
            completed = subprocess.run(
                [os.fspath(executable), "--version"],
                cwd=probe_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=_VERSION_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return False, "host_version_timeout"
        except (OSError, UnicodeError):
            return False, "host_version_unavailable"
        if completed.returncode != 0:
            return False, "host_version_unavailable"
        if not _version_matches(f"{completed.stdout}\n{completed.stderr}", expected_version):
            return False, "host_version_mismatch"
        return True, ""
    except (OSError, RuntimeError):
        return False, "host_version_unavailable"
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)


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
) -> EvaluationPreflightReport:
    """Validate a profile and its declared local prerequisites.

    A successful result means only that setup may be allocated. It does not
    run an evaluation scenario or establish a capability verdict. Version
    probing executes the supplied host binary and must be explicitly enabled
    inside an isolated evaluation VM; the redirected environment is not a
    filesystem or network sandbox.
    """

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
    version_ok, version_reason = _check_host_version(executable, version)
    if not version_ok:
        checks.append(_check("host_version", "blocked_environment", reason=version_reason))
        return _report("blocked_environment", "preflight", profile_id, checks, reason=version_reason)
    checks.append(_check("host_version", "passed"))

    artifact_results, artifact_status, artifact_reason = _artifact_checks(payload, artifact_paths)
    checks.extend(artifact_results)
    if artifact_status != "passed":
        return _report(artifact_status, "preflight", profile_id, checks, reason=artifact_reason)
    return _report("passed", "preflight", profile_id, checks)


def _remove_owned_root(root_path: Path, marker_token: str) -> bool:
    try:
        if root_path.name.startswith(_OWNED_ROOT_PREFIX) is False:
            raise EvaluationContractError("evaluation setup path has an invalid ownership name")
        if not _safe_temp_parent(root_path.parent):
            raise EvaluationContractError("evaluation setup path is outside a temporary root")
        if root_path.is_symlink():
            raise EvaluationContractError("evaluation setup path must not be a symlink")
        if not root_path.exists():
            return False
        marker = root_path / _MARKER_NAME
        if not marker.is_file() or marker.is_symlink():
            raise EvaluationContractError("evaluation setup ownership marker is missing")
        if marker.read_text(encoding="utf-8") != marker_token:
            raise EvaluationContractError("evaluation setup ownership marker does not match")
        if hasattr(os, "getuid") and root_path.stat().st_uid != os.getuid():
            raise EvaluationContractError("evaluation setup is owned by another user")
        shutil.rmtree(root_path)
        return True
    except (OSError, UnicodeError) as exc:
        raise EvaluationContractError("unable to clean up evaluation setup") from exc


def setup_evaluation(
    profile: EvaluationProfile | Mapping[str, object],
    *,
    host_executable: str | Path | None = None,
    artifact_paths: Mapping[str, str | Path] | None = None,
    parent_dir: str | Path | None = None,
    allow_host_execution: bool = False,
) -> EvaluationSetup:
    """Preflight and allocate a fresh private temporary evaluation setup."""

    preflight = preflight_evaluation(
        profile,
        host_executable=host_executable,
        artifact_paths=artifact_paths,
        allow_host_execution=allow_host_execution,
    )
    if preflight.status != "passed":
        return EvaluationSetup(report=replace(preflight, phase="setup"))

    try:
        payload = _profile_payload(profile)
        target_scope = cast(Mapping[str, object], payload["targetScope"])
        declared_root = Path(cast(str, target_scope["rootPath"]))
    except EvaluationContractError:
        return EvaluationSetup(report=replace(preflight, phase="setup", status="not_run", reason="invalid_profile"))
    try:
        base = Path(parent_dir) if parent_dir is not None else declared_root
        parent_matches = base.resolve() == declared_root.resolve()
    except (OSError, RuntimeError, ValueError, TypeError):
        parent_matches = False
        base = declared_root
    if not parent_matches or not _safe_temp_parent(base):
        report = replace(
            preflight,
            phase="setup",
            status="blocked_environment",
            reason="setup_parent_outside_profile_scope",
            checks=(
                *preflight.checks,
                _check("setup_parent", "blocked_environment", reason="setup_parent_outside_profile_scope"),
            ),
        )
        return EvaluationSetup(report=report)

    root_path: Path | None = None
    marker_token = secrets.token_hex(16)
    try:
        root_path = Path(tempfile.mkdtemp(prefix=_OWNED_ROOT_PREFIX, dir=base))
        _ = root_path.chmod(0o700)
        marker = root_path / _MARKER_NAME
        _ = marker.write_text(marker_token, encoding="utf-8")
        _ = marker.chmod(0o600)
        guard_home = root_path / "guard-home"
        workspace = root_path / "workspace"
        guard_home.mkdir(mode=0o700)
        workspace.mkdir(mode=0o700)
        report = replace(
            preflight,
            phase="setup",
            guard_home=str(guard_home),
            workspace=str(workspace),
            owned_root=str(root_path),
            checks=(*preflight.checks, _check("setup", "passed")),
        )
        return EvaluationSetup(report=report, root_path=root_path, marker_token=marker_token)
    except (OSError, RuntimeError) as exc:
        if root_path is not None and root_path.exists():
            with contextlib.suppress(EvaluationContractError):
                _ = _remove_owned_root(root_path, marker_token)
        report = replace(
            preflight,
            phase="setup",
            status="blocked_environment",
            reason="setup_unavailable",
            checks=(*preflight.checks, _check("setup", "blocked_environment", reason="setup_unavailable")),
        )
        del exc
        return EvaluationSetup(report=report)


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
    return _remove_owned_root(candidate, marker_token)


__all__ = [
    "EVALUATION_SETUP_SCHEMA_VERSION",
    "EvaluationPreflightReport",
    "EvaluationSetup",
    "cleanup_interrupted_evaluation_setup",
    "preflight_evaluation",
    "setup_evaluation",
]
