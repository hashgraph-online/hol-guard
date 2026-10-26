"""Private allocation and failure retention for bounded evaluations."""

from __future__ import annotations

import secrets
import tempfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

from . import evaluation_cleanup as _cleanup
from .evaluation_contracts import EvaluationContractError, EvaluationProfile
from .evaluation_preflight import (
    _DESCRIPTOR_CLEANUP_UNAVAILABLE_REASON,
    EvaluationExecutionMode,
    EvaluationSetup,
    _check,
    _profile_payload,
    preflight_evaluation,
)
from .evaluation_scope import _safe_temp_parent


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

    preflight = preflight_evaluation(
        profile,
        host_executable=host_executable,
        artifact_paths=artifact_paths,
        allow_host_execution=allow_host_execution,
        execution_mode=execution_mode,
    )
    if preflight.status != "passed":
        return EvaluationSetup(report=replace(preflight, phase="setup"))
    if not _cleanup.descriptor_cleanup_supported():
        report = replace(
            preflight,
            phase="setup",
            status="blocked_environment",
            reason=_DESCRIPTOR_CLEANUP_UNAVAILABLE_REASON,
            checks=(
                *preflight.checks,
                _check(
                    "setup_cleanup",
                    "blocked_environment",
                    reason=_DESCRIPTOR_CLEANUP_UNAVAILABLE_REASON,
                ),
            ),
        )
        return EvaluationSetup(report=report)

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
    root_identity: tuple[int, int] | None = None
    marker_established = False
    marker_token = secrets.token_hex(16)
    try:
        root_path = Path(tempfile.mkdtemp(prefix=_cleanup.OWNED_ROOT_PREFIX, dir=base))
        root_info = root_path.stat(follow_symlinks=False)
        root_identity = (root_info.st_dev, root_info.st_ino)
        _ = root_path.chmod(0o700)
        marker = root_path / _cleanup.MARKER_NAME
        _ = marker.write_text(marker_token, encoding="utf-8")
        _ = marker.chmod(0o600)
        marker_established = True
        guard_home = root_path / "guard-home"
        workspace = root_path / "workspace"
        guard_home.mkdir(mode=0o700)
        workspace.mkdir(mode=0o700)
        workspace_info = workspace.stat(follow_symlinks=False)
        report = replace(
            preflight,
            phase="setup",
            guard_home=str(guard_home),
            workspace=str(workspace),
            owned_root=str(root_path),
            checks=(*preflight.checks, _check("setup", "passed")),
        )
        return EvaluationSetup(
            report=report,
            root_path=root_path,
            marker_token=marker_token,
            root_identity=(root_info.st_dev, root_info.st_ino),
            workspace_identity=(workspace_info.st_dev, workspace_info.st_ino),
        )
    except (OSError, RuntimeError) as exc:
        retained_root = False
        if root_path is not None and root_path.exists():
            try:
                _ = _cleanup.remove_owned_root(
                    root_path,
                    marker_token,
                    expected_root_identity=root_identity,
                )
            except EvaluationContractError:
                retained_root = True
        reason = "setup_unavailable"
        if retained_root:
            reason = "setup_cleanup_incomplete" if marker_established else "setup_recovery_unavailable"
        report = replace(
            preflight,
            phase="setup",
            status="blocked_environment",
            reason=reason,
            owned_root=str(root_path) if retained_root else None,
            checks=(*preflight.checks, _check("setup", "blocked_environment", reason=reason)),
        )
        del exc
        # Preserve the capability so CLI owners can retain a private recovery
        # token even when allocating the remaining setup directories failed.
        return EvaluationSetup(
            report=report,
            root_path=root_path if retained_root else None,
            marker_token=marker_token if retained_root and marker_established else None,
            root_identity=root_identity if retained_root else None,
        )
