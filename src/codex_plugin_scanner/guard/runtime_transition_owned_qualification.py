"""Qualify an owned predecessor through its actual configured native hook.

This reads existing authority; it does not repair bindings, select a runtime,
authorize a transition, stop processes or produce a serialized admission grant.
"""

from __future__ import annotations

import math
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .adapters.base import HarnessContext
from .codex_install_transaction import codex_install_transaction
from .daemon.live_identity import DaemonArtifactBinding
from .daemon.start_lock import guard_daemon_start_lock
from .runtime_transition import TransitionError
from .runtime_transition_admission import NativeProtectionAdmission, verified_admission_payload
from .runtime_transition_codex_observer import observe_configured_codex_hook
from .runtime_transition_native_capture import (
    NativeCaptureError,
    OwnedNativeCandidate,
    capture_owned_native_candidate,
)

if TYPE_CHECKING:
    from .store import GuardStore


@dataclass(frozen=True)
class OwnedNativeQualification:
    candidate: OwnedNativeCandidate
    admission: NativeProtectionAdmission


def qualify_owned_codex_native(
    *,
    operation_id: str,
    artifact_generation: str,
    expected_artifact: DaemonArtifactBinding,
    context: HarnessContext,
    store: GuardStore,
    deadline_monotonic: float,
) -> OwnedNativeQualification:
    """Pin ownership around fresh allow/deny receipts under one parent deadline."""
    deadline = deadline_monotonic

    def check() -> None:
        if isinstance(deadline, bool) or not math.isfinite(deadline) or not 0 < deadline - time.monotonic() <= 60:
            raise TransitionError("owned_qualification_deadline")

    check()
    try:
        if str(uuid.UUID(operation_id)) != operation_id:
            raise ValueError
    except (ValueError, AttributeError, TypeError):
        raise TransitionError("operation_id_invalid") from None
    if len(artifact_generation) != 64 or any(value not in "0123456789abcdef" for value in artifact_generation):
        raise TransitionError("artifact_generation_invalid")
    home = context.guard_home.resolve(strict=True)
    if Path(store.guard_home).resolve(strict=True) != home:
        raise TransitionError("owned_qualification_store_mismatch")
    check()
    # Same lock order as activation/recovery. No start/stop/publication follows.
    with (
        codex_install_transaction(
            home, home / "owned-native-qualification", actor="desktop-native-qualification", deadline=deadline
        ),
        guard_daemon_start_lock(home, deadline=deadline),
    ):
        rows = deepcopy(store.list_managed_installs())
        check()
        active = [row for row in rows if row.get("active") is True]
        if len(active) != 1 or active[0].get("harness") != "codex":
            raise TransitionError("installed_hook_observer_unavailable")
        row = active[0]
        manifest = row.get("manifest")
        config = (
            cast(dict[str, object], manifest).get("managed_hook_config_path") if isinstance(manifest, dict) else None
        )
        workspace = row.get("workspace")
        if not isinstance(config, str) or not Path(config).is_absolute():
            raise TransitionError("installed_hook_binding_missing")
        if workspace is not None and (not isinstance(workspace, str) or not Path(workspace).is_absolute()):
            raise TransitionError("managed_install_snapshot_invalid")
        try:
            before = capture_owned_native_candidate(home, expected_artifact, deadline_monotonic=deadline)
            proof = observe_configured_codex_hook(
                operation_id=operation_id,
                artifact_generation=artifact_generation,
                expected_runtime=before.identity,
                guard_home=home,
                config_path=Path(config),
                workspace=Path(workspace) if isinstance(workspace, str) else context.home_dir,
                deadline_monotonic=deadline,
                artifact_binding=expected_artifact,
                receipt_store=store,
            )
            payload = verified_admission_payload(proof)
            evidence = payload.get("installed_hook_evidence")
            if (
                proof.operation_id != operation_id
                or proof.artifact_generation != artifact_generation
                or proof.runtime_identity != before.identity
                or proof.guard_home != home
                or not isinstance(evidence, dict)
                or cast(dict[str, object], evidence).get("harness") != "codex"
            ):
                raise TransitionError("owned_qualification_proof_mismatch")
            check()
            after = capture_owned_native_candidate(home, expected_artifact, deadline_monotonic=deadline)
        except NativeCaptureError as error:
            raise TransitionError(str(error)) from error
        if before.identity != after.identity or before.daemon != after.daemon or store.list_managed_installs() != rows:
            raise TransitionError("owned_qualification_generation_changed")
        check()
        return OwnedNativeQualification(after, proof)
