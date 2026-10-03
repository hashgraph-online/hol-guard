"""Exact daemon lifecycle driver for a Core-owned runtime transition.

The observer must exercise protected hooks; this driver never substitutes
daemon liveness for functional protection admission.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from .codex_hook_integrity import canonical_manifest_bytes
from .daemon import manager
from .daemon.discovery import load_authenticated_daemon_state
from .daemon.live_identity import DaemonArtifactBinding, verified_live_guard_daemon_identity
from .daemon.start_lock import guard_daemon_start_lock
from .live_process_identity import process_start_token
from .runtime_transition import RuntimeTransition, TransitionError, TransitionPlan
from .runtime_transition_admission import NativeProtectionAdmission, verified_admission_payload


class TransitionHookObserver(Protocol):
    def __call__(
        self,
        artifact: Mapping[str, object],
        daemon_identity: Mapping[str, object],
        operation_id: str,
        *,
        deadline_monotonic: float,
    ) -> NativeProtectionAdmission: ...


class TransitionDaemonDriver:
    def __init__(
        self,
        runtime: RuntimeTransition,
        plan: TransitionPlan,
        *,
        home_dir: Path,
        observe_hook: TransitionHookObserver,
    ):
        payload = plan.payload()
        self.runtime: RuntimeTransition = runtime
        self.home_dir: Path = home_dir
        self.operation_id: str = plan.operation_id
        self.subject: str = hashlib.sha256(canonical_manifest_bytes(payload)).hexdigest()
        self.artifacts: dict[str, dict[str, object]] = {
            side: cast(dict[str, object], payload[side]) for side in ("candidate", "predecessor")
        }
        self.bindings: dict[str, DaemonArtifactBinding] = {
            side: DaemonArtifactBinding.from_transition_plan(plan, side) for side in self.artifacts
        }
        # Refuse mutable plan changes between capture and dependency extraction.
        files = cast(list[dict[str, object]], payload["files"])
        for side, binding in self.bindings.items():
            if (
                str(binding.executable) != self.artifacts[side]["path"]
                or binding.package_version != self.artifacts[side]["version"]
                or not any(
                    change["path"] == str(binding.executable)
                    and change.get("expected_digest") == binding.executable_sha256
                    for change in files
                )
            ):
                raise TransitionError("plan_context_mismatch")
        if payload["guard_home"] != str(runtime.home):
            raise TransitionError("plan_context_mismatch")
        self.observe_hook: TransitionHookObserver = observe_hook

    def _admit(self, artifact: Mapping[str, object], action: str, deadline: float) -> str:
        if time.monotonic() >= deadline:
            raise TransitionError("deadline_exceeded")
        sides = [side for side, expected in self.artifacts.items() if artifact == expected]
        if len(sides) != 1:
            raise TransitionError("daemon_artifact_binding_invalid")
        side = sides[0]
        self.runtime.authorize_daemon_step(self.operation_id, subject=self.subject, side=side, action=action)
        if time.monotonic() >= deadline:
            raise TransitionError("deadline_exceeded")
        return side

    def _state(self, side: str, *, allow_retained_predecessor: bool = False) -> dict[str, object] | None:
        if (
            manager.load_authenticated_guard_daemon_pending_launch(self.runtime.home) is not None
            or manager.load_authenticated_guard_daemon_start_progress(self.runtime.home) is not None
        ):
            raise TransitionError("daemon_retirement_incomplete")
        state = load_authenticated_daemon_state(self.runtime.home)
        if state is not None:
            if not self.bindings[side].matches(state) and not (
                allow_retained_predecessor and side == "candidate" and self.bindings["predecessor"].matches(state)
            ):
                raise TransitionError("daemon_generation_changed")
            return state
        path = manager._state_path(self.runtime.home)
        if (path.exists() or path.is_symlink()) and not manager._daemon_lifecycle_artifact_is_exact_tombstone(path):
            raise TransitionError("daemon_identity_unavailable")
        if manager._guard_daemon_start_in_progress(self.runtime.home):
            raise TransitionError("daemon_retirement_incomplete")
        return None

    def stop(self, artifact: Mapping[str, object], *, deadline_monotonic: float) -> None:
        side = self._admit(artifact, "stop", deadline_monotonic)
        with guard_daemon_start_lock(self.runtime.home, deadline=deadline_monotonic):
            _ = self._admit(artifact, "stop", deadline_monotonic)
            state = self._state(side, allow_retained_predecessor=side == "candidate")
            if state is None:
                return
            if side == "candidate" and self.bindings["predecessor"].matches(state):
                # Crash before candidate launch, or retry after inverse launch.
                # Never retire the exact retained predecessor as a candidate.
                if self._live("predecessor", deadline_monotonic) is None:
                    raise TransitionError("daemon_identity_unavailable")
                _ = self._admit(artifact, "stop", deadline_monotonic)
                return
            pid = state.get("pid")
            if type(pid) is not int or pid <= 0:
                raise TransitionError("daemon_identity_unavailable")
            if not manager._guard_daemon_pid_is_proven_dead(pid):
                token = process_start_token(pid, deadline_monotonic=deadline_monotonic)
                if token is None or not manager._retire_guard_daemon_pid(
                    pid,
                    expected_guard_home=self.runtime.home,
                    expected_start_token=token,
                    deadline_monotonic=deadline_monotonic,
                ):
                    raise TransitionError("daemon_retirement_incomplete")
            if not manager._guard_daemon_pid_is_proven_dead(pid):
                raise TransitionError("daemon_retirement_incomplete")
            _ = self._admit(artifact, "stop", deadline_monotonic)
            if not manager._clear_authenticated_guard_daemon_state_if_current(self.runtime.home, expected_state=state):
                raise TransitionError("daemon_generation_changed")

    def start(self, artifact: Mapping[str, object], *, deadline_monotonic: float) -> None:
        side = self._admit(artifact, "start", deadline_monotonic)
        with guard_daemon_start_lock(self.runtime.home, deadline=deadline_monotonic):
            _ = self._admit(artifact, "start", deadline_monotonic)
            state = self._state(side)
            if state is not None:
                if self._live(side, deadline_monotonic) is not None:
                    return
                # Unhealthy authenticated ownership is retained for explicit
                # recovery, never replaced by broad discovery/retirement.
                raise TransitionError("daemon_identity_unavailable")
            try:
                _ = manager.ensure_guard_daemon(
                    self.runtime.home,
                    home_dir=self.home_dir,
                    executable=self.bindings[side].executable,
                    deadline_monotonic=deadline_monotonic,
                    background_maintenance=False,
                )
            except TransitionError:
                raise
            except (OSError, TimeoutError, ValueError, RuntimeError) as error:
                raise TransitionError("daemon_start_failed") from error
            if self._live(side, deadline_monotonic) is None:
                raise TransitionError("daemon_generation_changed")

    def _live(self, side: str, deadline: float) -> dict[str, object] | None:
        if time.monotonic() >= deadline:
            raise TransitionError("deadline_exceeded")
        identity = verified_live_guard_daemon_identity(
            self.runtime.home,
            expected_artifact=self.bindings[side],
            deadline_monotonic=deadline,
        )
        if time.monotonic() >= deadline:
            raise TransitionError("deadline_exceeded")
        return identity

    def observe_protection(
        self,
        artifact: Mapping[str, object],
        operation_id: str,
        *,
        deadline_monotonic: float,
    ) -> NativeProtectionAdmission:
        if operation_id != self.operation_id:
            raise TransitionError("operation_superseded")
        side = self._admit(artifact, "observe", deadline_monotonic)
        with guard_daemon_start_lock(self.runtime.home, deadline=deadline_monotonic):
            _ = self._admit(artifact, "observe", deadline_monotonic)
            identity = self._live(side, deadline_monotonic)
            if identity is None:
                raise TransitionError("daemon_identity_unavailable")
            observation = self.observe_hook(artifact, identity, operation_id, deadline_monotonic=deadline_monotonic)
            evidence = verified_admission_payload(observation).get("installed_hook_evidence")
            if (
                not isinstance(evidence, dict)
                or evidence.get("schema") != "hol-guard.installed-hook-evidence.v1"
                or evidence.get("harness") != "codex"
            ):
                raise TransitionError("installed_hook_proof_missing")
            _ = self._admit(artifact, "observe", deadline_monotonic)
            if self._live(side, deadline_monotonic) != identity:
                raise TransitionError("daemon_generation_changed")
            return observation
