"""Real public mutations and bounded physical faults in a disposable daemon."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from scripts.native_slo_contract import MAX_READINESS_P95_MS
from scripts.native_slo_expiry import _authenticated_readback, _readback_matches, expire_acknowledged_authority
from scripts.native_slo_posture_witness import binding_key

_READINESS_SECONDS = MAX_READINESS_P95_MS / 1000


class PostureControls:
    def __init__(self, session: Any) -> None:
        self.session = session
        self.worker = session.daemon._server.hook_worker
        self.publisher = self.worker.policy_snapshot_publisher
        self.known: set[tuple[object, ...]] = set()
        self.strict_workspace = session.root / "posture-strict-workspace"
        self.mode = "enforce"
        self.progress: dict[str, object] = {}

    def workspace(self, scope: str) -> Path:
        if scope not in {"initial", "strict"}:
            raise ValueError("posture workspace scope invalid")
        return self.strict_workspace if scope == "strict" else self.session.workspace

    def ack(self, *, previous: int = 0, strict: bool = False) -> Mapping[str, Any]:
        """One unchanged 400 ms barrier, then independent authenticated readback."""
        deadline = time.monotonic() + _READINESS_SECONDS
        while True:
            prepared = self.worker.prepare_workspace_policy(
                self.workspace("strict" if strict else "initial"), deadline=deadline
            )
            snapshot = self.publisher.current_snapshot()
            if isinstance(prepared, Mapping) and isinstance(snapshot, Mapping):
                binding, accepted = _authenticated_readback(self.session.store)
                effective = snapshot.get("effective_policy")
                generation = snapshot.get("generation")
                if (
                    _readback_matches(binding, accepted, snapshot)
                    and binding_key(prepared) == binding_key(snapshot)
                    and snapshot.get("mode") == self.mode
                    and type(generation) is int
                    and generation > previous
                    and (
                        not strict or (isinstance(effective, Mapping) and effective.get("sandbox_analysis") == "strict")
                    )
                    and time.monotonic() <= deadline
                ):
                    self.known.add(binding_key(snapshot))
                    return snapshot
            if time.monotonic() >= deadline:
                raise RuntimeError("posture authenticated acknowledgment deadline")
            time.sleep(0.005)

    def _mode_mutation(self, mode: str) -> None:
        from codex_plugin_scanner.guard.config import update_guard_settings

        if mode not in {"enforce", "observe"}:
            raise ValueError("posture mode invalid")
        self.progress["public_mutation_attempted"] = True
        update_guard_settings(
            self.session.guard_home, {"protection_posture": "watch" if mode == "observe" else "protected"}
        )
        self.progress["public_mutation_returned"] = True
        self.mode = mode

    def apply(
        self,
        operation: str,
        before: Mapping[str, Any],
        probe: Callable[[str, str | tuple[object, ...]], None],
    ) -> Mapping[str, Any] | None:
        self.progress = {"operation": operation, "deadline_ms": MAX_READINESS_P95_MS}
        if operation in {"enforce_to_watch", "watch_to_enforce"}:
            if before.get("mode") != ("enforce" if operation == "enforce_to_watch" else "observe"):
                raise RuntimeError("posture transition starting mode mismatch")
            self._mode_mutation("observe" if operation == "enforce_to_watch" else "enforce")
            return self.ack(previous=int(before["generation"]))
        if operation == "watch_restart":
            if self.mode != "observe":
                raise RuntimeError("posture Watch restart requires acknowledged Watch")
            self.progress.update(contained=self.session.stop_resident(), python_process_restarted=False)
            if self.progress["contained"] is not True:
                raise RuntimeError("posture resident containment failed")
            # A resident restart can retain the authenticated generation. Do
            # not demand a fabricated new policy generation for unchanged inputs.
            return self.ack()
        if operation == "first_strict_workspace":
            return self._first_workspace(before, probe)
        if operation == "failed_publication":
            return self._failed_publication(before, probe)
        if operation == "expiry":
            self.progress.update(expire_acknowledged_authority(self.session))
            if not all(
                self.progress.get(key) is True
                for key in (
                    "expired_resident_authority",
                    "short_lived_acknowledged",
                    "starting_authority_authenticated",
                    "authenticated_readback",
                    "policy_preserved",
                    "control_binding_preserved",
                    "policy_prepare_rejected",
                    "refresh_suspended",
                )
            ):
                raise RuntimeError("posture expiry fault proof incomplete")
            probe("initial", "unavailable")
            return None
        raise ValueError("unsupported posture transition")

    def _first_workspace(
        self, before: Mapping[str, Any], probe: Callable[[str, str | tuple[object, ...]], None]
    ) -> Mapping[str, Any]:
        from codex_plugin_scanner.guard.native_policy_snapshot_storage import _v3_generation_lock

        self.strict_workspace.mkdir(mode=0o700)
        config = self.strict_workspace / ".hol-guard.toml"
        with config.open("x", encoding="utf-8") as stream:
            config.chmod(0o600)
            # Workspace mode/posture overrides are deliberately unsupported.
            # Exercise a real permitted stricter overlay and ignored weakening.
            stream.write('sandbox_analysis = "strict"\nmode = "observe"\nprotection_posture = "watch"\n')
        self.progress["workspace_file_created"] = True
        resolved = self.publisher._resolved_workspace(self.strict_workspace)
        with self.publisher._condition:
            first = resolved not in self.publisher._workspace_paths
        self.progress["previously_unregistered"] = first
        if not first:
            raise RuntimeError("posture first workspace already registered")
        # Hold the real publication lock; do not replace readiness, ACK bytes,
        # the generation state, native evaluation, or its clock.
        with _v3_generation_lock(self.session.guard_home, deadline_monotonic=time.monotonic() + _READINESS_SECONDS):
            probe("strict", "unavailable")
            self.progress["first_use_delivered_unavailable"] = True
            self.progress["first_use_withdrew_ack"] = self.publisher.current_snapshot_binding() is None
            probe("initial", "unavailable")
            if self.progress["first_use_withdrew_ack"] is not True:
                raise RuntimeError("posture first workspace reused prior authority")
        result = self.ack(previous=int(before["generation"]), strict=True)
        self.progress["stricter_digest_changed"] = result["policy_digest"] != before["policy_digest"]
        self.progress["workspace_could_not_weaken_mode"] = result["mode"] == "enforce"
        if not all(
            self.progress[key] is True for key in ("stricter_digest_changed", "workspace_could_not_weaken_mode")
        ):
            raise RuntimeError("posture workspace overlay did not publish a stricter binding")
        return result

    def _failed_publication(
        self, before: Mapping[str, Any], probe: Callable[[str, str | tuple[object, ...]], None]
    ) -> Mapping[str, Any]:
        from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
        from codex_plugin_scanner.guard.native_policy_snapshot_storage import _v3_generation_lock

        with _v3_generation_lock(self.session.guard_home, deadline_monotonic=time.monotonic() + _READINESS_SECONDS):
            self.progress["publication_lock_held"] = True
            self._mode_mutation("observe")
            self.progress["mutation_withdrew_ack"] = self.publisher.current_snapshot_binding() is None
            # Observation can wait for the existing platform publication budget;
            # no production deadline, retry schedule, or result is changed.
            deadline = time.monotonic() + _PUBLISH_TIMEOUT_SECONDS + _READINESS_SECONDS
            while self.publisher.last_error != "native_policy_snapshot_generation_lock_timeout":
                if time.monotonic() >= deadline:
                    raise RuntimeError("posture actual publication lock failure not observed")
                time.sleep(0.01)
            self.progress["publication_failed_at_generation_lock"] = True
            self.progress["failed_publication_withheld_ack"] = self.publisher.current_snapshot_binding() is None
            probe("initial", "unavailable")
            if not all(
                self.progress[key] is True for key in ("mutation_withdrew_ack", "failed_publication_withheld_ack")
            ):
                raise RuntimeError("posture failed publication retained readiness")
        self.progress["publication_lock_released"] = True
        return self.ack(previous=int(before["generation"]))
