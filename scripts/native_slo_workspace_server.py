"""Workspace scaling controls for one real disposable installed daemon."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping
from typing import Any

from scripts.native_slo_contract import MAX_READINESS_P95_MS
from scripts.native_slo_expiry import _authenticated_readback, _readback_matches
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_request import fixture_request
from scripts.native_slo_mixed_response import delivered_decision
from scripts.native_slo_mixed_witness import ReceiptWitness, writer_drained
from scripts.native_slo_workspace_observer import PAGE_SIZE, PublicationObserver, public_binding

WORKSPACE_COUNTS = (1, 10, 100)
WORKSPACE_PHASES = (
    "initial",
    "unchanged",
    "stricter_overlay",
    "coalesced_burst",
    "public_policy",
    "resident_restart",
)
BURST_WRITES = 32


class WorkspaceScenarioFixture:
    def __init__(self, session: Any, count: int) -> None:
        self._prepare(session.daemon._server.hook_worker.policy_snapshot_publisher, session.workspace, count)
        self.attach(session)

    @classmethod
    def before_start(cls, publisher: Any, workspace: Any, count: int) -> WorkspaceScenarioFixture:
        fixture = cls.__new__(cls)
        fixture._prepare(publisher, workspace, count)
        return fixture

    def _prepare(self, publisher: Any, workspace: Any, count: int) -> None:
        if type(count) is not int or count not in WORKSPACE_COUNTS:
            raise ValueError("workspace count outside declared matrix")
        self.publisher = publisher
        if publisher._thread is not None:
            raise RuntimeError("workspace observer must precede publisher startup")
        initial_cache = getattr(self.publisher, "_compiled_workspace_policies", {})
        if not isinstance(initial_cache, Mapping) or initial_cache:
            raise RuntimeError("workspace initial compilation cache must be empty")
        self.workspaces = (workspace, *(workspace.parent / f"workspace-{index}" for index in range(1, count)))
        self.observer = PublicationObserver(self.publisher, self.workspaces)
        self.witness: ReceiptWitness | None = None
        self.next_phase = 0
        self.failed = False
        self.cache_feature_failed = False
        self.finished = False
        self.phases: list[dict[str, Any]] = []
        self.initial_started = time.monotonic()
        for index, path in enumerate(self.workspaces):
            if index:
                path.mkdir(mode=0o700)
            if path not in self.publisher._workspace_paths and self.publisher.register_workspace(path) is not True:
                raise RuntimeError("workspace registration was not accepted")
        if set(self.workspaces) != self.publisher._workspace_paths:
            raise RuntimeError("workspace registration count mismatch")
        self.registration_ms = (time.monotonic() - self.initial_started) * 1000

    def attach(self, session: Any) -> None:
        from codex_plugin_scanner.guard.native_runtime import native_runtime_status

        self.session = session
        self.worker = session.daemon._server.hook_worker
        status = native_runtime_status()
        if (
            self.worker.policy_snapshot_publisher is not self.publisher
            or self.workspaces[0] != session.workspace
            or self.worker.test_oracle is not None
            or status.mode != "auto"
            or not status.available
            or not status.compatible
            or status.reason != "native_ready"
            or status.identity is None
            or status.identity.path.resolve() != session.runtime.resolve()
        ):
            raise RuntimeError("workspace qualification requires exact installed native authority")
        self.runtime_build_sha = getattr(status.capabilities, "build_sha", None)

    def close(self) -> None:
        if self.witness is not None:
            self.witness.close()

    def startup_failure(self) -> dict[str, object]:
        self.observer.freeze()
        rows = self.observer.rows()
        return {
            "scope": "installed_workspace_startup",
            "passed": False,
            "registered_workspaces": len(self.workspaces),
            "registration_ms": self.registration_ms,
            "observer": self.observer.report(),
            "retained_initial_pages": {
                f"page_{offset // PAGE_SIZE}": rows[offset : offset + PAGE_SIZE]
                for offset in range(0, len(rows), PAGE_SIZE)
            },
            "initial_trace_complete": self.observer.report()["complete"],
            "headline_timing_eligible": False,
        }

    def dispatch(self, operation: str, request: Mapping[str, Any]) -> dict[str, object]:
        try:
            if operation == "workspace_lifecycle" and self.witness is None and not self.finished:
                from scripts.native_slo_workspace_lifecycle import run_lifecycle_cell

                if request.get("receipt_profile") != "candidate":
                    raise ValueError("workspace lifecycle requires candidate receipt profile")
                self.finished = True
                self.observer.close()
                return run_lifecycle_cell(self.session, self.workspaces, str(request["scenario"]))
            if operation == "workspace_start" and self.witness is None and not self.finished:
                from scripts.native_slo_qualification_scenarios import validate_receipt_profile

                validate_receipt_profile(str(request["receipt_profile"]), {"build_sha": self.runtime_build_sha})
                self.witness = ReceiptWitness(
                    self.session, maximum=len(WORKSPACE_PHASES), receipt_profile=str(request["receipt_profile"])
                ).__enter__()
                return {"status": "completed", "registered_workspaces": len(self.workspaces)}
            if self.witness is None:
                raise RuntimeError("workspace scenario has not started")
            if operation == "workspace_page" and self.finished:
                return {"status": "completed", **self.observer.page(request["offset"])}
            if operation == "workspace_finish" and not self.finished:
                return self.finish()
            if operation == "workspace_phase" and not self.finished and not self.failed:
                return self.phase(str(request["phase"]))
            raise ValueError("workspace control state invalid")
        except Exception as error:
            self.failed = True
            return {
                "status": "failed",
                "passed": False,
                "failure": failure_evidence(error),
                "observer": self.observer.report(),
            }

    def _ack(self, *, previous: int, action: str, strict: bool, deadline: float) -> Mapping[str, Any]:
        while True:
            prepared = self.worker.prepare_workspace_policy(self.session.workspace, deadline=deadline)
            snapshot = self.publisher.current_snapshot()
            if isinstance(prepared, Mapping) and isinstance(snapshot, Mapping):
                binding, accepted = _authenticated_readback(self.session.store)
                effective = snapshot.get("effective_policy")
                snapshot_binding = public_binding(snapshot)
                if (
                    snapshot_binding is not None
                    and public_binding(prepared) == snapshot_binding
                    and _readback_matches(binding, accepted, snapshot)
                    and snapshot_binding["generation"] >= previous
                    and snapshot.get("mode") == "enforce"
                    and isinstance(effective, Mapping)
                    and effective.get("default_action") == action
                    and effective.get("subprocess_action") == action
                    and (not strict or effective.get("sandbox_analysis") == "strict")
                    and time.monotonic() <= deadline
                ):
                    return snapshot
            if time.monotonic() >= deadline:
                raise RuntimeError("workspace authenticated acknowledgment deadline")
            time.sleep(0.005)

    def _probe(self, index: int, snapshot: Mapping[str, Any], action: str, accepted: float) -> dict[str, object]:
        from scripts.native_slo_session import _request

        assert self.witness is not None
        attempt = f"mixed-policy-{index}"
        response = _request(
            self.session.daemon,
            guard_home=self.session.guard_home,
            workspace=self.session.workspace,
            harness="claude-code",
            request_payload=fixture_request("claude-code", "PreToolUse", attempt=attempt),
        )
        row = self.witness.row(attempt)
        expected = "deny" if action == "block" else "allow"
        matched = (
            row is not None
            and row["policy_generation"] == snapshot["generation"]
            and row["policy_digest"] == snapshot["policy_digest"]
            and row["policy_action"] == action
            and row["decision"] == expected
            and delivered_decision("PreToolUse", response) == expected
        )
        return {
            "attempt": attempt,
            "first_native_receipt_matches": matched,
            "decision_id": row["decision_id"] if row else None,
            "accept_to_first_native_ms": row["native_finished_ms"] - (accepted - self.witness.started) * 1000
            if row is not None
            else None,
            "accept_to_delivered_response_ms": (time.monotonic() - accepted) * 1000,
        }

    def _chain(self, index: int, binding: object, accepted: float, deadline: float) -> dict[str, object]:
        from scripts.native_slo_workspace_trace import phase_chain

        while True:
            chain = phase_chain(
                self.observer.rows(index),
                binding,
                accepted_ms=(accepted - self.observer.started) * 1000,
                require_final_compile=WORKSPACE_PHASES[index] == "coalesced_burst",
            )
            if time.monotonic() >= deadline:
                raise RuntimeError("workspace observed publication chain deadline")
            if chain["matched"] is True:
                return chain
            time.sleep(0.005)

    def phase(self, name: str) -> dict[str, object]:
        if self.next_phase >= len(WORKSPACE_PHASES) or name != WORKSPACE_PHASES[self.next_phase]:
            raise ValueError("workspace phase order invalid")
        index = self.next_phase
        self.next_phase += 1
        self.observer.phase(index)
        before = public_binding(self.publisher.current_snapshot_binding())
        if before is None:
            raise RuntimeError("workspace phase starting authority unavailable")
        started = time.monotonic()
        accepted = self.initial_started if name == "initial" else started
        minimum_generation = before["generation"]
        action = "block" if index >= WORKSPACE_PHASES.index("public_policy") else "allow"
        strict = index >= WORKSPACE_PHASES.index("stricter_overlay")
        offered_writes = 0
        error: dict[str, object] | None = None
        evidence: dict[str, object] = {}
        try:
            if name == "unchanged":
                self.publisher.request_publish()
                accepted = time.monotonic()
            elif name == "stricter_overlay":
                self._overlay(0, 0)
                offered_writes = 1
                accepted = time.monotonic()
                minimum_generation += 1
                evidence["explicit_mutation_notification_sent"] = False
            elif name == "coalesced_burst":
                for revision in range(BURST_WRITES):
                    self._overlay(revision % len(self.workspaces), revision + 1)
                    offered_writes += 1
                accepted = time.monotonic()
                evidence["explicit_mutation_notification_sent"] = False
            elif name == "public_policy":
                from codex_plugin_scanner.guard.config import update_guard_settings

                update_guard_settings(
                    self.session.guard_home, {"default_action": "block", "subprocess_action": "block"}
                )
                accepted = time.monotonic()
                minimum_generation += 1
                evidence["public_settings_mutation_returned"] = True
            elif name == "resident_restart":
                evidence["contained"] = self.session.stop_resident()
                if evidence["contained"] is not True:
                    raise RuntimeError("workspace resident containment failed")
                accepted = time.monotonic()
            deadline = (
                accepted + MAX_READINESS_P95_MS / 1000 if name != "initial" else started + MAX_READINESS_P95_MS / 1000
            )
            if name == "coalesced_burst":
                # Require actual reconciliation after the final write. No hint,
                # cache, clock, watcher or compilation result is substituted.
                while not any(
                    row["kind"] == "compile"
                    and row["phase"] == index
                    and row.get("succeeded") is True
                    and isinstance(stamp := row.get("started_ms"), (int, float))
                    and stamp >= (accepted - self.observer.started) * 1000
                    for row in self.observer.rows(index)
                ):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("workspace unnotified reconciliation deadline")
                    time.sleep(0.005)
            snapshot = self._ack(previous=minimum_generation, action=action, strict=strict, deadline=deadline)
            acknowledged = time.monotonic()
            evidence.update(
                binding=public_binding(snapshot),
                authenticated_ack=True,
                accepted_ms=(accepted - self.observer.started) * 1000,
                acknowledgment_observed_ms=(acknowledged - self.observer.started) * 1000,
                accept_to_ack_ms=(acknowledged - accepted) * 1000,
                stricter_overlay_retained=(not strict or snapshot["effective_policy"]["sandbox_analysis"] == "strict"),
            )
            evidence["publication_chain"] = self._chain(index, public_binding(snapshot), accepted, deadline)
            evidence.update(self._probe(index, snapshot, action, accepted))
        except Exception as failure:
            error = failure_evidence(failure)
        rows = self.observer.rows(index)
        counts = Counter(str(row["kind"]) for row in rows)
        config_loads = 0
        for row in rows:
            if row["kind"] == "compile":
                loads = row.get("config_loads")
                if type(loads) is not int or loads < 0:
                    raise RuntimeError("workspace observed compilation count invalid")
                config_loads += loads
        from scripts.native_slo_workspace_scopes import scope_checks

        chain = evidence.get("publication_chain")
        features = scope_checks(name, len(self.workspaces), rows, chain if isinstance(chain, Mapping) else {})
        self.cache_feature_failed |= not all(features.values())
        unchanged_cached = counts["compile"] > 0 and config_loads == 0 if name == "unchanged" else None
        passed = error is None and evidence.get("first_native_receipt_matches") is True
        self.failed = not passed
        result = {
            "status": "completed",
            "phase": name,
            "index": index,
            "passed": passed,
            "registered_workspaces": len(self.workspaces),
            "offered_writes": offered_writes,
            "mutation_ms": (accepted - started) * 1000 if name != "initial" else None,
            "registration_ms": self.registration_ms if name == "initial" else None,
            "elapsed_ms": (time.monotonic() - started) * 1000,
            "observer_counts": dict(counts),
            "config_loads": config_loads,
            "unchanged_scopes_reused": unchanged_cached,
            "cache_feature_checks": features,
            "cache_feature_checks_passed": all(features.values()),
            "readiness_deadline_ms": MAX_READINESS_P95_MS,
            "failure": error,
            **evidence,
        }
        self.phases.append(result)
        return result

    def _overlay(self, index: int, revision: int) -> None:
        from codex_plugin_scanner.guard.settings_write_lock import atomic_write_settings

        target = self.workspaces[index] / ".hol-guard.toml"
        # All edits retain the stricter value; comment revisions exercise real
        # independent captures without manufacturing a policy change per write.
        atomic_write_settings(target, f'sandbox_analysis = "strict"\n# workspace revision {revision}\n')

    def finish(self) -> dict[str, object]:
        assert self.witness is not None
        self.observer.freeze()
        writer = self.session.daemon._server.runtime_hook_evidence_writer
        deadline = time.monotonic() + 5.0
        while True:
            with writer._condition:
                stats = {**writer.stats(), "in_flight": writer._in_flight}
            if writer_drained(stats) or time.monotonic() >= deadline:
                break
            time.sleep(0.025)
        self.witness.reconcile(verify_all=True)
        receipts = self.witness.report()
        observations = receipts.get("observations")
        observer = self.observer.report()
        self.finished = True
        self.close()
        clean = (
            isinstance(observations, Mapping)
            and not any(
                receipts.get(key)
                for key in (
                    "missing",
                    "binding_mismatches",
                    "writer_rejected",
                    "writer_admission_unobserved",
                    "pre_receipts_without_program_binding",
                )
            )
            and not any(
                observations.get(key, 0)
                for key in (
                    "duplicate_observations",
                    "witness_overflow",
                    "invalid_receipt_identity",
                    "native_without_receipt",
                )
            )
        )
        complete_receipts = receipts["native_receipts"] == receipts["committed"] == len(WORKSPACE_PHASES)
        return {
            "status": "completed",
            "passed": not self.failed
            and clean
            and writer_drained(stats)
            and self.next_phase == len(WORKSPACE_PHASES)
            and len(self.phases) == len(WORKSPACE_PHASES)
            and complete_receipts
            and observer["complete"],
            "registered_workspaces": len(self.workspaces),
            "completed_phases": len(self.phases),
            "receipt_count": receipts["native_receipts"],
            "committed_receipts": receipts["committed"],
            "receipt_bindings_validated": clean,
            "cache_feature_checks_passed": not self.cache_feature_failed and self.next_phase == len(WORKSPACE_PHASES),
            "writer_drained": writer_drained(stats),
            "observer": observer,
            "coverage_limits": {
                "unnotified_edit": "normal_polling_no_explicit_mutation_hint_not_a_lost_metadata_injection",
                "restart": "contained_resident_only_python_daemon_remains_running",
                "pending": ["key_rotation", "expiry_fault", "first_admission_fault", "lost_metadata_hint"],
                "timing": "instrumented_observer_inclusive_no_headline_performance_qualification",
            },
        }
