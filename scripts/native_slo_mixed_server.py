"""Private mixed-scenario controls for an actual installed daemon fixture.

Controls use production settings, policy publication, inventory persistence and
resident containment. Enforcing probes use authenticated HTTP, just like load
requests. This module does not construct snapshots or native decision receipts.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from scripts.native_slo_adapter import payload
from scripts.native_slo_contract import MAX_READINESS_P95_MS
from scripts.native_slo_mixed_response import delivered_decision
from scripts.native_slo_mixed_witness import MAX_CONTROL_ACTIONS, ReceiptWitness, writer_drained


class MixedScenarioFixture:
    def __init__(self, session: Any) -> None:
        self.session = session
        self.witness: ReceiptWitness | None = None
        self.samples = 0
        self.peaks: dict[str, int | float] = {}
        self.started = 0.0
        self.last_sample = 0.0
        self.max_sample_gap_ms = 0.0
        self.initial: dict[str, Any] = {}
        self.actions = 0
        self.finished = False
        self.progress: dict[str, object] = {}

    def close(self) -> None:
        if self.witness is not None:
            self.witness.close()

    def dispatch(self, operation: str, request: Mapping[str, Any]) -> dict[str, object]:
        # Failure remains an explicit control outcome, so later work and receipt
        # reconciliation can still be collected after a failed mutation/restart.
        self.progress = {}
        try:
            return {"status": "completed", **self._dispatch(operation, request)}
        except Exception as error:
            return {"status": "failed", "failure_type": type(error).__name__, **self.progress}

    def _dispatch(self, operation: str, request: Mapping[str, Any]) -> dict[str, object]:
        if operation == "mixed_start" and self.witness is None:
            worker = self.session.daemon._server.hook_worker
            if worker.test_oracle is not None:
                raise RuntimeError("mixed requires installed native authority")
            self._ack("allow", previous_generation=0)
            self.witness = ReceiptWitness(
                self.session,
                maximum=int(request["maximum"]),
                receipt_profile=str(request.get("receipt_profile", "candidate")),
            ).__enter__()
            self.started = self.last_sample = time.monotonic()
            self.initial = self._stats()
            return self.sample()
        if self.witness is None:
            raise RuntimeError("mixed scenario has not started")
        if operation == "mixed_page":
            if not self.finished:
                raise RuntimeError("mixed pages require completed collection")
            return self.witness.page(int(request["offset"]), int(request.get("limit", 128)))
        if self.finished:
            raise RuntimeError("mixed scenario already finished")
        if operation == "mixed_sample":
            return self.sample()
        if operation == "mixed_finish":
            deadline = time.monotonic() + 5.0
            while True:
                result = self.sample()
                stats = result["writer"]
                assert isinstance(stats, dict)
                if writer_drained(stats):
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.025)
            self.witness.reconcile(verify_all=True)
            result["receipts"] = self.witness.report()
            self.finished = True
            self.close()
            return result
        self.actions += 1
        if self.actions > MAX_CONTROL_ACTIONS:
            raise ValueError("mixed control action bound exceeded")
        index = int(request["index"])
        if not 0 <= index < MAX_CONTROL_ACTIONS:
            raise ValueError("mixed control index outside bound")
        if operation == "mixed_policy":
            return self.policy(str(request["action"]), index)
        if operation == "mixed_restart":
            return self.restart(index)
        if operation == "mixed_inventory":
            return self.inventory(index, int(request.get("count", 32)))
        raise ValueError("unsupported mixed operation")

    def _stats(self) -> dict[str, Any]:
        server = self.session.daemon._server
        writer = server.runtime_hook_evidence_writer
        # Both pinned versions use a Condition with its default reentrant lock.
        # Read the live batch flag with the corresponding public counters.
        with writer._condition:
            writer_stats = {**writer.stats(), "in_flight": writer._in_flight}
        return {
            "scheduler": server.runtime_hook_scheduler.stats(),
            "writer": writer_stats,
        }

    def sample(self) -> dict[str, object]:
        assert self.witness is not None
        self.witness.reconcile()
        now = time.monotonic()
        self.max_sample_gap_ms = max(self.max_sample_gap_ms, (now - self.last_sample) * 1000)
        self.last_sample = now
        self.samples += 1
        stats = self._stats()
        for section, keys in (
            ("scheduler", ("active", "queued", "retained_bytes", "oldest_queued_ms")),
            ("writer", ("queued", "queued_bytes", "durable_pending", "receipt_durable_pending")),
        ):
            for key in keys:
                value = stats[section].get(key)
                if isinstance(value, (int, float)):
                    name = f"{section}_{key}"
                    self.peaks[name] = max(self.peaks.get(name, 0), value)
        return {
            **stats,
            "initial": self.initial,
            "sampled_peaks": dict(self.peaks),
            "sample_count": self.samples,
            "max_sample_gap_ms": self.max_sample_gap_ms,
            "elapsed_ms": (now - self.started) * 1000,
            "receipts": self.witness.report(),
        }

    def _ack(self, action: str, *, previous_generation: int) -> dict[str, Any]:
        from codex_plugin_scanner.guard.native_policy_snapshot_acked import acked_snapshot_binding_for_store

        worker = self.session.daemon._server.hook_worker
        deadline = time.monotonic() + MAX_READINESS_P95_MS / 1000
        while True:
            prepared = worker.prepare_workspace_policy(self.session.workspace, deadline=deadline)
            snapshot = worker.policy_snapshot_publisher.current_snapshot()
            persisted = acked_snapshot_binding_for_store(self.session.store)
            effective = snapshot.get("effective_policy") if isinstance(snapshot, dict) else None
            if (
                time.monotonic() <= deadline
                and isinstance(prepared, dict)
                and isinstance(snapshot, dict)
                and isinstance(persisted, dict)
                and isinstance(effective, dict)
                and snapshot.get("mode") == "enforce"
                and effective.get("default_action") == action
                and effective.get("subprocess_action") == action
                and isinstance(prepared.get("generation"), int)
                and prepared["generation"] > previous_generation
                and all(
                    prepared.get(key) == snapshot.get(key) == persisted.get(key)
                    for key in ("generation", "policy_digest", "runtime_identity")
                )
            ):
                return prepared
            if time.monotonic() >= deadline:
                raise RuntimeError("mixed policy acknowledgment deadline")
            time.sleep(0.005)

    def _probe(
        self, kind: str, index: int, binding: Mapping[str, Any], action: str, accepted: float
    ) -> dict[str, object]:
        from scripts.native_slo_session import _request

        assert self.witness is not None
        attempt = f"mixed-{kind}-{index}"
        request = {**payload("PreToolUse"), "tool_use_id": attempt}
        response = _request(
            self.session.daemon,
            guard_home=self.session.guard_home,
            workspace=self.session.workspace,
            harness="claude-code",
            request_payload=request,
        )
        row = self.witness.row(attempt)
        expected_decision = "allow" if action == "allow" else "deny"
        enforced = (
            row is not None
            and row["policy_generation"] == binding["generation"]
            and row["policy_digest"] == binding["policy_digest"]
            and row["policy_action"] == action
            and row["decision"] == expected_decision
            and delivered_decision("PreToolUse", response) == expected_decision
        )
        first = self.witness.first_decision(binding, action, since=accepted)
        return {
            "attempt": attempt,
            "first_enforcing_receipt": enforced,
            "accept_to_probe_response_ms": (time.monotonic() - accepted) * 1000,
            "first_decision_attempt": first["attempt"] if first is not None else None,
            "accept_to_first_decision_ms": first["native_finished_ms"] - (accepted - self.witness.started) * 1000
            if first is not None
            else None,
            "generation": binding["generation"],
            "policy_digest": binding["policy_digest"],
            "expected_action": action,
            "probe_has_native_receipt": row is not None,
        }

    def policy(self, action: str, index: int) -> dict[str, object]:
        from codex_plugin_scanner.guard.config import update_guard_settings

        if action not in {"allow", "block"}:
            raise ValueError("mixed policy action unsupported")
        worker = self.session.daemon._server.hook_worker
        prior = worker.policy_snapshot_publisher.current_snapshot_binding()
        if not isinstance(prior, dict):
            raise RuntimeError("mixed prior policy unavailable")
        started = time.monotonic()
        self.progress = {
            "kind": "policy",
            "mutation_attempted": True,
            "mutation_returned": False,
            "acknowledged": False,
        }
        # This is the public settings API, including its normal approval gate.
        # The fixture owns a fresh private home; no gate override is supplied.
        update_guard_settings(self.session.guard_home, {"default_action": action, "subprocess_action": action})
        accepted = time.monotonic()
        self.progress.update(mutation_returned=True, mutation_ms=(accepted - started) * 1000)
        binding = self._ack(action, previous_generation=int(prior["generation"]))
        acked = time.monotonic()
        self.progress.update(acknowledged=True, accept_to_ack_ms=(acked - accepted) * 1000)
        return {
            "kind": "policy",
            "mutation_ms": (accepted - started) * 1000,
            "accept_to_ack_ms": (acked - accepted) * 1000,
            **self._probe("policy", index, binding, action, accepted),
        }

    def restart(self, index: int) -> dict[str, object]:
        worker = self.session.daemon._server.hook_worker
        snapshot = worker.policy_snapshot_publisher.current_snapshot()
        if not isinstance(snapshot, dict):
            raise RuntimeError("mixed recovery has no acknowledged policy")
        action = snapshot["effective_policy"]["default_action"]
        started = time.monotonic()
        self.progress = {"kind": "resident_recovery", "contained": False, "python_process_restarted": False}
        contained = self.session.stop_resident()
        if not contained:
            raise RuntimeError("mixed resident containment failed")
        self.progress["contained"] = True
        binding = self._ack(action, previous_generation=0)
        return {
            "kind": "resident_recovery",
            "contained": True,
            "python_process_restarted": False,
            **self._probe("recovery", index, binding, action, started),
        }

    def inventory(self, index: int, count: int) -> dict[str, object]:
        from codex_plugin_scanner.guard.models import GuardArtifact

        if not 1 <= count <= 128:
            raise ValueError("mixed inventory batch outside bound")
        started = time.monotonic()
        self.progress = {"kind": "local_inventory_upsert", "offered": count, "attempted": 0, "committed": 0}
        for item in range(count):
            self.progress["attempted"] = item + 1
            body = f"mixed local inventory revision {index}:{item}\n".encode("ascii")
            path = self.session.workspace / f"mixed-inventory-{item}.txt"
            path.write_bytes(body)
            artifact = GuardArtifact(
                artifact_id=f"mixed-inventory-{item}",
                name="Mixed inventory fixture",
                harness="codex",
                artifact_type="skill",
                source_scope="workspace",
                config_path=str(path),
            )
            self.session.store.record_inventory_artifact(
                artifact=artifact,
                artifact_hash=hashlib.sha256(path.read_bytes()).hexdigest(),
                policy_action="review",
                changed=True,
                now=datetime.now(timezone.utc).isoformat(),
                approved=False,
            )
            self.progress["committed"] = item + 1
        return {**self.progress, "elapsed_ms": (time.monotonic() - started) * 1000}
