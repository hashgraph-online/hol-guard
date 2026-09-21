"""Private installed-daemon posture transitions under bounded ordinary HTTP load.

Every ordinary request crosses the production authenticated HTTP adapter, even
though this diagnostic load generator lives in the disposable daemon process.
These instrumented observations are excluded from all headline timing samples.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from collections.abc import Mapping
from typing import Any

from scripts.native_slo_adapter import route_counts
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_witness import writer_drained
from scripts.native_slo_observation_failure import verdict_evidence
from scripts.native_slo_posture_controls import PostureControls
from scripts.native_slo_posture_witness import (
    MAX_POSTURE_ATTEMPTS,
    POSTURE_ROUTES,
    PostureWitness,
    binding_key,
    posture_case,
    validate_delivery,
)

POSTURE_OPERATIONS = (
    "enforce_to_watch",
    "watch_restart",
    "watch_to_enforce",
    "first_strict_workspace",
    "failed_publication",
    "expiry",
)
_MAX_PHASES = 3
_PER_WORKER_LIMIT = 64


class PostureScenarioFixture:
    def __init__(self, session: Any) -> None:
        self.session = session
        self.controls = PostureControls(session)
        self.witness: PostureWitness | None = None
        self.rows: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.phases = 0
        self.failed = False
        self.finished = False

    def close(self) -> None:
        if self.witness is not None:
            self.witness.close()

    def dispatch(self, operation: str, request: Mapping[str, Any]) -> dict[str, object]:
        try:
            if operation == "posture_start" and self.witness is None:
                if self.controls.worker.test_oracle is not None:
                    raise RuntimeError("posture qualification requires installed native authority")
                self.controls.ack()
                self.witness = PostureWitness(self.session, receipt_profile=str(request["receipt_profile"])).__enter__()
                return {"status": "completed", "starting_authority_authenticated": True}
            if self.witness is None:
                raise RuntimeError("posture scenario has not started")
            if operation == "posture_page" and self.finished:
                offset = request["offset"]
                if type(offset) is not int or not 0 <= offset <= len(self.rows):
                    raise ValueError("posture page outside bound")
                return {
                    "status": "completed",
                    "rows": [self._public(row) for row in self.rows[offset : offset + 32]],
                    "total": len(self.rows),
                }
            if operation == "posture_finish" and not self.finished:
                return self.finish()
            if operation == "posture_phase" and not self.failed and not self.finished:
                return self.phase(str(request["transition"]))
            raise ValueError("unsupported posture operation or state")
        except Exception as error:
            self.failed = True
            return {
                "status": "failed",
                "passed": False,
                "failure": failure_evidence(error),
                "attempted": len(self.rows),
            }

    def _request(
        self,
        route: int,
        *,
        phase: str,
        part: str,
        scope: str = "initial",
        required: str | tuple[object, ...] | None = None,
    ) -> None:
        from scripts.native_slo_session import _request

        harness, event = POSTURE_ROUTES[route]
        case = posture_case(harness, event)
        with self.lock:
            if len(self.rows) >= MAX_POSTURE_ATTEMPTS:
                raise RuntimeError("posture request bound exceeded")
            attempt = f"mixed-load-{len(self.rows)}"
            row: dict[str, Any] = {
                "attempt": attempt,
                "phase": phase,
                "part": part,
                "scope": scope,
                "harness": harness,
                "event": event,
                "state": "offered",
                "required": required,
                "started": time.monotonic(),
            }
            self.rows.append(row)
        try:
            row["response"] = _request(
                self.session.daemon,
                guard_home=self.session.guard_home,
                workspace=self.controls.workspace(scope),
                harness=harness,
                request_payload={**case.payload, "tool_use_id": attempt},
            )
            row["state"] = "completed"
        except Exception as error:
            row.update(state="failed", failure=failure_evidence(error))
        finally:
            row["finished"] = time.monotonic()

    def _probes(self, phase: str, part: str, scope: str, required: str | tuple[object, ...]) -> None:
        # Four distinct ordinary calls, not retries of an ambiguous invocation.
        attempts: list[dict[str, Any]] = []
        for route in range(len(POSTURE_ROUTES)):
            self._request(route, phase=phase, part=part, scope=scope, required=required)
        # Concurrent load can append between these probes. Select the exact
        # marked calls before claiming that the held fault was delivered.
        with self.lock:
            attempts = [
                row for row in self.rows if row["phase"] == phase and row["part"] == part and row["scope"] == scope
            ]
        if self._validate(attempts):
            raise RuntimeError("posture explicit probe contract failed")

    def phase(self, operation: str) -> dict[str, object]:
        if operation not in POSTURE_OPERATIONS or self.phases >= _MAX_PHASES:
            raise ValueError("posture transition bound exceeded")
        assert self.witness is not None
        self.phases += 1
        offset = len(self.rows)
        before_counts = dict(route_counts(self.controls.worker.metrics.snapshot()))
        before = self.controls.ack()
        self._probes(operation, "before", "initial", binding_key(before))
        stop = threading.Event()
        first_offer = threading.Event()
        threads: list[threading.Thread] = []

        def load(route: int) -> None:
            for index in range(_PER_WORKER_LIMIT):
                if index >= 2 and stop.is_set():
                    break
                first_offer.set()
                self._request(route, phase=operation, part="during")
                if stop.wait(0.1) and index >= 1:
                    break

        for route in range(len(POSTURE_ROUTES)):
            thread = threading.Thread(target=load, args=(route,), daemon=True)
            thread.start()
            threads.append(thread)
        first_offer.wait(0.4)
        mutation_started = time.monotonic()
        after: Mapping[str, Any] | None = None
        error_detail: dict[str, object] | None = None
        try:
            after = self.controls.apply(
                operation, before, lambda scope, required: self._probes(operation, "held", scope, required)
            )
        except Exception as error:
            error_detail = failure_evidence(error)
        finally:
            mutation_finished = time.monotonic()
            stop.set()
            # One aggregate completion deadline; never reset it per worker.
            completion_deadline = time.monotonic() + 10.0
            for thread in threads:
                thread.join(max(0, completion_deadline - time.monotonic()))
        unfinished = sum(thread.is_alive() for thread in threads)
        if not unfinished and error_detail is None:
            requirement = binding_key(after) if after is not None else "unavailable"
            self._probes(operation, "after", "initial", requirement)
            if operation == "first_strict_workspace":
                self._probes(operation, "after", "strict", requirement)
        rows = self.rows[offset:]
        mismatches = self._validate(rows)
        after_counts = dict(route_counts(self.controls.worker.metrics.snapshot()))
        delta = {
            name: after_counts.get(name, 0) - before_counts.get(name, 0)
            for name in set(before_counts) | set(after_counts)
        }
        actual = Counter(row.get("route") for row in rows if row.get("valid") is True)
        route_conservation = all(value >= 0 for value in delta.values()) and {
            key: value for key, value in delta.items() if value
        } == dict(actual)
        overlap = sum(
            row["part"] == "during"
            and row["started"] < mutation_finished
            and row.get("finished", float("inf")) > mutation_started
            for row in rows
        )
        completed = sum(row["state"] == "completed" for row in rows)
        passed = (
            error_detail is None
            and not unfinished
            and not mismatches
            and overlap > 0
            and route_conservation
            and completed == len(rows)
        )
        self.failed = not passed
        proof: dict[str, object] = {
            "status": "completed",
            "passed": passed,
            "operation": operation,
            "attempted": len(rows),
            "completed": completed,
            "semantic_mismatches": mismatches,
            "overlapping_http_calls": overlap,
            "concurrent_workers": len(threads),
            "unfinished_workers": unfinished,
            "native_receipts": actual.get("native_resident", 0),
            "intrinsic_block_receipts": actual.get("native_resident", 0),
            "validated_request_bindings": actual.get("native_resident", 0),
            "watch_deliveries": sum(row.get("valid") is True and row.get("ack_mode") == "observe" for row in rows),
            "enforce_deliveries": sum(row.get("valid") is True and row.get("ack_mode") == "enforce" for row in rows),
            "authenticated_bindings": len(self.controls.known),
            "explicit_unavailable": actual.get("native_fail_safe", 0),
            "route_conservation": route_conservation,
            "native_routes_observed": delta.get("native_resident", 0),
            "fail_safe_routes_observed": delta.get("native_fail_safe", 0),
            "other_routes_observed": sum(
                value for name, value in delta.items() if name not in {"native_resident", "native_fail_safe"}
            ),
            "routes_before": before_counts,
            "routes_after": after_counts,
            "acknowledged_after": after is not None,
            "generation_before": before["generation"],
            "generation_after": after["generation"] if after is not None else None,
            "mode_before": before["mode"],
            "mode_after": after["mode"] if after is not None else None,
            "after_probes": sum(row["part"] == "after" for row in rows),
            **self.controls.progress,
        }
        if error_detail is not None:
            proof["failure"] = error_detail
        return proof

    def _validate(self, rows: list[dict[str, Any]]) -> int:
        assert self.witness is not None
        mismatches = 0
        for row in rows:
            row["valid"] = False
            if row["state"] != "completed":
                mismatches += 1
                continue
            try:
                context = self.witness.context(row["attempt"])
                row["route"] = validate_delivery(
                    case=posture_case(row["harness"], row["event"]),
                    response=row["response"],
                    context=context,
                    known_bindings=self.controls.known,
                    required=row["required"],
                )
                if row["route"] == "native_resident" and context is not None:
                    row["ack_mode"] = context["binding"]["mode"]
                row["valid"] = True
            except Exception as error:
                row["failure"] = failure_evidence(error)
                mismatches += 1
        return mismatches

    def _public(self, row: Mapping[str, Any]) -> dict[str, object]:
        assert self.witness is not None
        receipt = self.witness.row(row["attempt"])
        context = self.witness.context(row["attempt"])
        return {
            **{
                key: row.get(key)
                for key in (
                    "attempt",
                    "phase",
                    "part",
                    "scope",
                    "harness",
                    "event",
                    "state",
                    "route",
                    "ack_mode",
                    "valid",
                    "failure",
                )
            },
            "elapsed_ms": (row.get("finished", row["started"]) - row["started"]) * 1000,
            "binding": context,
            "receipt": receipt,
            "semantics": verdict_evidence(row.get("response")),
        }

    def finish(self) -> dict[str, object]:
        assert self.witness is not None
        writer = self.session.daemon._server.runtime_hook_evidence_writer
        deadline = time.monotonic() + 5.0
        while True:
            with writer._condition:
                stats = {**writer.stats(), "in_flight": writer._in_flight}
            if writer_drained(stats) or time.monotonic() >= deadline:
                break
            time.sleep(0.025)
        self.witness.reconcile(verify_all=True)
        report = self.witness.report()
        observations = report["observations"]
        assert isinstance(observations, dict)
        clean = not any(
            observations.get(key, 0)
            for key in (
                "duplicate_observations",
                "witness_overflow",
                "invalid_receipt_identity",
                "native_without_receipt",
                "posture_duplicate_or_overflow",
            )
        )
        persisted = all(
            report.get(key) == 0
            for key in (
                "missing",
                "binding_mismatches",
                "writer_rejected",
                "writer_admission_unobserved",
                "pre_receipts_without_program_binding",
            )
        )
        self.finished = True
        self.close()
        return {
            "status": "completed",
            "passed": not self.failed and clean and persisted and writer_drained(stats),
            "attempted": len(self.rows),
            "native_receipts": report["native_receipts"],
            "committed": report["committed"],
            "distinct_receipts": clean,
            "bindings_validated": persisted,
            "writer_drained": writer_drained(stats),
            "committed_identity_digest": report["committed_identity_digest"],
        }
