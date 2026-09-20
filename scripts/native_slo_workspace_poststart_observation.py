"""Observe poststart registration, public mutation and one declared last-workspace request."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from contextlib import ExitStack, closing
from typing import Any, cast

from scripts.native_slo_contract import MAX_READINESS_P95_MS
from scripts.native_slo_expiry import _authenticated_readback, _readback_matches
from scripts.native_slo_mixed_witness import ReceiptWitness
from scripts.native_slo_workspace_observer import PublicationObserver, public_binding
from scripts.native_slo_workspace_poststart_session import diagnostic_failure
from scripts.native_slo_workspace_request_observer import WorkspaceRequestObserver
from scripts.native_slo_workspace_trace import phase_chain

STRICT_OVERLAY = b'sandbox_analysis = "strict"\n# poststart same-home replacement control\n'


def stricter_overlay(home: Any) -> dict[str, object]:
    from codex_plugin_scanner.guard.settings_write_lock import atomic_write_settings

    if len(home.instances) != 1 or home.instances[0].retirement.get("passed") is not True:
        raise RuntimeError("stricter overlay requires verified first-service retirement")
    target = home.workspaces[-1] / ".hol-guard.toml"
    raw = STRICT_OVERLAY
    atomic_write_settings(target, raw.decode("utf-8"))
    if target.read_bytes() != raw:
        raise RuntimeError("stricter overlay did not persist unchanged")
    return {
        "target_workspace_index": len(home.workspaces) - 1,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "written_after_first_service_retirement": True,
        "written_before_replacement_construction_and_registration": True,
        "automatic_workspace_restore_claimed": False,
    }


def ack(session: Any, *, previous: int, action: str, strict: bool, deadline: float) -> Mapping[str, Any]:
    while True:
        prepared = session.worker.prepare_workspace_policy(session.workspace, deadline=deadline)
        snapshot = session.publisher.current_snapshot()
        if isinstance(prepared, Mapping) and isinstance(snapshot, Mapping):
            binding, accepted = _authenticated_readback(session.store)
            effective = snapshot.get("effective_policy")
            if (
                public_binding(snapshot) is not None
                and public_binding(prepared) == public_binding(snapshot)
                and _readback_matches(binding, accepted, snapshot)
                and cast(int, snapshot["generation"]) >= previous
                and snapshot.get("mode") == "enforce"
                and isinstance(effective, Mapping)
                and effective.get("default_action") == action
                and effective.get("subprocess_action") == action
                and (not strict or effective.get("sandbox_analysis") == "strict")
                and time.monotonic() <= deadline
            ):
                return snapshot
        if time.monotonic() >= deadline:
            raise RuntimeError("poststart authenticated acknowledgment deadline")
        time.sleep(0.005)


def observed_chain(observer: Any, index: int, binding: object, accepted: float, deadline: float) -> dict[str, object]:
    while True:
        result = phase_chain(
            observer.rows(index),
            binding,
            accepted_ms=(accepted - observer.started) * 1000,
            require_final_compile=False,
        )
        if time.monotonic() >= deadline:
            raise RuntimeError("poststart publication chain deadline")
        if result["matched"] is True:
            return result
        time.sleep(0.005)


class PostStartObservation:
    """Attach only after actual service and global policy readiness."""

    def __init__(self, session: Any, *, instance: int) -> None:
        if type(instance) is not int or instance not in (0, 1):
            raise ValueError("service instance outside the declared pair")
        if session.ready_report.get("global_ready") is not True:
            raise RuntimeError("poststart observation requires actual ready report")
        if session.daemon._owned_service_ready is not True or not session.publisher.is_ready():
            raise RuntimeError("poststart service or publisher readiness was lost")
        self.session = session
        self.instance = instance
        self.publisher_observer = PublicationObserver(session.publisher, session.workspaces)
        self.stack = ExitStack()
        self.phases: list[dict[str, Any]] = []
        self.closed = False
        self.final: dict[str, Any] | None = None

    def __enter__(self) -> PostStartObservation:
        self.stack.enter_context(self.publisher_observer)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def phase(self, name: str) -> dict[str, object]:
        expected = ("poststart_registration", "public_policy") if self.instance == 0 else ("explicit_reregistration",)
        index = len(self.phases)
        if self.closed or index >= len(expected) or name != expected[index]:
            raise ValueError("poststart phase order invalid")
        observer = self.publisher_observer
        observer.phase(index)
        if name == "poststart_registration":
            declared = 0
        elif name == "public_policy":
            declared = 1
        else:
            declared = 2
        action = "allow" if name == "poststart_registration" else "block"
        strict = self.instance == 1
        result: dict[str, Any] = {
            "name": name,
            "instance": self.instance,
            "index": index,
            "registered_workspaces": len(self.session.workspaces),
            "target_workspace_index": len(self.session.workspaces) - 1,
            "secondary_workspace_probed": len(self.session.workspaces) > 1,
            "declared_request_index": declared,
            "request_offered": False,
            "readiness_deadline_ms": MAX_READINESS_P95_MS,
            "initial_compilation_observed": False,
            "headline_timing_eligible": False,
            "qualification_complete": False,
            "passed": False,
            "status": "started",
            "cleanup_errors": [],
        }
        self.phases.append(result)
        accepted, snapshot, request, witness = None, None, None, None
        try:
            with ExitStack() as stack:
                witness = stack.enter_context(closing(ReceiptWitness(self.session, maximum=3).__enter__()))
                request = stack.enter_context(
                    WorkspaceRequestObserver(
                        self.session,
                        witness,
                        self.session.workspaces,
                        maximum=3,
                    )
                )
                try:
                    before = public_binding(self.session.publisher.current_snapshot_binding())
                    if before is None:
                        raise RuntimeError("poststart phase starting binding is unavailable")
                    minimum_generation = before["generation"] + (1 if name == "public_policy" else 0)
                    started = time.monotonic()
                    registration_returns = []
                    result["explicit_registration_returns"] = registration_returns
                    if name in ("poststart_registration", "explicit_reregistration"):
                        with self.session.publisher._condition:
                            previous_scopes = set(self.session.publisher._workspace_paths)
                        if previous_scopes:
                            raise RuntimeError("workspace scopes appeared before explicit poststart registration")
                        if name == "explicit_reregistration":
                            overlay = (self.session.workspaces[-1] / ".hol-guard.toml").read_bytes()
                            if overlay != STRICT_OVERLAY:
                                raise RuntimeError("stricter overlay changed before explicit reregistration")
                            result["overlay_readback_before_reregistration_sha256"] = hashlib.sha256(
                                overlay
                            ).hexdigest()
                        for workspace in self.session.workspaces:
                            registration_returns.append(self.session.publisher.register_workspace(workspace))
                        accepted = time.monotonic()
                        if registration_returns != [True] * len(self.session.workspaces):
                            raise RuntimeError("an explicit poststart workspace registration was not accepted")
                        with self.session.publisher._condition:
                            actual_scopes = set(self.session.publisher._workspace_paths)
                        if actual_scopes != set(self.session.workspaces):
                            raise RuntimeError("actual registered workspace set differs")
                    else:
                        from codex_plugin_scanner.guard.config import update_guard_settings

                        update_guard_settings(
                            self.session.guard_home, {"default_action": "block", "subprocess_action": "block"}
                        )
                        accepted = time.monotonic()
                    result.update(
                        operation_ms=(accepted - started) * 1000,
                        accepted_ms=(accepted - observer.started) * 1000,
                    )
                    deadline = accepted + MAX_READINESS_P95_MS / 1000
                    snapshot = ack(
                        self.session,
                        previous=minimum_generation,
                        action=action,
                        strict=strict,
                        deadline=deadline,
                    )
                    acknowledged = time.monotonic()
                    result.update(
                        acknowledgment_observed_ms=(acknowledged - observer.started) * 1000,
                        accept_to_ack_ms=(acknowledged - accepted) * 1000,
                        binding=public_binding(snapshot),
                        stricter_overlay_retained=snapshot["effective_policy"].get("sandbox_analysis") == "strict"
                        if strict
                        else None,
                    )
                    result["publication_chain"] = observed_chain(
                        observer,
                        index,
                        public_binding(snapshot),
                        accepted,
                        deadline,
                    )
                    result["request_offered"] = True
                    request.probe(declared, len(self.session.workspaces) - 1)
                except BaseException as error:
                    result["failure"] = diagnostic_failure(error)
                finally:
                    try:
                        result["writer_drained_before_readback"] = self.session.drain()
                    except BaseException as error:
                        result["cleanup_errors"].append({"stage": "writer_drain", "failure": diagnostic_failure(error)})
                    for stage, operation in (
                        ("request_close", request.close),
                        ("witness_reconcile", lambda: witness.reconcile(verify_all=True)),
                    ):
                        try:
                            operation()
                        except BaseException as error:
                            result["cleanup_errors"].append({"stage": stage, "failure": diagnostic_failure(error)})
                    try:
                        if accepted is not None and snapshot is not None:
                            result["request_receipt_join"] = request.join(
                                accepted=accepted,
                                snapshot=snapshot,
                                action=action,
                                declared_indexes=(declared,),
                            )
                    except BaseException as error:
                        result["cleanup_errors"].append({"stage": "receipt_join", "failure": diagnostic_failure(error)})
                    try:
                        with request._lock:
                            if len(request._rows) > request.maximum:
                                raise RuntimeError("poststart request capture exceeded declared bound")
                            result["complete_request_rows"] = json.loads(
                                json.dumps(list(request._rows.values()), allow_nan=False)
                            )
                            result["owned_offered_attempts"] = list(request._rows)
                        result["complete_witness_report"] = witness.report()
                    except BaseException as error:
                        result["cleanup_errors"].append(
                            {
                                "stage": "request_capture",
                                "failure": diagnostic_failure(error),
                            }
                        )
        except BaseException as error:
            detail = diagnostic_failure(error)
            if "failure" not in result:
                result["failure"] = detail
            else:
                result["cleanup_errors"].append({"stage": "observer_or_witness_exit", "failure": detail})
        chain, joined = result.get("publication_chain"), result.get("request_receipt_join")
        result.update(
            status="finished",
            passed="failure" not in result
            and not result["cleanup_errors"]
            and isinstance(chain, Mapping)
            and chain.get("matched") is True
            and isinstance(joined, Mapping)
            and joined.get("passed") is True,
        )
        return result

    def close(self) -> dict[str, object]:
        if self.closed:
            assert self.final is not None
            return self.final
        self.closed = True
        self.final = {
            "observer": None,
            "rows": [],
            "phases": list(self.phases),
            "passed": False,
            "capture_errors": [],
            "qualification_complete": False,
        }
        try:
            self.publisher_observer.freeze()
        except BaseException as error:
            self.final["capture_errors"].append({"stage": "freeze", "failure": diagnostic_failure(error)})
        for name, operation in (
            ("observer", self.publisher_observer.report),
            ("rows", self.publisher_observer.rows),
        ):
            try:
                self.final[name] = operation()
            except BaseException as error:
                self.final["capture_errors"].append({"stage": name, "failure": diagnostic_failure(error)})
        try:
            self.stack.close()
        except BaseException as error:
            self.final["capture_errors"].append({"stage": "close", "failure": diagnostic_failure(error)})
        report = self.final["observer"]
        self.final["passed"] = (
            not self.final["capture_errors"]
            and isinstance(report, Mapping)
            and report.get("complete") is True
            and len(self.phases) == (2 if self.instance == 0 else 1)
            and all(row["passed"] is True for row in self.phases)
        )
        return self.final
