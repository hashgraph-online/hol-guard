"""Actual producer-boundary lifecycle cells, separate from workspace throughput.

Each cell uses one disposable installed daemon and an explicit request cohort.
Fault requests and their outcomes remain separate from recovered native receipt
timings. No result here qualifies uninstrumented or cross-platform performance.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from contextlib import ExitStack, closing
from typing import Any

from scripts.native_slo_contract import MAX_READINESS_P95_MS
from scripts.native_slo_expiry import _authenticated_readback, _readback_matches, expire_acknowledged_authority
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_witness import ReceiptWitness, writer_drained
from scripts.native_slo_workspace_lifecycle_clocks import LifecycleClocks
from scripts.native_slo_workspace_lifecycle_faults import (
    FirstAdmissionReplyFault,
    LostMetadataHints,
    key_recovery_matches,
    recover_command_key,
    unavailable_request,
)
from scripts.native_slo_workspace_lifecycle_service import (
    register_scopes,
    replace_expired_publisher,
    replace_service,
    require_owned_paths,
)
from scripts.native_slo_workspace_observer import PublicationObserver, public_binding
from scripts.native_slo_workspace_request_observer import WorkspaceRequestObserver
from scripts.native_slo_workspace_trace import phase_chain

LIFECYCLE_SCENARIOS = (
    "lost_metadata_hint",
    "key_rotation",
    "first_admission_fault",
    "expiry_fault",
    "service_restart",
)


def await_ack(
    session: Any, *, minimum: int, action: str, strict: bool, workspace: Any, deadline: float
) -> Mapping[str, Any]:
    worker = session.daemon._server.hook_worker
    publisher = worker.policy_snapshot_publisher
    while True:
        prepared = worker.prepare_workspace_policy(workspace, deadline=deadline)
        snapshot = publisher.current_snapshot()
        if isinstance(prepared, Mapping) and isinstance(snapshot, Mapping):
            binding, authenticated = _authenticated_readback(session.store)
            effective = snapshot.get("effective_policy")
            snapshot_binding = public_binding(snapshot)
            if (
                snapshot_binding is not None
                and public_binding(prepared) == snapshot_binding
                and _readback_matches(binding, authenticated, snapshot)
                and snapshot_binding["generation"] >= minimum
                and snapshot.get("mode") == "enforce"
                and isinstance(effective, Mapping)
                and effective.get("default_action") == action
                and effective.get("subprocess_action") == action
                and (not strict or effective.get("sandbox_analysis") == "strict")
                and publisher.current_snapshot() == snapshot
                and time.monotonic() <= deadline
            ):
                return snapshot
        if time.monotonic() >= deadline:
            raise RuntimeError("workspace lifecycle authenticated acknowledgment deadline")
        time.sleep(0.005)


def _overlay(workspace: Any) -> None:
    from codex_plugin_scanner.guard.settings_write_lock import atomic_write_settings

    atomic_write_settings(workspace / ".hol-guard.toml", 'sandbox_analysis = "strict"\n')


def _drain(session: Any) -> bool:
    writer = session.daemon._server.runtime_hook_evidence_writer
    deadline = time.monotonic() + 5.0
    while True:
        with writer._condition:
            stats = {**writer.stats(), "in_flight": writer._in_flight}
        if writer_drained(stats):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.025)


def _chain(
    observer: PublicationObserver, snapshot: Mapping[str, Any], accepted: float, deadline: float
) -> dict[str, object]:
    while True:
        result = phase_chain(
            observer.rows(0), public_binding(snapshot), accepted_ms=(accepted - observer.started) * 1000
        )
        if time.monotonic() >= deadline:
            raise RuntimeError("workspace lifecycle publication chain deadline")
        if result["matched"] is True:
            return result
        time.sleep(0.005)


def _scope_checks(observer: PublicationObserver, chain: Mapping[str, Any], count: int) -> dict[str, bool]:
    current = [
        row
        for row in observer.rows(0)
        if row["kind"] == "compile" and row.get("publication") == chain.get("publication")
    ]
    return {
        "acknowledged_compile_observed": bool(current) and current[-1].get("succeeded") is True,
        "all_registered_workspaces_retained": bool(current) and current[-1].get("registered_workspaces") == count,
        "compiled_cache_complete": bool(current) and current[-1].get("cache_entries") == count + 1,
        "config_capture_complete": bool(current)
        and all(row.get("unregistered_loads") == row.get("config_load_failures") == 0 for row in current),
    }


def _cleanup(result: dict[str, Any], stage: str, operation: Any) -> None:
    try:
        operation()
    except Exception as error:
        result["passed"] = False
        result.setdefault("cleanup_failures", []).append({"stage": stage, "failure": failure_evidence(error)})


def run_lifecycle_cell(session: Any, workspaces: tuple[Any, ...], scenario: str) -> dict[str, object]:
    if scenario not in LIFECYCLE_SCENARIOS:
        raise ValueError("workspace lifecycle scenario unsupported")
    require_owned_paths(session, workspaces)
    clocks = LifecycleClocks()
    count = len(workspaces)
    publisher = session.daemon._server.hook_worker.policy_snapshot_publisher
    result: dict[str, Any] = {
        "status": "completed",
        "scenario": scenario,
        "registered_workspaces": count,
        "passed": False,
        "readiness_deadline_ms": MAX_READINESS_P95_MS,
        "headline_timing_eligible": False,
        "full_rsp_128_129_qualification": False,
        "python_process_restarted": False,
        "recovered_requests_declared": 1,
        "probe_workspace_index": count - 1,
        "secondary_workspace_probe_declared": count > 1,
        "secondary_workspace_probed": False,
    }
    observer: PublicationObserver | None = None
    fault: Any = None
    requests: WorkspaceRequestObserver | None = None
    witness: ReceiptWitness | None = None
    accepted: float | None = None
    snapshot: Mapping[str, Any] | None = None
    lifetime = ExitStack()

    def prepare_service(current: Any) -> None:
        nonlocal publisher, observer, fault, accepted
        publisher = current
        observer = lifetime.enter_context(PublicationObserver(current, workspaces))
        if scenario == "first_admission_fault":
            fault = lifetime.enter_context(FirstAdmissionReplyFault(current))
        register_scopes(current, workspaces)
        accepted = time.monotonic()
        clocks.mark("cold_registrations_return")
        result["acceptance_boundary"] = "cold_provider_all_workspace_registrations_returned"

    try:
        # Keep the stricter overlay active through key/expiry/service changes.
        # The lost-hint cell introduces it as the measured actual mutation.
        if scenario != "lost_metadata_hint":
            _overlay(workspaces[-1])
            publisher.request_publish()
        before = await_ack(
            session,
            minimum=1,
            action="allow",
            strict=scenario != "lost_metadata_hint",
            workspace=workspaces[-1],
            deadline=time.monotonic() + MAX_READINESS_P95_MS / 1000,
        )
        clocks.mark("setup_ack_return")
        if scenario in {"first_admission_fault", "service_restart"}:
            clocks.mark("replacement_enter")
            result["service_replacement"] = replace_service(session, workspaces, prepare=prepare_service, clocks=clocks)
            clocks.mark("replacement_return")
            publisher = session.daemon._server.hook_worker.policy_snapshot_publisher
        elif scenario == "expiry_fault":
            clocks.mark("expiry_enter")
            expiry = expire_acknowledged_authority(session)
            clocks.mark("expiry_return")
            result["expiry"] = expiry
            if not all(
                expiry.get(key) is True
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
                raise RuntimeError("workspace expiry proof incomplete")
            result["fault_request"] = unavailable_request(session, workspaces[-1])
            publisher = replace_expired_publisher(session, workspaces)
        if observer is None:
            observer = lifetime.enter_context(PublicationObserver(publisher, workspaces))
        # Cold registration acceptance precedes replacement construction. Keep
        # receipt and request offsets on that captured origin, without moving
        # acceptance or the publication observer's independent phase origin.
        witness = lifetime.enter_context(
            closing(ReceiptWitness(session, maximum=1, monotonic_origin=accepted).__enter__())
        )
        requests = lifetime.enter_context(WorkspaceRequestObserver(session, witness, workspaces, maximum=1))
        if scenario == "lost_metadata_hint":
            fault = lifetime.enter_context(LostMetadataHints(publisher))
            _overlay(workspaces[-1])
            accepted = time.monotonic()
            minimum = int(before["generation"]) + 1
            result["acceptance_boundary"] = "atomic_workspace_mutation_return"
        elif scenario == "key_rotation":
            accepted, evidence = recover_command_key(
                session, publisher, before, lambda: unavailable_request(session, workspaces[-1])
            )
            result["key_change"] = evidence
            minimum = int(before["generation"]) + 1
            result["acceptance_boundary"] = "supported_command_key_recovery_return"
        else:
            if scenario == "expiry_fault":
                register_scopes(publisher, workspaces)
                accepted = time.monotonic()
                clocks.mark("cold_registrations_return")
                result["acceptance_boundary"] = "cold_provider_all_workspace_registrations_returned"
                clocks.mark("publisher_start_enter")
                publisher.start()
                clocks.mark("publisher_start_return")
            minimum = int(before["generation"])
        if accepted is None:
            raise RuntimeError("workspace lifecycle acceptance was not observed")
        deadline = accepted + MAX_READINESS_P95_MS / 1000
        result["accepted_ms"] = (accepted - observer.started) * 1000
        clocks.mark("recovered_ack_enter")
        snapshot = await_ack(
            session,
            minimum=minimum,
            action="allow",
            strict=True,
            workspace=workspaces[-1],
            deadline=deadline,
        )
        clocks.mark("recovered_ack_return")
        result["accept_to_ack_ms"] = (time.monotonic() - accepted) * 1000
        result["binding"] = public_binding(snapshot)
        result["publication_chain"] = _chain(observer, snapshot, accepted, deadline)
        result["scope_checks"] = _scope_checks(observer, result["publication_chain"], count)
        if scenario in {"first_admission_fault", "service_restart"}:
            # The real constructor already starts its cold native publisher.
            # Observe that barrier under the original registration deadline;
            # full service startup also performs unrelated reconciliation.
            clocks.mark("daemon_start_enter")
            session.daemon.start()
            clocks.mark("daemon_start_return")
            binding, authenticated = _authenticated_readback(session.store)
            if publisher.current_snapshot() != snapshot or not _readback_matches(binding, authenticated, snapshot):
                raise RuntimeError("workspace full startup changed acknowledged authority")
        if scenario == "key_rotation" and not key_recovery_matches(before, snapshot):
            raise RuntimeError("workspace acknowledged key recovery linkage mismatch")
        requests.probe(0, count - 1)
        result["secondary_workspace_probed"] = count > 1
        drained = _drain(session)
        result["writer_drained"] = drained
        requests.close()
        witness.reconcile(verify_all=True)
        joined = requests.join(accepted=accepted, snapshot=snapshot, action="allow", declared_indexes=(0,))
        result["requests"] = joined
        result["writer_drained"] = drained
        result["stricter_overlay_retained"] = snapshot["effective_policy"]["sandbox_analysis"] == "strict"
        result["key_recovery_linked"] = key_recovery_matches(before, snapshot) if scenario == "key_rotation" else None
        fault_valid = True
        if fault is not None:
            proof = fault.report()
            result["fault"] = proof
            fault_valid = (
                proof["actual_changed_hint_observed"] is True
                if scenario == "lost_metadata_hint"
                else all(
                    proof[name] is True
                    for name in (
                        "real_accepted_reply_discarded",
                        "production_ack_error_observed",
                        "first_error_withheld_ack",
                        "subsequent_transport_forwarded",
                    )
                )
            )
        result["passed"] = (
            joined["passed"] is True
            and drained
            and fault_valid
            and result["stricter_overlay_retained"]
            and all(result["scope_checks"].values())
        )
    except Exception as error:
        result["failure"] = failure_evidence(error)
    finally:
        result["lifecycle_clocks"] = clocks.report()
        if fault is not None:
            _cleanup(result, "fault_report", lambda: result.update(fault=fault.report()))
        # End the one-scenario cell before freezing its final publication rows.
        # Containment is checked; an active callback can never imply completion.
        _cleanup(result, "publisher_close", publisher.close)
        result["publisher_contained"] = False
        _cleanup(
            result,
            "publisher_containment",
            lambda: result.update(
                publisher_contained=publisher.closed and (publisher._thread is None or not publisher._thread.is_alive())
            ),
        )
        result["passed"] = result["passed"] and result["publisher_contained"]
        if (
            requests is not None
            and witness is not None
            and snapshot is not None
            and accepted is not None
            and "requests" not in result
        ):
            # Preserve an actually offered request even if its HTTP response,
            # readback or normal join failed. The same declared set is retained;
            # collecting it cannot turn the original failure into a pass.
            _cleanup(result, "partial_writer_drain", lambda: result.update(writer_drained=_drain(session)))
            _cleanup(result, "partial_request_close", requests.close)
            _cleanup(result, "partial_receipt_reconcile", lambda: witness.reconcile(verify_all=True))
            partial_accepted = accepted
            _cleanup(
                result,
                "partial_request_join",
                lambda: result.update(
                    requests=requests.join(
                        accepted=partial_accepted, snapshot=snapshot, action="allow", declared_indexes=(0,)
                    )
                ),
            )
        _cleanup(result, "observation_restore", lifetime.close)
        if observer is not None:
            final_observer = observer
            _cleanup(result, "publication_freeze", final_observer.freeze)
            _cleanup(result, "publication_report", lambda: result.update(publication_observer=final_observer.report()))
            _cleanup(result, "publication_rows", lambda: result.update(publication_rows=final_observer.rows()))
            result["passed"] = result["passed"] and result.get("publication_observer", {}).get("complete") is True
        if requests is not None and "requests" not in result:
            result["recovered_request_cohort_complete"] = False
        if witness is not None and "requests" not in result:
            _cleanup(result, "receipt_report", lambda: result.update(receipt_witness=witness.report()))
    return result
