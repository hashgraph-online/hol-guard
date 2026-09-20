"""Witnessed, process-local synthetic faults for the qualification corpus.

These faults exist only in the private benchmark fixture. Injection scope is
reported explicitly; a failed transport function is not a simulated crash test.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Mapping
from contextlib import ExitStack
from typing import Any, cast
from unittest.mock import patch

from scripts.native_slo_config_observer import PublisherConfigObserver
from scripts.native_slo_edge_diagnostic import capture_native_edge_stages
from scripts.native_slo_native_diagnostic import observe_native_call
from scripts.native_slo_publisher_diagnostic import policy_refusal_diagnostic


class FaultFixture:
    def __init__(self, session: Any, setup: str) -> None:
        self.session = session
        self.setup = setup
        self.stack = ExitStack()
        self.last_native: dict[str, object] | None = None
        self.last_native_diagnostic: dict[str, object] | None = None
        self.native_calls = 0
        self.native_completed_calls = 0
        self.last_policy_refusal_diagnostic: dict[str, object] | None = None
        self.policy_refusal_calls: int | None = None
        self.policy_refusal_observer_installed: bool = False
        self.capture_lock = threading.Lock()
        self.observed: dict[str, object] = {}
        worker = session.daemon._server.hook_worker
        snapshot = worker.policy_snapshot_publisher.current_snapshot()
        effective = snapshot.get("effective_policy") if snapshot else None
        risk_actions = effective.get("risk_actions") if isinstance(effective, Mapping) else None
        self.evidence: dict[str, object] = {
            "command_authority_fixture": dict(session.command_authority_fixture),
            "isolated_store": session.guard_home.is_relative_to(session.root)
            and session.workspace.is_relative_to(session.root),
            "policy_ack_current": snapshot is not None and worker.policy_snapshot_publisher.is_ready(),
            "effective_policy_allow": isinstance(effective, Mapping)
            and effective.get("default_action") == "allow"
            and effective.get("subprocess_action") == "allow"
            and isinstance(risk_actions, Mapping)
            and all(value == "allow" for value in risk_actions.values()),
            "watch_observe_config": snapshot is not None
            and snapshot.get("mode") == "observe"
            and isinstance(effective, Mapping)
            and effective.get("protection_posture") == "watch",
            "python_oracle_disabled": worker.test_oracle is None,
            "fault_scope": "none",
        }

    def __enter__(self) -> FaultFixture:
        try:
            return self._enter()
        except BaseException:
            self.stack.close()
            raise

    def _enter(self) -> FaultFixture:
        from codex_plugin_scanner.guard import native_hook_edge
        from codex_plugin_scanner.guard.daemon import hook_worker_responses
        from codex_plugin_scanner.guard.runtime import hook_payload_reference

        worker = self.session.daemon._server.hook_worker
        config_observer = self.stack.enter_context(PublisherConfigObserver(worker.policy_snapshot_publisher))
        self.evidence["publisher_config_observer"] = config_observer.identity
        original = worker._review_raw_hook_native
        self.stack.enter_context(capture_native_edge_stages())

        def capture(**kwargs: object) -> object:
            with self.capture_lock:
                self.native_calls += 1
            result, diagnostic = observe_native_call(
                lambda: original(**kwargs),
                worker=worker,
                deadline=kwargs.get("deadline"),
                policy_snapshot=kwargs.get("policy_snapshot"),
            )
            native_result = result.get("result") if isinstance(result, Mapping) else None
            with self.capture_lock:
                self.last_native = (
                    dict(cast(Mapping[str, object], native_result)) if isinstance(native_result, Mapping) else None
                )
                self.last_native_diagnostic = diagnostic
                self.native_completed_calls += 1
            return result

        self.stack.enter_context(patch.object(worker, "_review_raw_hook_native", capture))
        if self.setup in {"unavailable", "watch_unavailable"}:

            def unavailable(**_kwargs: object) -> None:
                self.observed["native_request_unavailable"] = True
                return None

            self.stack.enter_context(patch.object(native_hook_edge, "native_resident_client_request", unavailable))
            self.evidence["fault_scope"] = "injected_native_transport_unavailable"
        elif self.setup == "off":
            self.stack.enter_context(patch.dict("os.environ", {"HOL_GUARD_NATIVE": "off"}))
            from codex_plugin_scanner.guard.native_runtime import native_mode

            self.evidence["native_mode_off"] = native_mode() == "off"
            self.evidence["fault_scope"] = "explicit_off_mode"
        elif self.setup == "integrity":
            # The HTTP handler imports this function inside each request. The
            # defining module is the actual runtime seam; server has no module
            # attribute with that name in the pinned baseline or candidate.
            original_size = hook_payload_reference.hook_payload_reference_size

            def reference_size(*args: Any, **kwargs: Any) -> object:
                try:
                    return original_size(*args, **kwargs)
                except hook_payload_reference.HookPayloadReferenceError:
                    self.observed["payload_reference_rejected"] = True
                    raise

            self.stack.enter_context(
                patch.object(hook_payload_reference, "hook_payload_reference_size", reference_size)
            )
            self.evidence["fault_scope"] = "malformed_encrypted_reference"
        elif self.setup == "queue_bytes":
            scheduler = self.session.daemon._server.runtime_hook_scheduler
            self.stack.enter_context(patch.object(scheduler, "_retained_bytes_limit", 1))
            original_reserve = scheduler.reserve_bytes

            def reserve(**kwargs: object) -> object:
                result = original_reserve(**kwargs)
                if result == (None, "daemon_hook_queue_bytes"):
                    self.observed["byte_reservation_rejected"] = True
                return result

            self.stack.enter_context(patch.object(scheduler, "reserve_bytes", reserve))
            self.evidence["fault_scope"] = "configured_byte_limit_rejection"
        elif self.setup == "review_queue_failed":

            def approval_failed(*_args: object, **_kwargs: object) -> None:
                self.observed["approval_persistence_failed"] = True
                raise sqlite3.OperationalError("synthetic qualification write failure")

            self.stack.enter_context(patch.object(self.session.store, "add_approval_request", approval_failed))
            self.evidence["fault_scope"] = "injected_approval_persistence_error"
        elif self.setup == "expired":
            from scripts.native_slo_expiry import expire_acknowledged_authority

            self.evidence.update(expire_acknowledged_authority(self.session))
            self.evidence["fault_scope"] = "authenticated_short_lived_generation"
        elif self.setup == "revoked":
            from scripts.native_slo_revocation import revoke_acknowledged_authority

            self.evidence.update(revoke_acknowledged_authority(self.session))
            self.evidence["fault_scope"] = "withdrawn_accepted_authority_file"
        elif self.setup not in {"normal", "watch"}:
            raise RuntimeError("qualification fault setup has no witnessed implementation")
        owned_server = self.session.daemon._server
        original_reason = getattr(hook_worker_responses, "_native_policy_not_ready_reason", None)
        if callable(original_reason):

            def capture_policy_refusal(daemon_server: object) -> object:
                stamp = config_observer.stamp() if daemon_server is owned_server else None
                reason = original_reason(daemon_server)
                if daemon_server is owned_server:
                    diagnostic: dict[str, object]
                    try:
                        diagnostic = policy_refusal_diagnostic(reason)
                        config_failure = config_observer.evidence(stamp, diagnostic)
                        if config_failure is not None:
                            diagnostic["publisher_config_failure"] = config_failure
                    except Exception:
                        diagnostic = {"publisher_error_state": "collection_failed"}
                    try:
                        with self.capture_lock:
                            self.last_policy_refusal_diagnostic = diagnostic
                            if self.policy_refusal_calls is not None:
                                self.policy_refusal_calls += 1
                    except Exception:
                        # Optional recording must not replace the original
                        # helper's result; an incomplete count is unavailable.
                        self.last_policy_refusal_diagnostic = None
                        self.policy_refusal_calls = None
                return reason

            self.stack.enter_context(
                patch.object(hook_worker_responses, "_native_policy_not_ready_reason", capture_policy_refusal)
            )
            self.policy_refusal_observer_installed = True
            self.policy_refusal_calls = 0

        return self

    def before_case(self) -> None:
        with self.capture_lock:
            self.last_native = self.last_native_diagnostic = None
            self.native_calls = 0
            self.native_completed_calls = 0
            self.last_policy_refusal_diagnostic = None
            self.policy_refusal_calls = 0 if self.policy_refusal_observer_installed else None
        self.observed.clear()

    def result(self) -> dict[str, object]:
        with self.capture_lock:
            return {
                "setup": {**self.evidence, **self.observed},
                "native_result": self.last_native,
                "native_call_diagnostic": self.last_native_diagnostic,
                "native_call_count": self.native_calls,
                "native_completed_call_count": self.native_completed_calls,
                "policy_refusal_diagnostic": self.last_policy_refusal_diagnostic,
                "policy_refusal_count": self.policy_refusal_calls,
            }

    def __exit__(self, *_args: object) -> None:
        self.stack.close()
