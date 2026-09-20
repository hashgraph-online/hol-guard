"""Bounded physical faults for disposable workspace publication diagnostics.

Only the metadata hint fault substitutes an observation, and it substitutes
only that hint. Content capture, resident identity, clocks, generation files,
signatures, native decisions and acknowledgment validation remain production.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack, contextmanager
from typing import Any
from unittest.mock import patch


class LostMetadataHints:
    """Drop actual changed policy metadata while forwarding resident identity."""

    def __init__(self, publisher: Any) -> None:
        self.publisher = publisher
        self.calls = 0
        self.dropped_changes = 0
        self._lock = threading.Lock()
        self._patch: Any = None
        self._closed = False

    def __enter__(self) -> LostMetadataHints:
        if self._patch is not None or self._closed:
            raise RuntimeError("metadata fault lifecycle invalid")
        original = self.publisher._current_input_fingerprint
        baseline = original()[0]

        def observed() -> Any:
            policy, resident = original()
            with self._lock:
                self.calls += 1
                self.dropped_changes += policy != baseline
            return baseline, resident

        self._patch = patch.object(self.publisher, "_current_input_fingerprint", observed)
        self._patch.__enter__()
        return self

    def report(self) -> dict[str, object]:
        with self._lock:
            return {
                "metadata_observations": self.calls,
                "changed_metadata_hints_dropped": self.dropped_changes,
                "actual_changed_hint_observed": self.dropped_changes > 0,
                "resident_identity_forwarded": True,
                "content_capture_replaced": False,
                "clock_replaced": False,
                "explicit_publish_hint_sent": False,
            }

    def __exit__(self, *_args: object) -> None:
        try:
            if self._patch is not None:
                self._patch.__exit__(None, None, None)
        finally:
            self._closed = True


class FirstAdmissionReplyFault:
    """Discard one real accepted reply before a cold Python barrier admits it."""

    def __init__(self, publisher: Any) -> None:
        self.publisher = publisher
        self.calls = 0
        self.injected = False
        self.error_observed = False
        self.ack_withheld = False
        self._stack = ExitStack()

    def __enter__(self) -> FirstAdmissionReplyFault:
        from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _decode_ack_v3
        from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request

        if self.publisher._thread is not None or self.publisher._snapshot is not None:
            raise RuntimeError("first admission fault requires a cold publisher")
        original = self.publisher._client_request or native_resident_client_request
        record_error = self.publisher._record_error

        def client(*args: Any, **kwargs: Any) -> Any:
            self.calls += 1
            output = original(*args, **kwargs)
            if self.calls == 1:
                ack = _decode_ack_v3(output)
                try:
                    candidate = json.loads(kwargs["payload"])["request"]["snapshot"]
                    matched = (
                        ack is not None
                        and ack["status"] == "accepted"
                        and ack["generation"] == candidate["generation"]
                        and ack["policy_digest"] == candidate["policy_digest"]
                    )
                except (KeyError, TypeError, ValueError):
                    matched = False
                if matched:
                    self.injected = True
                    return b"{}"
            return output

        def failed(error: str) -> None:
            record_error(error)
            if self.injected and error == "native_policy_snapshot_ack_invalid":
                self.error_observed = True
                with self.publisher._condition:
                    self.ack_withheld = self.publisher._snapshot is None and not self.publisher._acked

        try:
            self._stack.enter_context(patch.object(self.publisher, "_client_request", client))
            self._stack.enter_context(patch.object(self.publisher, "_record_error", failed))
        except BaseException:
            self._stack.close()
            raise
        return self

    def report(self) -> dict[str, object]:
        return {
            "scope": "one_real_accepted_reply_discarded_before_first_python_admission",
            "real_client_calls": self.calls,
            "real_accepted_reply_discarded": self.injected,
            "production_ack_error_observed": self.error_observed,
            "first_error_withheld_ack": self.ack_withheld,
            "subsequent_transport_forwarded": self.calls >= 2,
            "successful_ack_fabricated": False,
        }

    def __exit__(self, *_args: object) -> None:
        self._stack.close()


def require_withdrawn(publisher: Any) -> None:
    if publisher.current_snapshot_binding() is not None or publisher.is_ready():
        raise RuntimeError("workspace lifecycle fault retained acknowledgment")


def unavailable_request(session: Any, workspace: Any) -> dict[str, object]:
    """Retain a distinct fault request, never count it as a successful receipt."""
    from scripts.native_slo_adapter import payload, route_counts
    from scripts.native_slo_daemon_fixture import witnessed_route
    from scripts.native_slo_mixed_response import delivered_decision
    from scripts.native_slo_observation_failure import contextual_failure
    from scripts.native_slo_session import _request
    from scripts.native_slo_workloads import _availability_expected, _validate_projection

    worker = session.daemon._server.hook_worker
    started = time.monotonic()
    result: dict[str, object] = {
        "passed": False,
        "scope": "fault_request_separate_from_recovered_receipt_cohort",
        "offered_requests": 0,
        "returned_requests": 0,
        "native_receipts_expected": 0,
        "availability_semantics": "explicit_advisory_continuation_without_native_policy_decision",
    }
    try:
        before = dict(route_counts(worker.metrics.snapshot()))
        result["offered_requests"] = 1
        response = _request(
            session.daemon,
            guard_home=session.guard_home,
            workspace=workspace,
            harness="claude-code",
            request_payload={**payload("PreToolUse"), "tool_use_id": "workspace-lifecycle-fault"},
        )
        result["returned_requests"] = 1
        result["delivered_decision"] = delivered_decision("PreToolUse", response)
        reason = response.get("reason_code")
        route = witnessed_route(before, dict(route_counts(worker.metrics.snapshot())))
        result["route"] = route
        if (
            reason
            not in {
                "native_policy_not_ready",
                "native_pre_tool_unavailable",
                "native_command_control_fence_unavailable",
            }
            or route != "native_fail_safe"
        ):
            raise RuntimeError("workspace lifecycle fault request mismatch")
        result["reason"] = reason
        _validate_projection(
            _availability_expected("claude-code", "PreToolUse", str(reason)), response, "workspace-lifecycle-fault"
        )
        result["passed"] = True
    except Exception as error:
        result["elapsed_ms"] = (time.monotonic() - started) * 1000
        raise contextual_failure(error, fault_request=result) from error
    result["elapsed_ms"] = (time.monotonic() - started) * 1000
    return result


@contextmanager
def publication_lock(session: Any) -> Any:
    from codex_plugin_scanner.guard.native_policy_snapshot_storage import _v3_generation_lock

    # Acquire the actual interprocess publication lock. No authority is
    # synthesized while the publisher's own bounded lock wait is exercised.
    with _v3_generation_lock(session.guard_home, deadline_monotonic=time.monotonic() + 0.4):
        yield


def recover_command_key(
    session: Any, publisher: Any, before: Mapping[str, Any], probe: Callable[[], dict[str, object]]
) -> tuple[float, dict[str, object]]:
    """Replace a lost generated command key through explicit linked recovery.

    Empty fixture authority is required because recovery deliberately archives
    unverifiable layers. This is not an arbitrary policy-integrity key migration
    or interactive enrollment qualification.
    """
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
    from scripts.native_slo_command_fixture import verify_empty_command_authority

    store = session.store
    verify_empty_command_authority(store)
    previous = before["command_extensions"]["authority"]
    old_key_id = previous["authority_key_id"]
    if not isinstance(old_key_id, str):
        raise RuntimeError("workspace prior command key identity missing")
    with publication_lock(session):
        store._secret_store().delete_secret(store._key_ref())
        if store._authority_key(required=False) is not None:
            raise RuntimeError("workspace command key fault was not applied")
        publisher.request_publish()
        require_withdrawn(publisher)
        fault = probe()
        recovered = store.recover_extension_control_authority(
            catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
        )
        accepted = time.monotonic()
        if recovered.health is not AuthorityHealth.PROTECTED or recovered.revision != 0 or recovered.layers:
            raise RuntimeError("workspace key recovery changed empty control policy")
        verify_empty_command_authority(store)
        require_withdrawn(publisher)
    return accepted, {
        "key_domain": "generated_command_control_authority",
        "actual_key_removed": True,
        "mutation_withdrew_ack": True,
        "supported_recovery_returned": True,
        "empty_control_policy_preserved": True,
        "old_authority_key_id": old_key_id,
        "old_authority_epoch": previous["epoch"],
        "fault_request": fault,
        "interactive_enrollment_exercised": False,
        "policy_integrity_key_migration_exercised": False,
    }


def key_recovery_matches(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    old = before.get("command_extensions")
    new = after.get("command_extensions")
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        return False
    prior, current = old.get("authority"), new.get("authority")
    if not isinstance(prior, Mapping) or not isinstance(current, Mapping):
        return False
    recovery = current.get("recovery")
    old_epoch, new_epoch = prior.get("epoch"), current.get("epoch")
    return (
        new.get("health") == "protected"
        and new.get("catalog_digest") == old.get("catalog_digest")
        and isinstance(current.get("authority_key_id"), str)
        and current["authority_key_id"] != prior.get("authority_key_id")
        and type(new_epoch) is int
        and type(old_epoch) is int
        and new_epoch > old_epoch
        and isinstance(recovery, Mapping)
        and recovery.get("previous_authority_key_id") == prior.get("authority_key_id")
        and recovery.get("previous_epoch") == old_epoch
    )
