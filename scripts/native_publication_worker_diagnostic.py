"""Failure-only, finite observations of a publisher already running at attachment."""

from __future__ import annotations

import sys
import threading
from queue import Queue
from types import CodeType, FrameType, FunctionType

from codex_plugin_scanner.guard.native_cloud_policy_inputs import read_native_cloud_policy_inputs
from codex_plugin_scanner.guard.native_policy_authority_managed import (
    read_frozen_native_managed_authority,
    require_unenrolled_secrets,
)
from codex_plugin_scanner.guard.native_policy_authority_read import (
    _capture_native_policy_authority_inputs,
    read_native_policy_authority_inputs,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import compiled_v3_compatible_policy
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _publish_snapshot_v3
from codex_plugin_scanner.guard.native_resident_client import (
    _PersistentNativeClientPool,
    native_resident_client_request,
)
from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient
from codex_plugin_scanner.guard.store_connection_schema import StoreConnectionSchemaMixin
from codex_plugin_scanner.guard.store_secret_policy_integrity import StoreSecretPolicyIntegrityMixin


def _wrapped_source_code(function: object) -> CodeType | None:
    """Use the trusted contextmanager body, never the shared decorator code."""
    if type(function) is not FunctionType:
        return None
    wrapped = vars(function).get("__wrapped__")
    return wrapped.__code__ if type(wrapped) is FunctionType else None


_MAX_STACK_FRAMES = 32
_RESPONSE_QUEUE_GET_CODE = Queue.get.__code__
_NATIVE_CLIENT_REQUEST_CODE = _PersistentNativeClient.request.__code__
_PHASE_CODES: tuple[tuple[CodeType | None, str], ...] = (
    (NativePolicySnapshotPublisher._run.__code__, "publisher_loop"),
    (NativePolicySnapshotPublisher._publish_once.__code__, "publication"),
    (NativePolicySnapshotPublisher._publication_context.__code__, "context_preparation"),
    (NativePolicySnapshotPublisherInputs._compiled_command_extensions.__code__, "command_preparation"),
    (NativePolicySnapshotPublisherInputs._compiled_effective_policy.__code__, "config_preparation"),
    (NativePolicySnapshotPublisherInputs._policy_input_changed.__code__, "input_observation"),
    (NativePolicySnapshotPublisherInputs._current_input_fingerprint.__code__, "input_metadata"),
    (NativePolicySnapshotPublisherInputs._confirm_resident_fingerprint.__code__, "resident_confirmation"),
    (compiled_v3_compatible_policy.__code__, "v3_source_capture"),
    (read_native_policy_authority_inputs.__code__, "authority_capture"),
    (_capture_native_policy_authority_inputs.__code__, "authority_sql_capture"),
    (read_frozen_native_managed_authority.__code__, "managed_authority_capture"),
    (require_unenrolled_secrets.__code__, "unenrolled_authority_check"),
    (read_native_cloud_policy_inputs.__code__, "cloud_input_validation"),
    (StoreSecretPolicyIntegrityMixin._policy_integrity_secret_material.__code__, "integrity_material"),
    (StoreSecretPolicyIntegrityMixin._load_policy_integrity_control_state.__code__, "integrity_control"),
    (StoreSecretPolicyIntegrityMixin._policy_integrity_cache_marker.__code__, "integrity_marker"),
    (_wrapped_source_code(StoreConnectionSchemaMixin._connect_once), "store_connection"),
    (StoreSecretPolicyIntegrityMixin._repair_store_permissions.__code__, "store_permissions"),
    (_publish_snapshot_v3.__code__, "snapshot_transport"),
    (native_resident_client_request.__code__, "resident_transport"),
    (_NATIVE_CLIENT_REQUEST_CODE, "resident_transport"),
    (_PersistentNativeClient._request_snapshot.__code__, "client_snapshot"),
    (_PersistentNativeClient._start.__code__, "client_start"),
    (_PersistentNativeClient._write_frame.__code__, "client_frame_write"),
    (_PersistentNativeClientPool._lease.__code__, "transport_capacity"),
)


def _boolean(value: object) -> str:
    return "yes" if value is True else "no" if value is False else "unknown"


def _stack_phase(frame: object) -> tuple[str, str]:
    """Read code identity only; never read locals, source paths, or arguments."""
    response_queue = False
    try:
        for _ in range(_MAX_STACK_FRAMES):
            if frame is None:
                return "unknown", "complete"
            if type(frame) is not FrameType:
                return "unknown", "unavailable"
            if frame.f_code is _RESPONSE_QUEUE_GET_CODE:
                response_queue = True
            for code, phase in _PHASE_CODES:
                if frame.f_code is code:
                    if response_queue and code is _NATIVE_CLIENT_REQUEST_CODE:
                        return "client_response_wait", "matched"
                    return phase, "matched"
            frame = frame.f_back
        return "unknown", "truncated" if frame is not None else "complete"
    finally:
        # A frame can retain private request material even without inspecting it.
        frame = None


def _worker_phase(thread: threading.Thread) -> tuple[str, str]:
    frame: FrameType | None = None
    try:
        identity = vars(thread).get("_ident")
        if type(identity) is not int:
            return "unknown", "unavailable"
        frames = sys._current_frames()
        frame = frames.get(identity)
        del frames
        return _stack_phase(frame)
    except BaseException:
        return "unknown", "unavailable"
    finally:
        frame = None


def describe_publication_worker(publisher: object) -> str:
    """Sample existing state without acquiring its locks or invoking its methods."""
    facts: dict[str, str] = dict.fromkeys(
        ("started", "closed", "acked", "snapshot", "thread", "event", "phase"), "unknown"
    )
    facts["stack"] = "unavailable"
    try:
        # Reject arbitrary properties, thread substitutes, and subclass overrides.
        if type(publisher) is NativePolicySnapshotPublisher:
            namespace = vars(publisher)
            for field in ("started", "closed", "acked"):
                facts[field] = _boolean(namespace.get("_" + field))
            if "_snapshot" in namespace:
                snapshot = namespace["_snapshot"]
                facts["snapshot"] = (
                    "missing" if snapshot is None else "present" if type(snapshot) is dict else "unknown"
                )
            event = namespace.get("_publish_event")
            if type(event) is threading.Event:
                facts["event"] = _boolean(threading.Event.is_set(event))
            thread = namespace.get("_thread")
            if thread is None:
                facts["thread"] = "missing"
            elif type(thread) is threading.Thread:
                alive = threading.Thread.is_alive(thread)
                facts["thread"] = "alive" if alive else "stopped"
                if alive:
                    facts["phase"], facts["stack"] = _worker_phase(thread)
    except BaseException:
        pass
    return "; ".join(f"worker_{field}={value}" for field, value in facts.items())


__all__ = ["describe_publication_worker"]
