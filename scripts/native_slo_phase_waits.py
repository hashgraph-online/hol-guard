"""Request-scoped scheduler/pool/stream waits; no fabricated socket timer."""

from __future__ import annotations

import contextvars
import functools
import threading
from contextlib import ExitStack
from dataclasses import dataclass
from queue import Queue
from typing import Any
from unittest.mock import patch

from scripts.native_slo_phase_calls import Recorder, byte_size

_CONDITION = contextvars.ContextVar[tuple[object, str] | None]("phase_condition", default=None)
_QUEUED = contextvars.ContextVar[list[Any] | None]("phase_queued", default=None)


@dataclass
class _StreamScope:
    queue: object | None = None


_STREAM = contextvars.ContextVar[_StreamScope | None]("phase_stream", default=None)


def install_wait_probes(stack: ExitStack, recorder: Any) -> None:
    from codex_plugin_scanner.guard import native_resident_client, native_resident_stream
    from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler

    acquire = RuntimeHookScheduler.acquire
    reserve = RuntimeHookScheduler.reserve_bytes
    enqueue = RuntimeHookScheduler._enqueue
    lease = native_resident_client._PersistentNativeClientPool._lease
    request = native_resident_stream._PersistentNativeClient.request
    snapshot = native_resident_stream._PersistentNativeClient._request_snapshot
    condition_wait = threading.Condition.wait
    queue_get = Queue.get

    @functools.wraps(reserve)
    def measured_reserve(self: Any, *args: Any, **kwargs: Any) -> Any:
        recorder.work("byte_admission", "attempted_payload_bytes", kwargs.get("payload_bytes"))
        result = recorder.call(reserve, "byte_admission", self, *args, **kwargs)
        recorder.work("byte_admission", "reserved" if result[0] is not None else "rejected", 1)
        return result

    @functools.wraps(acquire)
    def measured_acquire(self: Any, *args: Any, **kwargs: Any) -> Any:
        captured: list[Any] = []
        item_token = _QUEUED.set(captured)
        wait_token = _CONDITION.set((self._condition, "scheduler_condition_wait"))
        result = None
        try:
            recorder.work("admission_and_queue", "attempted_payload_bytes", kwargs.get("payload_bytes"))
            result = recorder.call(acquire, "admission_and_queue", self, *args, **kwargs)
            return result
        finally:
            _CONDITION.reset(wait_token)
            _QUEUED.reset(item_token)
            if captured:
                item = captured[0]
                if item.admitted_at is not None:
                    # Real scheduler timestamps, including when a different
                    # request's release dispatches this waiting request.
                    recorder.duration("scheduler_queue_admitted", max(0, item.admitted_at - item.queued_at) * 1000)
                else:
                    # Retain rejected/cancelled work; the end is acquire's
                    # return, NOT a claimed exact dequeue timestamp.
                    recorder.duration(
                        "scheduler_queue_unadmitted_until_return", max(0, self._monotonic() - item.queued_at) * 1000
                    )
                recorder.work("admission_and_queue", "enqueued_attempts", 1)
            else:
                recorder.work("admission_and_queue", "never_enqueued_attempts", 1)
            if result is not None:
                recorder.work("admission_and_queue", "admitted" if result.permit is not None else "rejected", 1)

    @functools.wraps(enqueue)
    def measured_enqueue(self: Any, item: Any) -> Any:
        result = enqueue(self, item)
        captured = _QUEUED.get()
        if captured is not None and not captured:
            captured.append(item)
        return result

    @functools.wraps(lease)
    def measured_lease(self: Any, *args: Any, **kwargs: Any) -> Any:
        token = _CONDITION.set((self._condition, "client_pool_condition_wait"))
        try:
            return recorder.call(lease, "client_pool_lease_inclusive", self, *args, **kwargs)
        finally:
            _CONDITION.reset(token)

    @functools.wraps(condition_wait)
    def measured_wait(self: Any, *args: Any, **kwargs: Any) -> Any:
        scope = _CONDITION.get()
        if scope is None or self is not scope[0]:
            return condition_wait(self, *args, **kwargs)
        return recorder.call(condition_wait, scope[1], self, *args, **kwargs)

    @functools.wraps(request)
    def measured_request(self: Any, payload: bytes, *args: Any, **kwargs: Any) -> Any:
        token = _STREAM.set(_StreamScope())
        try:
            size = byte_size(payload)
            if size is not None:
                recorder.work("client_stream_exchange_inclusive", "attempted_payload_bytes", size)
            result = recorder.call(request, "client_stream_exchange_inclusive", self, payload, *args, **kwargs)
            if isinstance(result, bytes):
                recorder.work("client_stream_exchange_inclusive", "returned_payload_bytes", len(result))
            return result
        finally:
            _STREAM.reset(token)

    @functools.wraps(snapshot)
    def measured_snapshot(self: Any) -> Any:
        result = recorder.call(snapshot, "client_snapshot_start_or_attestation", self)
        scope = _STREAM.get()
        if scope is not None and result is not None:
            scope.queue = result[2]
        return result

    @functools.wraps(queue_get)
    def measured_get(self: Any, *args: Any, **kwargs: Any) -> Any:
        scope = _STREAM.get()
        if scope is None or self is not scope.queue:
            return queue_get(self, *args, **kwargs)
        result = recorder.call(queue_get, "client_response_wait_inclusive", self, *args, **kwargs)
        if isinstance(result, bytes):
            recorder.work("client_response_wait_inclusive", "delivered_payload_bytes", len(result))
        else:
            recorder.work("client_response_wait_inclusive", "stream_failure_sentinels", 1)
        return result

    targets = (
        (RuntimeHookScheduler, "reserve_bytes", measured_reserve),
        (RuntimeHookScheduler, "acquire", measured_acquire),
        (RuntimeHookScheduler, "_enqueue", measured_enqueue),
        (native_resident_client._PersistentNativeClientPool, "_lease", measured_lease),
        (native_resident_stream._PersistentNativeClient, "request", measured_request),
        (native_resident_stream._PersistentNativeClient, "_request_snapshot", measured_snapshot),
        (threading.Condition, "wait", measured_wait),
        (Queue, "get", measured_get),
    )
    for owner, name, wrapped in targets:
        stack.enter_context(patch.object(owner, name, wrapped))


def frame_writer(function: Any, recorder: Recorder) -> Any:
    @functools.wraps(function)
    def measured(stdin: Any, frame: bytes, **kwargs: Any) -> Any:
        recorder.work("client_frame_write", "attempted_frame_bytes", len(frame))
        result = recorder.call(function, "client_frame_write", stdin, frame, **kwargs)
        if result is True:
            recorder.work("client_frame_write", "completed_frame_bytes", len(frame))
        else:
            # False can follow a partial write, not necessarily zero bytes.
            recorder.work("client_frame_write", "partial_or_unwritten_attempts", 1)
        return result

    return measured
