"""Bounded work counts at real serializer, pipe, hash and HTTP I/O boundaries."""

from __future__ import annotations

import functools
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

from scripts.native_slo_phase_calls import ModuleProbe, byte_size, hashlib_probe, json_probe
from scripts.native_slo_phase_waits import frame_writer


class _IOProbe:
    def __init__(self, target: Any, recorder: Any) -> None:
        self._target, self._recorder = target, recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._target, name)

    def read1(self, *args: Any, **kwargs: Any) -> Any:
        result = self._recorder.call(self._target.read1, "http_body_read", *args, **kwargs)
        size = byte_size(result)
        if size is not None:
            self._recorder.work("http_body_read", "returned_bytes", size)
        return result

    def write(self, data: Any) -> Any:
        size = byte_size(data)
        if size is not None:
            self._recorder.work("http_response_write", "attempted_bytes", size)
        result = self._recorder.call(self._target.write, "http_response_write", data)
        if type(result) is int and result >= 0:
            self._recorder.work("http_response_write", "written_bytes", result)
        else:
            self._recorder.work("http_response_write", "unknown_written_count", 1)
        return result


def _io_method(function: Any, recorder: Any, attribute: str, phase: str) -> Any:
    @functools.wraps(function)
    def measured(self: Any, *args: Any, **kwargs: Any) -> Any:
        # Handler instances belong to one HTTP request thread. Preserve the
        # exact original stream even when the underlying function raises.
        with patch.object(self, attribute, _IOProbe(getattr(self, attribute), recorder)):
            return recorder.call(function, phase, self, *args, **kwargs)

    return measured


def _encoded_result(function: Any, recorder: Any, phase: str) -> Any:
    @functools.wraps(function)
    def measured(*args: Any, **kwargs: Any) -> Any:
        result = recorder.call(function, phase, *args, **kwargs)
        size = byte_size(result)
        if size is not None:
            recorder.work(phase, "returned_bytes", size)
        return result

    return measured


def install_io_probes(stack: ExitStack, recorder: Any) -> None:
    from codex_plugin_scanner.guard import (
        native_hook_edge,
        native_resident_stream,
        native_runtime,
        native_runtime_identity,
    )
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal, server

    for owner, prefix in (
        (native_hook_edge, "edge"),
        (server, "daemon"),
        (runtime_hook_evidence_journal, "evidence"),
    ):
        stack.enter_context(patch.object(owner, "json", json_probe(owner.json, recorder, prefix)))
    # Avoid replacing server.hashlib: hmac.new(..., hashlib.sha256) would
    # select a different HMAC implementation if passed a wrapped constructor.
    for owner, prefix in ((native_runtime, "runtime"), (native_runtime_identity, "runtime_manifest")):
        stack.enter_context(patch.object(owner, "hashlib", hashlib_probe(owner.hashlib, recorder, prefix)))

    struct_module = native_resident_stream.struct

    def pack(*args: Any, **kwargs: Any) -> Any:
        result = recorder.call(struct_module.pack, "client_frame_header_pack", *args, **kwargs)
        recorder.work("client_frame_header_pack", "returned_bytes", len(result))
        return result

    def unpack(*args: Any, **kwargs: Any) -> Any:
        # The persistent reader does not inherit a request's ContextVar and
        # may outlive several requests. Keep its count explicitly unassigned.
        return recorder.reader_call(struct_module.unpack, "client_frame_header_unpack", *args, **kwargs)

    stack.enter_context(
        patch.object(native_resident_stream, "struct", ModuleProbe(struct_module, {"pack": pack, "unpack": unpack}))
    )

    process_module = native_resident_stream.subprocess

    def spawn(*args: Any, **kwargs: Any) -> Any:
        return recorder.call(process_module.Popen, "client_process_spawn", *args, **kwargs)

    stack.enter_context(
        patch.object(native_resident_stream, "subprocess", ModuleProbe(process_module, {"Popen": spawn}))
    )
    stack.enter_context(
        patch.object(native_resident_stream, "write_frame", frame_writer(native_resident_stream.write_frame, recorder))
    )
    handler = server._GuardDaemonHandler
    targets = (
        (native_hook_edge, "_encode_hook_envelope", "envelope_encode"),
        (runtime_hook_evidence_journal._NativeDecisionReceiptRecord, "serialized", "receipt_record_serialization"),
    )
    for owner, name, phase in targets:
        stack.enter_context(patch.object(owner, name, _encoded_result(getattr(owner, name), recorder, phase)))
    stack.enter_context(
        patch.object(
            handler,
            "_read_request_body",
            _io_method(handler._read_request_body, recorder, "rfile", "http_body_read_inclusive"),
        )
    )
    stack.enter_context(
        patch.object(
            handler, "_write_json", _io_method(handler._write_json, recorder, "wfile", "response_encode_write")
        )
    )
