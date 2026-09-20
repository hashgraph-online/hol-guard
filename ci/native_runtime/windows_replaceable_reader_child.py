"""Bounded child for source-only Windows reader regression controls."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

_OLD = "synthetic-before-token"
_NEW = "synthetic-after-token"


def _code(error: BaseException | None) -> dict[str, object] | None:
    if error is None:
        return None
    kind = "other"
    if type(error) is PermissionError:
        kind = "PermissionError"
    elif isinstance(error, OSError):
        kind = "OSError"
    return {"kind": kind, "errno": getattr(error, "errno", None), "winerror": getattr(error, "winerror", None)}


class _WriterOs:
    def __init__(self, original, target: Path, hold_source: bool):
        self.original = original
        self.target = target
        self.hold_source = hold_source
        self.closed = []
        self.replace_calls = 0
        self.writer_fd_closed = False
        self.source_reader_opened = False
        self.source_reader_closed = False
        self.replace_returned = False
        self.error: BaseException | None = None

    def __getattr__(self, name):
        return getattr(self.original, name)

    def close(self, descriptor):
        self.original.close(descriptor)
        self.closed.append(descriptor)

    def replace(self, source, destination):
        self.replace_calls += 1
        if self.replace_calls != 1 or Path(destination) != self.target or not self.closed:
            raise RuntimeError("control_writer_boundary_invalid")
        try:
            self.original.fstat(self.closed[-1])
        except OSError as error:
            self.writer_fd_closed = error.errno == errno.EBADF
        if not self.writer_fd_closed:
            raise RuntimeError("control_writer_descriptor_still_open")
        descriptor = None
        try:
            if self.hold_source:
                # An intentionally noncooperating CRT source handle is a separate
                # negative control. No source reader is opened by the product fix.
                descriptor = self.original.open(source, self.original.O_RDONLY)
                self.source_reader_opened = True
            try:
                self.original.replace(source, destination)
            except BaseException as error:
                self.error = error
                raise
            self.replace_returned = True
        finally:
            if descriptor is not None:
                self.original.close(descriptor)
                self.source_reader_closed = True


def _writer(args) -> int:
    from codex_plugin_scanner.guard.daemon import manager, manager_pending_launch

    original = manager.os
    observer = _WriterOs(original, args.target, args.hold_crt_source)
    failure = None
    locked = False
    writer_calls = 0
    if manager._write_private_atomic_text is not manager_pending_launch._write_private_atomic_text:
        raise RuntimeError("control_writer_alias_mismatch")
    manager.os = cast(Any, observer)
    try:
        with manager._guard_daemon_state_write_lock(args.target.parent):
            locked = True
            writer_calls += 1
            manager._write_private_atomic_text(args.target, _NEW)
    except BaseException as error:
        failure = error
    finally:
        manager.os = original
    report = {
        "schema": 1,
        "operation": "writer",
        "writer_calls": writer_calls,
        "writer_locked": locked,
        "replace_calls": observer.replace_calls,
        "writer_fd_closed_before_replace": observer.writer_fd_closed,
        "source_reader_opened": observer.source_reader_opened,
        "source_reader_closed": observer.source_reader_closed,
        "replace_returned": observer.replace_returned,
        "original_exception_identity_preserved": failure is None or failure is observer.error,
        "error": _code(failure),
        "temporary_siblings_removed": not list(args.target.parent.glob(".daemon-auth-token.*")),
    }
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if failure is None else 1


def _audit(args) -> int:
    from codex_plugin_scanner.guard import windows_replaceable_file as reader

    crt = reader._crt_api()
    mode = ctypes.c_int()
    if crt._get_fmode(ctypes.byref(mode)):
        raise RuntimeError("control_get_default_mode_failed")
    original_mode = mode.value
    setter = crt._set_fmode
    setter.argtypes = [ctypes.c_int]
    setter.restype = ctypes.c_int
    requested = {"text": os.O_TEXT, "binary": os.O_BINARY}.get(args.default_mode)
    if requested is not None and setter(requested):
        raise RuntimeError("control_set_default_mode_failed")
    active = ctypes.c_int()
    if crt._get_fmode(ctypes.byref(active)):
        raise RuntimeError("control_confirm_default_mode_failed")
    target = args.target
    events = []
    refusal = RuntimeError("synthetic audit refusal")
    observed = None
    payload = None

    def hook(event, arguments):
        if event == "open" and isinstance(arguments[0], (str, os.PathLike)) and os.fspath(arguments[0]) == str(target):
            events.append({"mode": arguments[1], "flags": arguments[2]})
            if args.audit_switch_default:
                switched = os.O_BINARY if active.value == os.O_TEXT else os.O_TEXT
                if setter(switched):
                    raise RuntimeError("control_audit_default_switch_failed")
            if args.refuse:
                raise refusal

    sys.addaudithook(hook)
    try:
        if args.route == "bounded":
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            opener = reader.open_replaceable_read_descriptor if args.candidate else os.open
            descriptor = opener(target, flags)
            try:
                payload = os.read(descriptor, 4096)
            finally:
                os.close(descriptor)
        elif args.candidate:
            payload = reader.read_replaceable_text(target)
        else:
            payload = target.read_text(encoding="utf-8")
    except BaseException as error:
        observed = error
    finally:
        observed_mode = ctypes.c_int()
        mode_query_succeeded = crt._get_fmode(ctypes.byref(observed_mode)) == 0
        restored = setter(original_mode) == 0
    projection = None
    if payload is not None:
        encoded = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        projection = {
            "kind": "bytes" if isinstance(payload, bytes) else "text",
            "utf8_or_raw_bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    print(
        json.dumps(
            {
                "schema": 1,
                "operation": "audit",
                "events": events,
                "refusal_same_object": observed is refusal,
                "result": projection,
                "default_mode": active.value,
                "post_audit_default_mode": observed_mode.value if mode_query_succeeded else None,
                "default_mode_restored": restored,
                "error": _code(observed),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


def _failure_origins(error: BaseException) -> list[str]:
    module = sys.modules.get("codex_plugin_scanner.guard.windows_replaceable_file")
    identities = {}
    for name, label in (
        ("_crt_api", "crt_binding"),
        ("_default_translation_mode", "crt_default"),
        ("_file_api", "win32_binding"),
        ("_open_descriptor", "verified_native_open"),
        ("_transfer_descriptor", "crt_transfer"),
    ):
        function = getattr(module, name, None)
        code = getattr(getattr(function, "__wrapped__", function), "__code__", None)
        if code is not None:
            identities[code] = label
    found = []
    traceback = error.__traceback__
    for _index in range(32):
        if traceback is None:
            break
        label = identities.get(traceback.tb_frame.f_code)
        if label is not None and label not in found:
            found.append(label)
        traceback = traceback.tb_next
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--operation", choices=("writer", "audit"), required=True)
    parser.add_argument("--hold-crt-source", action="store_true")
    parser.add_argument("--route", choices=("bounded", "text"), default="bounded")
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--refuse", action="store_true")
    parser.add_argument("--default-mode", choices=("inherited", "text", "binary"), default="inherited")
    parser.add_argument("--audit-switch-default", action="store_true")
    args = parser.parse_args()
    if os.name != "nt" or sys.flags.isolated != 1:
        raise RuntimeError("control_requires_isolated_windows_python")
    source = args.source_root.resolve(strict=True)
    sys.path.insert(0, str(source / "src"))
    try:
        if args.operation == "writer":
            return _writer(args)
        return _audit(args)
    except BaseException as error:
        print(
            json.dumps(
                {
                    "schema": 1,
                    "operation": "failure",
                    "requested_operation": args.operation,
                    "error": _code(error),
                    "origins": _failure_origins(error),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
