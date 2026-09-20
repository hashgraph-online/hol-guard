"""Bounded observations of the actual product Windows atomic writer."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any, cast


class _NativeCalls:
    def __init__(self, api: Any):
        self.api = api
        self.handles: set[int] = set()
        self.opens = 0
        self.closes = 0
        self.rename_calls = 0
        self.rename_returned = False
        self.first_failed_operation: str | None = None
        self.volume_queries = 0
        self.volume_query_succeeded: bool | None = None
        self.volume_flags: int | None = None

    def __getattr__(self, name: str) -> Any:
        methods = {
            "CreateFileW": self.create_file,
            "SetFileInformationByHandle": self.rename,
            "CloseHandle": self.close_handle,
            "GetVolumeInformationByHandleW": self.volume_information,
        }
        if name in methods:
            return methods[name]
        return getattr(self.api, name)

    def volume_information(self, *arguments: Any) -> Any:
        self.volume_queries += 1
        result = self.api.GetVolumeInformationByHandleW(*arguments)
        self.volume_query_succeeded = bool(result)
        if result:
            self.volume_flags = int(ctypes.cast(arguments[5], ctypes.POINTER(wintypes.DWORD)).contents.value)
        return result

    def create_file(self, *arguments: Any) -> Any:
        self.opens += 1
        handle = self.api.CreateFileW(*arguments)
        if handle in (None, ctypes.c_void_p(-1).value):
            self.failed("source_open" if arguments[1] & 0x10000 else "parent_open")
        else:
            self.handles.add(int(handle))
        return handle

    def rename(self, *arguments: Any) -> Any:
        self.rename_calls += 1
        result = self.api.SetFileInformationByHandle(*arguments)
        if not result:
            self.failed("rename")
        else:
            self.rename_returned = True
        return result

    def close_handle(self, handle: int) -> Any:
        self.closes += 1
        result = self.api.CloseHandle(handle)
        if result:
            self.handles.discard(int(handle))
        else:
            self.failed("close")
        return result

    def failed(self, operation: str) -> None:
        if self.first_failed_operation is None:
            self.first_failed_operation = operation

    def report(self) -> dict[str, object]:
        return {
            "opens": self.opens,
            "closes": self.closes,
            "rename_calls": self.rename_calls,
            "rename_returned": self.rename_returned,
            "owned_handles_remaining": len(self.handles),
            "first_failed_operation": self.first_failed_operation,
            "volume_queries": self.volume_queries,
            "volume_query_succeeded": self.volume_query_succeeded,
            "volume_flags": self.volume_flags,
        }


class _ProductOs:
    """Observe the actual product's selected operation without replacing it."""

    def __init__(self, original: Any, subject: Any):
        self.original = original
        self.subject = subject
        self.original_ex = subject.replace_once
        self.expected = None
        self.error: BaseException | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)

    def selected_ex(self, source: Path, destination: Path, expected: Any) -> None:
        from codex_plugin_scanner.guard.daemon import manager

        self.expected = expected
        # The existing observer retains one attempt, fd-close proof, a separate
        # source-CRT negative and the exact original returned exception.
        manager.os.replace(source, destination)

    def replace(self, source: Path, destination: Path) -> None:
        try:
            if self.expected is None:
                self.original.replace(source, destination)
            else:
                self.original_ex(source, destination, self.expected)
        except BaseException as error:
            self.error = error
            raise


def _writer(args: Any, original_child: Any, subject: Any, native: _NativeCalls) -> int:
    from ci.native_runtime.windows_atomic_replace_reference import original_write_private_atomic_text
    from codex_plugin_scanner.guard.daemon import manager, manager_pending_launch

    original_os = manager.os
    observer = _ProductOs(original_os, subject)
    original_print = getattr(original_child, "print", print)
    original_writer = manager._write_private_atomic_text
    original_leaf = manager_pending_launch._write_private_atomic_text

    def report_print(value: str, **keywords: Any) -> None:
        report = json.loads(value)
        report["probe"] = native.report()
        report["probe"]["writer_snapshot_taken"] = observer.expected is not None
        report["reference_writer"] = args.original_writer
        if hasattr(args, "writer_audit_events"):
            report["audit_events"] = args.writer_audit_events
            report["refusal_same_object"] = observer.error is args.writer_refusal
        original_print(json.dumps(report, sort_keys=True), **keywords)

    manager.os = cast(Any, observer)
    subject.replace_once = observer.selected_ex
    original_child.print = report_print
    if args.original_writer:
        manager._write_private_atomic_text = original_write_private_atomic_text
        manager_pending_launch._write_private_atomic_text = original_write_private_atomic_text
    try:
        return original_child._writer(args)
    finally:
        manager.os = original_os
        subject.replace_once = observer.original_ex
        original_child.print = original_print
        manager._write_private_atomic_text = original_writer
        manager_pending_launch._write_private_atomic_text = original_leaf


def _audit(args: Any, original_child: Any, probe: Any, native: _NativeCalls) -> int:
    source = args.target.with_name(".rename-audit-source")
    descriptor = os.open(source, os.O_RDONLY)
    try:
        expected = probe.snapshot_descriptor(descriptor)
    finally:
        os.close(descriptor)
    refusal = RuntimeError("synthetic rename audit refusal")
    events: list[dict[str, object]] = []
    observed = None

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event != "os.rename":
            return
        events.append(
            {
                "source_same": arguments[0] == str(source),
                "destination_same": arguments[1] == str(args.target),
                "source_dir_fd": arguments[2],
                "destination_dir_fd": arguments[3],
                "opens_before_event": native.opens,
                "renames_before_event": native.rename_calls,
            }
        )
        if args.refuse:
            raise refusal

    sys.addaudithook(audit)
    try:
        if args.candidate:
            probe.replace_once(source, args.target, expected)
        else:
            os.replace(source, args.target)
    except BaseException as error:
        observed = error
    print(
        json.dumps(
            {
                "schema": 1,
                "operation": "rename_audit",
                "events": events,
                "refusal_same_object": observed is refusal,
                "error": original_child._code(observed),
                "probe": native.report(),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


def _writer_audit(args: Any, original_child: Any, subject: Any, native: _NativeCalls) -> int:
    events: list[dict[str, object]] = []
    refusal = RuntimeError("synthetic original writer audit refusal")

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event != "os.rename" or arguments[1] != str(args.target):
            return
        source = Path(cast(str, arguments[0]))
        events.append(
            {
                "source_same": source.parent == args.target.parent and source.name.startswith(f".{args.target.name}."),
                "destination_same": arguments[1] == str(args.target),
                "source_dir_fd": arguments[2],
                "destination_dir_fd": arguments[3],
                "opens_before_event": native.opens,
                "renames_before_event": native.rename_calls,
            }
        )
        if args.refuse:
            raise refusal

    args.original_writer = not args.candidate
    args.writer_audit_events = events
    args.writer_refusal = refusal
    sys.addaudithook(audit)
    return _writer(args, original_child, subject, native)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--operation", choices=("writer", "writer_audit", "rename_audit", "audit"), required=True)
    parser.add_argument("--hold-crt-source", action="store_true")
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--refuse", action="store_true")
    parser.add_argument("--original-writer", action="store_true")
    parser.add_argument("--route", choices=("bounded", "text"), default="bounded")
    parser.add_argument("--default-mode", choices=("inherited", "text", "binary"), default="inherited")
    parser.add_argument("--audit-switch-default", action="store_true")
    args = parser.parse_args()
    if os.name != "nt" or sys.flags.isolated != 1:
        raise RuntimeError("control_requires_isolated_windows_python")
    source = args.source_root.resolve(strict=True)
    sys.path[:0] = [str(source / "src"), str(source)]
    from ci.native_runtime import windows_replaceable_reader_child as original_child
    from codex_plugin_scanner.guard import windows_atomic_replace as probe

    if args.operation == "audit":
        return original_child._audit(args)
    native = _NativeCalls(probe._api())
    probe._api = lambda: native
    try:
        if args.operation == "writer_audit":
            return _writer_audit(args, original_child, probe, native)
        if args.operation == "writer":
            return _writer(args, original_child, probe, native)
        return _audit(args, original_child, probe, native)
    except BaseException as error:
        print(
            json.dumps(
                {
                    "schema": 1,
                    "operation": "failure",
                    "requested_operation": args.operation,
                    "error": original_child._code(error),
                    "probe": native.report(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
