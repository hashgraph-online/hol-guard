"""Observe the original and candidate Windows CRT translation boundaries.

This diagnostic has no product mutation, timing sample, retry, or qualification
claim. Each invocation performs one declared read in a fresh isolated process.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

_READ_BYTES = 4096
_WTEXT = 0x10000
PAYLOADS = {
    "ascii-no-bom": b"synthetic\r\nvalue\x1a\n",
    "utf8-bom": b"\xef\xbb\xbf" + "synthetic caf\u00e9\r\n".encode("utf-8"),
    "utf16le-bom": b"\xff\xfe" + "synthetic \u03a9\r\n".encode("utf-16-le"),
    "empty": b"",
    "utf8-bom-only": b"\xef\xbb\xbf",
    "utf16le-bom-only": b"\xff\xfe",
}


def _error(error: BaseException | None) -> dict[str, object] | None:
    if error is None:
        return None
    names: dict[type[BaseException], str] = {
        PermissionError: "PermissionError",
        FileNotFoundError: "FileNotFoundError",
        UnicodeDecodeError: "UnicodeDecodeError",
        OSError: "OSError",
        ValueError: "ValueError",
        RuntimeError: "RuntimeError",
    }
    result: dict[str, object] = {"kind": names.get(type(error), "other")}
    for key in ("errno", "winerror"):
        value = getattr(error, key, None)
        result[key] = value if type(value) is int else None
    if isinstance(error, UnicodeDecodeError):
        result["encoding"] = error.encoding if error.encoding in ("utf-8", "utf-16-le") else "other"
        result["start"] = error.start
        result["end"] = error.end
    return result


def _mode(api: Any) -> int:
    value = ctypes.c_int()
    if api._get_fmode(ctypes.byref(value)):
        raise RuntimeError("probe_get_fmode_failed")
    return value.value


def _read(target: Path, *, candidate: bool, route: str, reader: Any) -> bytes | str:
    if route == "text":
        if candidate:
            return reader.read_replaceable_text(target)
        return target.read_text(encoding="utf-8")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    opener = reader.open_replaceable_read_descriptor if candidate else os.open
    descriptor = opener(target, flags)
    try:
        return os.read(descriptor, _READ_BYTES)
    finally:
        os.close(descriptor)


def observe(args: argparse.Namespace) -> dict[str, object]:
    if os.name != "nt" or sys.flags.isolated != 1 or sys.implementation.name != "cpython":
        raise RuntimeError("probe_requires_isolated_windows_cpython")
    source = args.source_root.resolve(strict=True)
    target = args.target.resolve(strict=True)
    expected = PAYLOADS[args.payload]
    with target.open("rb") as stream:
        admitted = stream.read(65)
    if admitted != expected:
        raise RuntimeError("probe_synthetic_input_mismatch")
    sys.path.insert(0, str(source / "src"))
    reader = importlib.import_module("codex_plugin_scanner.guard.windows_replaceable_file")
    if (
        Path(cast(str, reader.__file__)).resolve()
        != source / "src/codex_plugin_scanner/guard/windows_replaceable_file.py"
    ):
        raise RuntimeError("probe_reader_source_mismatch")
    api = reader._crt_api()
    api._set_fmode.argtypes = [ctypes.c_int]
    api._set_fmode.restype = ctypes.c_int
    modes = {"text": os.O_TEXT, "binary": os.O_BINARY, "wtext": _WTEXT}
    original_mode = _mode(api)
    initial_mode = modes[args.initial_mode]
    audit_mode = None if args.audit_mode == "unchanged" else modes[args.audit_mode]
    if api._set_fmode(initial_mode):
        raise RuntimeError("probe_set_initial_mode_failed")
    events: list[dict[str, object]] = []
    refusal = RuntimeError("synthetic audit refusal")
    value = None
    failure: BaseException | None = None
    observed_before = observed_after = None
    restored = False
    cleanup_error: BaseException | None = None
    calls = 0
    target_name = str(target)

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event != "open" or not arguments or arguments[0] != target_name:
            return
        if len(events) >= 2:
            raise RuntimeError("probe_unexpected_extra_open_event")
        before = _mode(api)
        if audit_mode is not None and api._set_fmode(audit_mode):
            raise RuntimeError("probe_audit_mode_switch_failed")
        events.append(
            {
                "event": "open",
                "mode": arguments[1],
                "flags": arguments[2],
                "crt_before": before,
                "crt_after": _mode(api),
            }
        )
        if args.refuse:
            raise refusal

    try:
        sys.addaudithook(audit)
        observed_before = _mode(api)
        calls += 1
        value = _read(target, candidate=args.candidate, route=args.route, reader=reader)
    except BaseException as error:
        failure = error
    finally:
        try:
            observed_after = _mode(api)
        except BaseException as error:
            cleanup_error = error
        try:
            restored = api._set_fmode(original_mode) == 0 and _mode(api) == original_mode
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error

    projection = None
    if value is not None:
        encoded = value if isinstance(value, bytes) else value.encode("utf-8")
        projection = {
            "kind": "bytes" if isinstance(value, bytes) else "text",
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    return {
        "schema": "windows-wtext-acceptance-observation.v1",
        "scope": "single original or candidate reader boundary; not installed qualification",
        "candidate": bool(args.candidate),
        "route": args.route,
        "payload": args.payload,
        "input_bytes": len(expected),
        "input_sha256": hashlib.sha256(expected).hexdigest(),
        "read_bound_bytes": _READ_BYTES if args.route == "bounded" else None,
        "reader_import_binding_verified": True,
        "initial_mode": initial_mode,
        "mode_before_call": observed_before,
        "mode_after_call": observed_after,
        "audit_mode": audit_mode,
        "audit_refuse": bool(args.refuse),
        "events": events,
        "operation_calls": calls,
        "result": projection,
        "error": _error(failure),
        "refusal_same_object": failure is refusal,
        "default_mode_restored": restored,
        "cleanup_error": _error(cleanup_error),
        "observation_complete": calls == 1 and len(events) == 1 and restored and cleanup_error is None,
        "qualification": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--payload", choices=tuple(PAYLOADS), required=True)
    parser.add_argument("--route", choices=("bounded", "text"), required=True)
    parser.add_argument("--initial-mode", choices=("text", "binary", "wtext"), required=True)
    parser.add_argument("--audit-mode", choices=("unchanged", "text", "binary", "wtext"), default="unchanged")
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--refuse", action="store_true")
    args = parser.parse_args()
    try:
        report = observe(args)
    except BaseException as error:
        report = {
            "schema": "windows-wtext-acceptance-observation.v1",
            "observation_complete": False,
            "setup_or_observer_error": _error(error),
            "qualification": False,
        }
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["observation_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
