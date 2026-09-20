from __future__ import annotations

import builtins
import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import private_file_io
from codex_plugin_scanner.guard import windows_replaceable_file as replaceable
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth
from codex_plugin_scanner.guard.daemon import manager

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Real Windows sharing and audit semantics")
_CONTROL_SECONDS = 5.0
_ROOT = Path(__file__).resolve().parents[1]
_CHILD = _ROOT / "ci/native_runtime/windows_atomic_replace_child.py"
_OLD = "synthetic-before-token"
_NEW = "synthetic-after-token"


def _unique_child_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("control_child_duplicate_key")
        result[key] = value
    return result


def _safe_child_value(value, depth=0):
    if depth > 6:
        return False
    if value is None or type(value) in (bool, int):
        return True
    if isinstance(value, str):
        return value in {
            "writer",
            "audit",
            "failure",
            "bytes",
            "text",
            "r",
            "PermissionError",
            "OSError",
            "other",
            "crt_binding",
            "crt_default",
            "win32_binding",
            "verified_native_open",
            "crt_transfer",
            "parent_open",
            "source_open",
            "rename",
            "close",
        } or (len(value) == 64 and all(char in "0123456789abcdef" for char in value))
    if isinstance(value, list):
        return len(value) <= 32 and all(_safe_child_value(item, depth + 1) for item in value)
    keys = {
        "schema",
        "operation",
        "requested_operation",
        "origins",
        "writer_calls",
        "writer_locked",
        "replace_calls",
        "writer_fd_closed_before_replace",
        "source_reader_opened",
        "source_reader_closed",
        "replace_returned",
        "original_exception_identity_preserved",
        "error",
        "temporary_siblings_removed",
        "kind",
        "errno",
        "winerror",
        "events",
        "mode",
        "flags",
        "refusal_same_object",
        "result",
        "utf8_or_raw_bytes",
        "sha256",
        "default_mode",
        "post_audit_default_mode",
        "default_mode_restored",
        "probe",
        "opens",
        "closes",
        "rename_calls",
        "rename_returned",
        "owned_handles_remaining",
        "first_failed_operation",
        "writer_snapshot_taken",
        "reference_writer",
        "volume_queries",
        "volume_query_succeeded",
        "volume_flags",
        "audit_events",
        "source_same",
        "destination_same",
        "source_dir_fd",
        "destination_dir_fd",
        "opens_before_event",
        "renames_before_event",
    }
    return (
        isinstance(value, dict)
        and set(value) <= keys
        and all(_safe_child_value(item, depth + 1) for item in value.values())
    )


def _error_metadata(error):
    if error is None:
        return None
    kind = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "other"
    if isinstance(error, OSError):
        kind = "OSError"
    return {"kind": kind, "errno": getattr(error, "errno", None), "winerror": getattr(error, "winerror", None)}


def _child_capture(stdout, stderr, code, failure, killed, retired):
    return {
        "return_code": code,
        "timed_out": isinstance(failure, subprocess.TimeoutExpired),
        "transport_error": _error_metadata(failure),
        "kill_requested": killed,
        "process_retired": retired,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stderr_content_retained": False,
        "stdout_content": None,
    }


def _run_child(target: Path, *arguments: str, record_property, label: str):
    command = [
        sys.executable,
        "-I",
        str(_CHILD),
        "--source-root",
        str(_ROOT),
        "--target",
        str(target),
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
    except BaseException as error:
        record_property(
            f"child_capture_{label}",
            json.dumps(
                {
                    "spawned": False,
                    "process_retired": True,
                    "error": _error_metadata(error),
                },
                sort_keys=True,
            ),
        )
        raise
    failure = None
    stdout = stderr = b""
    killed = False
    cleanup_failure = None
    timeout_partial = None
    try:
        stdout, stderr = process.communicate(timeout=_CONTROL_SECONDS)
    except BaseException as error:
        failure = error
        if isinstance(error, subprocess.TimeoutExpired):
            stdout, stderr = error.output or b"", error.stderr or b""
            timeout_partial = _child_capture(stdout, stderr, None, error, False, False)
    finally:
        if process.poll() is None:
            try:
                killed = True
                process.kill()
                stdout, stderr = process.communicate(timeout=_CONTROL_SECONDS)
            except BaseException as cleanup_error:
                cleanup_failure = _error_metadata(cleanup_error)
                if failure is None:
                    failure = cleanup_error
                else:
                    replaceable._note_cleanup_failure(failure, "control_child_cleanup_failed")
    capture = _child_capture(stdout, stderr, process.returncode, failure, killed, process.poll() is not None)
    capture["timeout_partial"] = timeout_partial
    capture["cleanup_error"] = cleanup_failure
    report = None
    parse_failure = None
    try:
        if len(stdout) > 8192:
            raise RuntimeError("control_child_output_limit")
        report = json.loads(stdout, object_pairs_hook=_unique_child_object)
        if not isinstance(report, dict) or not _safe_child_value(report):
            raise RuntimeError("control_child_report_invalid")
        capture["stdout_content"] = stdout.decode("utf-8")
    except (ValueError, RuntimeError) as error:
        parse_failure = error
    capture["report_valid"] = parse_failure is None
    record_property(f"child_capture_{label}", json.dumps(capture, sort_keys=True))
    if failure is not None:
        raise failure
    if parse_failure is not None:
        raise parse_failure
    if stderr:
        raise RuntimeError("control_child_stderr_observed")
    return process.returncode, report


class _HeldRead:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.closed = threading.Event()
        self.owner: int | None = None
        self.descriptor: int | None = None
        self.inheritable: bool | None = None
        self.identity: tuple[int, int] | None = None

    def pause(self, descriptor):
        if threading.get_ident() != self.owner or self.descriptor is not None:
            return
        self.descriptor = descriptor
        self.inheritable = os.get_inheritable(descriptor)
        metadata = os.fstat(descriptor)
        self.identity = metadata.st_dev, metadata.st_ino
        self.entered.set()
        if not self.release.wait(_CONTROL_SECONDS):
            raise TimeoutError("control_reader_release_timeout")


class _ReaderOs:
    def __init__(self, held):
        self.held = held

    def __getattr__(self, name):
        return getattr(os, name)

    def read(self, descriptor, maximum):
        self.held.pause(descriptor)
        return os.read(descriptor, maximum)

    def close(self, descriptor):
        os.close(descriptor)
        if descriptor == self.held.descriptor and threading.get_ident() == self.held.owner:
            self.held.closed.set()


class _TextRead:
    def __init__(self, handle, held):
        self.handle = handle
        self.held = held

    def __enter__(self):
        self.handle.__enter__()
        return self

    def read(self):
        self.held.pause(self.handle.fileno())
        return self.handle.read()

    def __exit__(self, *arguments):
        try:
            return self.handle.__exit__(*arguments)
        finally:
            if self.handle.closed:
                self.held.closed.set()


@pytest.mark.parametrize("route", ["bounded_manager", "codex_text"])
@pytest.mark.parametrize("hold_crt_source", [False, True], ids=["destination_only", "separate_crt_source"])
def test_actual_readers_allow_other_process_atomic_product_writer(
    tmp_path,
    monkeypatch,
    record_property,
    route,
    hold_crt_source,
):
    assert Path(private_file_io.__file__).resolve() == _ROOT / "src/codex_plugin_scanner/guard/private_file_io.py"
    assert Path(replaceable.__file__).resolve() == _ROOT / "src/codex_plugin_scanner/guard/windows_replaceable_file.py"
    home = tmp_path / "guard"
    manager._ensure_private_directory(home)
    target = home / "daemon-auth-token"
    manager._write_private_atomic_text(target, _OLD)
    before = target.stat()
    old_identity = before.st_dev, before.st_ino
    held = _HeldRead()
    values = queue.Queue(maxsize=1)
    errors = queue.Queue(maxsize=1)

    def read():
        held.owner = threading.get_ident()
        try:
            if route == "bounded_manager":
                value = manager.load_guard_daemon_auth_token(home)
            else:
                value = codex_daemon_hook_auth._private_file_text(target, label="token")
            values.put_nowait(value)
        except BaseException as error:
            errors.put_nowait(error)

    def open_text(path, *arguments, **keywords):
        # The returned handle is owned by the original caller's context manager.
        handle = builtins.open(path, *arguments, **keywords)  # noqa: SIM115
        if Path(path) == target and threading.get_ident() == held.owner:
            return _TextRead(handle, held)
        return handle

    thread = threading.Thread(target=read, name="owned-source-reader", daemon=True)
    report = None
    code = None
    held_after_child = False
    old_handle_after_child = False
    with monkeypatch.context() as patch:
        patch.setattr(private_file_io, "os", _ReaderOs(held))
        patch.setattr(replaceable, "open", open_text, raising=False)
        thread.start()
        try:
            if not held.entered.wait(_CONTROL_SECONDS):
                raise TimeoutError("control_reader_ready_timeout")
            if held.descriptor is None:
                raise RuntimeError("control_reader_descriptor_missing")
            extra = ["--hold-crt-source"] if hold_crt_source else []
            code, report = _run_child(
                target,
                "--operation",
                "writer",
                *extra,
                record_property=record_property,
                label="writer",
            )
            held_after_child = thread.is_alive() and not held.closed.is_set()
            after = os.fstat(held.descriptor)
            old_handle_after_child = (after.st_dev, after.st_ino) == old_identity
        finally:
            held.release.set()
            thread.join(_CONTROL_SECONDS)
            record_property("reader_retired", not thread.is_alive())
            record_property("reader_descriptor_closed", held.closed.is_set())
            record_property("writer_is_separate_process", True)
            record_property("source_crt_negative_control", hold_crt_source)
            record_property("writer_exit_code", code)
            record_property("writer_report", json.dumps(report, sort_keys=True))
    assert not thread.is_alive()
    assert errors.empty()
    assert held.closed.is_set()
    assert held.inheritable is False
    assert held.identity == old_identity
    assert held_after_child and old_handle_after_child
    assert values.get_nowait() == _OLD
    assert report is not None
    assert report["writer_calls"] == report["replace_calls"] == 1
    assert report["writer_locked"] and report["writer_fd_closed_before_replace"]
    assert report["source_reader_opened"] is hold_crt_source
    assert report["source_reader_closed"] is hold_crt_source
    assert report["temporary_siblings_removed"]
    assert report["original_exception_identity_preserved"]
    assert report["reference_writer"] is False
    native = report["probe"]
    assert native["writer_snapshot_taken"] is True
    assert native["volume_queries"] == 1 and native["volume_query_succeeded"] is True
    assert native["volume_flags"] & 0x400
    assert native["opens"] == 2 and native["closes"] == (1 if hold_crt_source else 2)
    assert native["rename_calls"] == int(not hold_crt_source)
    assert native["rename_returned"] is not hold_crt_source
    assert native["owned_handles_remaining"] == 0
    assert native["first_failed_operation"] == ("source_open" if hold_crt_source else None)
    if hold_crt_source:
        assert code == 1
        assert report["replace_returned"] is False
        assert report["error"] == {"kind": "PermissionError", "errno": 13, "winerror": 32}
        assert target.read_text(encoding="utf-8") == _OLD
    else:
        assert code == 0
        assert report["replace_returned"] is True
        assert report["error"] is None
        assert target.read_text(encoding="utf-8") == _NEW
        current = target.stat()
        assert (current.st_dev, current.st_ino) != old_identity
    assert not list(home.glob(".daemon-auth-token.*"))


def _compare_original_audit(tmp_path, record_property, default_mode, route, refuse, switch_default=False):
    target = tmp_path / "authority"
    target.write_bytes(b"synthetic\r\nvalue\x1a\n")
    extra = ["--default-mode", default_mode]
    if refuse:
        extra.append("--refuse")
    if switch_default:
        extra.append("--audit-switch-default")
    original_code, original = _run_child(
        target,
        "--operation",
        "audit",
        "--route",
        route,
        *extra,
        record_property=record_property,
        label="original",
    )
    candidate_code, candidate = _run_child(
        target,
        "--operation",
        "audit",
        "--route",
        route,
        "--candidate",
        *extra,
        record_property=record_property,
        label="candidate",
    )
    record_property("original_exit_code", original_code)
    record_property("candidate_exit_code", candidate_code)
    record_property("original_report", json.dumps(original, sort_keys=True))
    record_property("candidate_report", json.dumps(candidate, sort_keys=True))
    assert original_code == candidate_code == 0
    assert isinstance(original, dict)
    assert isinstance(candidate, dict)
    assert candidate == original
    assert len(candidate["events"]) == 1
    assert candidate["refusal_same_object"] is refuse
    assert candidate["default_mode_restored"] is True
    assert candidate["post_audit_default_mode"] is not None
    if switch_default:
        expected = os.O_BINARY if candidate["default_mode"] == os.O_TEXT else os.O_TEXT
        assert candidate["post_audit_default_mode"] == expected
    if default_mode != "inherited":
        assert candidate["default_mode"] == {"text": os.O_TEXT, "binary": os.O_BINARY}[default_mode]
    if refuse:
        assert candidate["result"] is None
    else:
        assert candidate["error"] is None
        assert original["result"] is not None
        assert original["result"]["utf8_or_raw_bytes"] > 0


@pytest.mark.parametrize("default_mode", ["inherited", "text", "binary"])
@pytest.mark.parametrize("route", ["bounded", "text"])
@pytest.mark.parametrize("refuse", [False, True], ids=["observe", "refuse"])
def test_real_python_audit_matches_original_once(tmp_path, record_property, default_mode, route, refuse):
    _compare_original_audit(tmp_path, record_property, default_mode, route, refuse)


@pytest.mark.parametrize("default_mode", ["text", "binary"])
@pytest.mark.parametrize("route", ["bounded", "text"])
def test_real_python_audit_hook_mode_change_matches_original(tmp_path, record_property, default_mode, route):
    _compare_original_audit(tmp_path, record_property, default_mode, route, False, switch_default=True)
