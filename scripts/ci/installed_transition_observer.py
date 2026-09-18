"""Passive producer diagnostics; these records never qualify a transition."""

from __future__ import annotations

import atexit
import json
import os
import sys
import threading
import time
from pathlib import Path
from types import BuiltinFunctionType, CodeType, FrameType
from typing import Any

from scripts.ci.installed_transition_observer_support import (
    CONFIG_ENV,
    MAX_LEDGER_BYTES,
    MAX_RECORDS,
    file_digest,
    identity,
    observer_directory,
    operation_metadata,
    private_directory,
    result_metadata,
)

_observer: Observer | None = None
_PROCESS_EVENTS = frozenset(
    {"os.fork", "os.forkpty", "os.posix_spawn", "os.spawn", "os.exec", "os.system", "os.startfile"}
)
_ENTRY_EVENTS = {
    "native_resident_client_request": "native_client_entry",
    "_send_review_to_slot": "review_send_entry",
}
_CLEANUP_FUNCTIONS = frozenset({"retire_worker_slot", "close_contained", "_finish_service", "_finish_service_locked"})


class Observer:
    """One synchronous ledger, installed without replacing application functions."""

    def __init__(self, directory: Path, run_id: str, role: str) -> None:
        self.directory = directory
        self.run_id = run_id
        self.pid = os.getpid()
        self.errors: set[str] = set()
        self.sequence = 0
        self.byte_count = 0
        self.sealed = False
        self.installing = True
        self.self_test_seen = False
        self.lock = threading.RLock()
        self.calls: dict[int, tuple[int, str, dict[str, Any]]] = {}
        self.next_call = 0
        self.audit_callback = self.audit
        self.monitor_id = None
        self.monitor_events = (
            sys.monitoring.events.PY_START
            | sys.monitoring.events.PY_RETURN
            | sys.monitoring.events.CALL
            | sys.monitoring.events.RAISE
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        self.descriptor = os.open(directory / f"{self.pid}.jsonl", flags, 0o600)
        self.emit(
            "registered",
            role=role,
            parent_pid=os.getppid(),
            **identity(self.pid),
            observer_sha256=file_digest(__file__),
            python_sha256=file_digest(sys.executable),
            interpreter_version="_".join(map(str, sys.version_info[:3])),
            run_id=run_id,
        )
        previous_profile = sys.getprofile()
        previous_thread_profile = threading.getprofile()
        sys.addaudithook(self.audit_callback)
        sys.audit("hol_guard.transition_observer.selftest", run_id, self.pid)
        if not self.self_test_seen:
            self.errors.add("audit_registration_unconfirmed")
        if previous_profile is not None or previous_thread_profile is not None:
            self.errors.add("existing_profile_preserved")
        for tool_id in (3, 4):
            if sys.monitoring.get_tool(tool_id) is None:
                sys.monitoring.use_tool_id(tool_id, "transition_producer_diagnostics")
                for event, callback in (
                    (sys.monitoring.events.PY_START, self.python_start),
                    (sys.monitoring.events.PY_RETURN, self.python_return),
                    (sys.monitoring.events.CALL, self.called),
                    (sys.monitoring.events.C_RAISE, self.c_raised),
                    (sys.monitoring.events.RAISE, self.raised),
                ):
                    sys.monitoring.register_callback(tool_id, event, callback)
                sys.monitoring.set_events(tool_id, self.monitor_events)
                self.monitor_id = tool_id
                break
        if self.monitor_id is None:
            self.errors.add("exception_monitor_unavailable")
        self.installing = False
        self.emit(
            "observer_ready",
            audit_confirmed=self.self_test_seen,
            execution_monitor_confirmed=self.monitor_id is not None,
        )
        # multiprocessing clears its own Finalize registry during bootstrap.
        atexit.register(self.finish)

    def emit(self, kind: str, **fields: object) -> None:
        try:
            with self.lock:
                if self.sealed:
                    self.errors.add("activity_after_seal")
                if self.sequence >= MAX_RECORDS - 1 and kind != "sealed":
                    self.errors.add("record_limit_exceeded")
                    return
                record = {
                    "sequence": self.sequence + 1,
                    "event": kind,
                    "pid": self.pid,
                    "thread_id": threading.get_ident(),
                    "at_ns": time.monotonic_ns(),
                    **fields,
                }
                encoded = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode()
                if self.byte_count + len(encoded) > MAX_LEDGER_BYTES:
                    self.errors.add("ledger_limit_exceeded")
                    return
                if os.write(self.descriptor, encoded) != len(encoded):
                    self.errors.add("ledger_partial_write")
                    return
                self.sequence += 1
                self.byte_count += len(encoded)
        except Exception:
            self.errors.add("ledger_write_failed")

    def audit(self, event: str, arguments: tuple[object, ...]) -> None:
        try:
            if event == "hol_guard.transition_observer.selftest" and arguments == (self.run_id, self.pid):
                self.self_test_seen = True
            elif event == "subprocess.Popen":
                self.emit("subprocess_intent", **operation_metadata(arguments[1] if len(arguments) > 1 else None))
            elif event in _PROCESS_EVENTS:
                self.emit("process_launch_attempt", launch_api=event)
            elif (
                event in {"sys.setprofile", "sys.settrace", "sys.monitoring.register_callback"} and not self.installing
            ):
                self.errors.add("execution_observer_changed")
                self.emit("observer_changed", observer_api=event)
            elif event in {"cpython.PyInterpreterState_New", "cpython._PySys_ClearAuditHooks"}:
                self.errors.add("interpreter_coverage_changed")
                self.emit("interpreter_changed", observer_api=event)
        except Exception:
            self.errors.add("audit_callback_failed")

    def profile(self, frame: FrameType, event: str, value: object) -> None:
        try:
            name = frame.f_code.co_name
            module = frame.f_globals.get("__name__", "")
            if event == "c_call" and getattr(value, "__name__", "") in {"fork_exec", "CreateProcess"}:
                caller: FrameType | None = frame
                owner_call_id = None
                for _ in range(32):
                    if caller is None:
                        break
                    entry = self.calls.get(id(caller))
                    if entry is not None and entry[1] in {"spawnv_passfds", "__init__"}:
                        owner_call_id = entry[0]
                        break
                    caller = caller.f_back
                self.emit(
                    "process_launch_attempt",
                    launch_api=getattr(value, "__name__", "unknown"),
                    owner_call_id=owner_call_id,
                )
                return
            if event == "c_exception" and getattr(value, "__name__", "") in {"fork_exec", "CreateProcess"}:
                self.errors.add("low_level_launch_exception")
                self.emit("process_launch_exception")
                return
            if event == "c_call" and getattr(value, "__name__", "") == "start_new_thread":
                self.emit("thread_creation_attempt", standard_threading=module == "threading")
                if module != "threading":
                    self.errors.add("nonstandard_thread_creation")
                return
            if event == "call" and name in _ENTRY_EVENTS:
                self.emit(_ENTRY_EVENTS[name], code_sha256=file_digest(frame.f_code.co_filename))
                return
            if event == "call" and name == "_require_snapshot_mapping_fields_v3":
                self.emit("snapshot_validator_entry", code_sha256=file_digest(frame.f_code.co_filename))
                return
            if event == "call" and self.watched(name, module):
                self.begin_call(frame, name, module)
            elif event == "return" and id(frame) in self.calls:
                self.end_call(frame, value)
        except Exception:
            self.errors.add("profile_callback_failed")

    def python_start(self, code: CodeType, _offset: int) -> None:
        self.execution_event(code, "call", None)

    def python_return(self, code: CodeType, _offset: int, returned: object) -> None:
        self.execution_event(code, "return", returned)

    def called(self, code: CodeType, _offset: int, function: object, _arg0: object) -> None:
        if type(function) is BuiltinFunctionType and function.__name__ in {
            "fork_exec",
            "CreateProcess",
            "start_new_thread",
        }:
            self.execution_event(code, "c_call", function)

    def c_raised(self, code: CodeType, _offset: int, function: object, _arg0: object) -> None:
        if type(function) is BuiltinFunctionType and function.__name__ in {"fork_exec", "CreateProcess"}:
            self.execution_event(code, "c_exception", function)

    def execution_event(self, code: CodeType, event: str, value: object) -> None:
        try:
            # The monitoring callback's caller is the application frame; this
            # adapter adds one frame but never replaces that application's code.
            frame = sys._getframe(2)
            if frame.f_code is code:
                self.profile(frame, event, value)
            else:
                self.errors.add("monitor_frame_identity_unconfirmed")
        except Exception:
            self.errors.add("execution_monitor_failed")

    def raised(self, code: CodeType, _offset: int, error: BaseException) -> None:
        try:
            if code.co_name != "_require_snapshot_mapping_fields_v3":
                return
            if type(error).__name__ == "NativePolicySnapshotError" and error.args == (
                "native_policy_snapshot_unknown_field",
            ):
                caller: FrameType | None = sys._getframe(1)
                cached_frame = False
                for _ in range(32):
                    if caller is None:
                        break
                    cached_frame = cached_frame or caller.f_code.co_name == "_cached_snapshot_v3"
                    caller = caller.f_back
                self.emit(
                    "snapshot_unknown_field_raised",
                    rejection_code="native_policy_snapshot_unknown_field",
                    cached_snapshot_frame_seen=cached_frame,
                    code_sha256=file_digest(code.co_filename),
                )
        except Exception:
            self.errors.add("exception_monitor_failed")

    @staticmethod
    def watched(name: str, module: object) -> bool:
        if not isinstance(module, str):
            return False
        return (
            name in _CLEANUP_FUNCTIONS
            or name == "installed_identity"
            or name == "run_isolated_hook_process"
            or (name == "spawnv_passfds" and module == "multiprocessing.util")
            or (name == "start" and module == "multiprocessing.process")
            or (name == "__init__" and (module == "subprocess" or module.startswith("multiprocessing.popen_")))
            or (name in {"wait", "join"} and module in {"subprocess", "multiprocessing.process"})
        )

    def begin_call(self, frame: FrameType, name: str, module: str) -> None:
        self.next_call += 1
        call_id = self.next_call
        metadata: dict[str, Any] = {
            "call_id": call_id,
            "function": name,
            "code_sha256": file_digest(frame.f_code.co_filename),
        }
        if name in {"run_isolated_hook_process", "spawnv_passfds"}:
            metadata.update(operation_metadata(frame.f_locals.get("command", frame.f_locals.get("args"))))
        process = frame.f_locals.get("self")
        if name == "start" and module == "multiprocessing.process":
            target = self.stored_attributes(process).get("_target")
            metadata["target_kind"] = getattr(target, "__name__", "unknown")
        self.calls[id(frame)] = (call_id, name, metadata)
        self.emit("call_started", **metadata)

    def end_call(self, frame: FrameType, value: object) -> None:
        _call_id, name, metadata = self.calls.pop(id(frame))
        result = dict(metadata)
        if name == "run_isolated_hook_process":
            result.update(result_metadata(value))
        elif (
            name == "installed_identity" and isinstance(value, tuple) and len(value) == 2 and isinstance(value[1], dict)
        ):
            for field in ("runtime_sha256", "build_sha", "wheel_sha256", "installed_package_sha256"):
                observed = value[1].get(field)
                if (
                    isinstance(observed, str)
                    and len(observed) in {40, 64}
                    and all(c in "0123456789abcdef" for c in observed)
                ):
                    result[field] = observed
        elif name in _CLEANUP_FUNCTIONS:
            result["contained"] = value if type(value) is bool else None
        process = frame.f_locals.get("self")
        process_fields = self.stored_attributes(process)
        popen_fields = self.stored_attributes(process_fields.get("_popen"))
        pid = (
            value
            if name == "spawnv_passfds" and type(value) is int
            else process_fields.get("pid", popen_fields.get("pid"))
        )
        if type(pid) is int and pid > 0:
            result["child_pid"] = pid
            child = identity(pid)
            result["child_start_marker"] = child.get("start_marker")
            result["child_identity_status"] = child["identity_status"]
            result["child_executable_sha256"] = child.get("executable_sha256")
        if name in {"wait", "join"}:
            # BaseProcess.exitcode polls/reaps: observe stored results only.
            exit_code = (
                value if type(value) is int else process_fields.get("returncode", popen_fields.get("returncode"))
            )
            result["observed_exit_code"] = exit_code if type(exit_code) is int else None
        if name == "spawnv_passfds" and type(value) is not int:
            self.errors.add("spawn_return_unattributed")
        self.emit("call_returned", **result)

    @staticmethod
    def stored_attributes(value: object) -> dict[str, Any]:
        try:
            result = object.__getattribute__(value, "__dict__")
            return result if type(result) is dict else {}
        except AttributeError:
            return {}

    def finish(self) -> None:
        try:
            if self.monitor_id is None or sys.monitoring.get_events(self.monitor_id) != self.monitor_events:
                self.errors.add("exception_monitor_missing_at_exit")
            remaining = [
                thread
                for thread in threading.enumerate()
                if thread is not threading.current_thread() and thread.is_alive()
            ]
            if remaining:
                self.errors.add("threads_alive_at_exit")
            if self.calls:
                self.errors.add("unfinished_calls_at_exit")
            self.emit("sealed", incomplete=sorted(self.errors), alive_thread_count=len(remaining))
            self.sealed = True
            # Leave hooks active through subsequent finalizers. Late events invalidate the seal.
        except Exception:
            self.errors.add("observer_seal_failed")


def _argument(argv: list[str], name: str) -> str | None:
    try:
        return argv[argv.index(name) + 1]
    except (ValueError, IndexError):
        return None


def bootstrap(entry_name: str, argv: list[str] | None = None) -> None:
    """Enable only the negative phase; failures remain diagnostic, never raised."""
    global _observer
    if _observer is not None:
        return
    try:
        if entry_name == "__main__":
            arguments = sys.argv[1:] if argv is None else argv
            if _argument(arguments, "--phase") != "baseline_rollback":
                return
            fixture_value = _argument(arguments, "--fixture-root")
            if fixture_value is None:
                return
            fixture = Path(fixture_value).resolve()
            private_directory(fixture)
            directory = observer_directory(fixture)
            private_directory(directory, create=True)
            config = {"directory": str(directory), "run_id": os.urandom(16).hex()}
            os.environ[CONFIG_ENV] = json.dumps(config, separators=(",", ":"))
            role = "phase"
        elif entry_name == "__mp_main__" and CONFIG_ENV in os.environ:
            config = json.loads(os.environ[CONFIG_ENV])
            directory = Path(config["directory"])
            private_directory(directory)
            role = "python_spawn"
        else:
            return
        _observer = Observer(directory, config["run_id"], role)
    except Exception:
        # Missing/partial registration is detected by the independent parent reader.
        return
