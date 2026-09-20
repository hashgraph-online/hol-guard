"""Owned real-binary controls for native diagnostic lifecycle tests.

These synthetic controls may keep their stdin stream open to sample the
exporter. They do not change the installed workload, native deadlines or
shutdown implementation. Failure cleanup targets retained pidfds only.
"""

from __future__ import annotations

import errno
import json
import os
import select
import signal
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import IO, Any

from scripts.native_slo_rust_phase_process import Executable, ProcessIdentity, parse_stat, read_process
from scripts.native_slo_rust_phase_receiver import NativePhaseReceiver

HEALTH = b'{"operation":"health","request":{}}'
INVALID = b"{"
HEALTH_RESPONSE = b'{"protocol_version":2,"status":"ready"}'
INVALID_RESPONSE = b'{"error":"native_request_invalid_json","retryable":false}'
MAX_CONTROL_PROCESSES = 32
MAX_PROC_ENTRIES = 32768


def wait_report(receiver: NativePhaseReceiver, predicate: Any, seconds: float = 4.0) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        report = receiver.report()
        if predicate(report):
            return report
        if report["receiver_terminal"]:
            break
        time.sleep(0.01)
    raise AssertionError("bounded native diagnostic observation was not retained")


def statistics(report: dict[str, Any], role: str, phase: str) -> list[dict[str, Any]]:
    return [
        row["statistics"]
        for process in report["processes"]
        if process["role"] == role and process["snapshot"] is not None
        for row in process["snapshot"]["phases"]
        if row["phase"] == phase and row["statistics"] is not None
    ]


@contextmanager
def fill_owned_receiver(receiver: NativePhaseReceiver, evidence: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Require refusal on a distinct fresh sender, within the original send cap."""
    payload = b"controlled diagnostic backpressure"
    flags = socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL
    evidence.update(
        {
            "send_attempt_cap": 1024,
            "live_socket_cap": 16,
            "payload_bytes": len(payload),
            "total_attempts": 0,
            "accepted": 0,
            "senders": [],
            "fresh_first_send_refused": False,
            "all_fillers_closed": False,
            "queue_limit": None,
            "queue_limit_error": None,
            "queue_limit_errno": None,
            "stage": "queue_limit_metadata",
            "sender_index": None,
            "terminal_error": None,
            "terminal_errno": None,
            "terminal_stage": None,
            "terminal_sender_index": None,
            "operation_failure": None,
        }
    )
    try:
        with Path("/proc/sys/net/unix/max_dgram_qlen").open("rb") as stream:
            raw_limit = stream.read(129)
        if len(raw_limit) > 128 or not raw_limit.strip().isdigit():
            raise ValueError("bounded queue-limit metadata is not decimal")
        evidence["queue_limit"] = int(raw_limit)
    except (OSError, ValueError) as exc:
        evidence["queue_limit_error"] = type(exc).__name__
        evidence["queue_limit_errno"] = getattr(exc, "errno", None)
    fillers: list[socket.socket] = []
    identities: set[tuple[int, int]] = set()
    operation_error: BaseException | None = None
    try:
        with ExitStack() as owned:
            try:
                for index in range(16):
                    evidence["sender_index"] = index
                    evidence["stage"] = "socket_create"
                    filler = owned.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
                    fillers.append(filler)
                    evidence["stage"] = "set_nonblocking"
                    filler.setblocking(False)
                    evidence["stage"] = "connect"
                    filler.connect(str(receiver.path))
                    evidence["stage"] = "socket_identity"
                    metadata = os.fstat(filler.fileno())
                    identity = metadata.st_dev, metadata.st_ino
                    assert identity not in identities, "fresh filler socket identity was reused"
                    identities.add(identity)
                    evidence["stage"] = "send_buffer_metadata"
                    row: dict[str, Any] = {
                        "index": index,
                        "socket_device": identity[0],
                        "socket_inode": identity[1],
                        "send_buffer_bytes": filler.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
                        "attempts": 0,
                        "accepted": 0,
                        "blocked_errno": None,
                        "blocked_on_first_send": False,
                    }
                    evidence["senders"].append(row)
                    while evidence["total_attempts"] < 1024:
                        row["attempts"] += 1
                        evidence["total_attempts"] += 1
                        try:
                            evidence["stage"] = "send"
                            sent = filler.send(payload, flags)
                        except BlockingIOError as exc:
                            row["blocked_errno"] = exc.errno
                            row["blocked_on_first_send"] = row["attempts"] == 1
                            assert exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK)
                            if row["blocked_on_first_send"]:
                                assert index > 0 and evidence["accepted"] > 0
                                evidence["fresh_first_send_refused"] = True
                                evidence["stage"] = "control_body"
                                yield evidence
                                return
                            break
                        assert sent == len(payload), "controlled datagram send was partial"
                        row["accepted"] += 1
                        evidence["accepted"] += 1
                    else:
                        raise AssertionError("original 1024-send cap reached before fresh-sender refusal")
                raise AssertionError("bounded live-socket cap reached before fresh-sender refusal")
            except BaseException as exc:
                operation_error = exc
                evidence["operation_failure"] = {
                    "stage": evidence["stage"],
                    "sender_index": evidence["sender_index"],
                    "error": type(exc).__name__,
                    "errno": getattr(exc, "errno", None),
                }
                raise
            finally:
                evidence["stage"] = "owned_cleanup"
                evidence["sender_index"] = None
    except BaseException as exc:
        evidence["terminal_error"] = type(exc).__name__
        evidence["terminal_errno"] = getattr(exc, "errno", None)
        evidence["terminal_stage"] = (
            evidence["operation_failure"]["stage"] if exc is operation_error else evidence["stage"]
        )
        evidence["terminal_sender_index"] = (
            evidence["operation_failure"]["sender_index"] if exc is operation_error else None
        )
        raise
    finally:
        evidence["all_fillers_closed"] = all(filler.fileno() == -1 for filler in fillers)


def retain_native_stderr(descriptor: int) -> dict[str, Any]:
    """Read an owned duplicate after original cleanup, without a wait or retry."""
    result: dict[str, Any] = {
        "scope": "owned_stderr_duplicate_after_original_cleanup",
        "limit_bytes": 4096,
        "bytes": 0,
        "content_hex": "",
        "eof": False,
        "overflow": False,
        "would_block": False,
        "error_errno": None,
        "descriptor_closed": False,
        "complete": False,
    }
    captured = bytearray()
    try:
        os.set_blocking(descriptor, False)
        while len(captured) < 4097:
            try:
                chunk = os.read(descriptor, 4097 - len(captured))
            except BlockingIOError:
                result["would_block"] = True
                break
            if not chunk:
                result["eof"] = True
                break
            captured.extend(chunk)
        result["overflow"] = len(captured) > 4096
    except OSError as exc:
        result["error_errno"] = exc.errno
    finally:
        try:
            os.close(descriptor)
            result["descriptor_closed"] = True
        except OSError as exc:
            result["close_errno"] = exc.errno
        result["bytes"] = len(captured)
        result["content_hex"] = captured.hex()
        result["complete"] = (
            result["eof"]
            and not result["overflow"]
            and not result["would_block"]
            and result["error_errno"] is None
            and result["descriptor_closed"]
        )
    return result


def _read_exact(stream: IO[bytes], length: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise AssertionError("original native response was not received within the control deadline")
        chunk = os.read(stream.fileno(), length - len(result))
        if not chunk:
            raise AssertionError("original native response ended before its frame")
        result.extend(chunk)
    return bytes(result)


def _bounded_proc_entries() -> list[Path]:
    entries: list[Path] = []
    with os.scandir("/proc") as iterator:
        for entry in iterator:
            assert len(entries) < MAX_PROC_ENTRIES, "process census entry cap reached"
            entries.append(Path(entry.path))
    return entries


class OwnedNativeStream:
    def __init__(self, runtime: Path, root: Path, diagnostic_environment: dict[str, str]) -> None:
        self.runtime = runtime
        with ExitStack() as construction:
            self.executable = Executable(runtime)
            construction.callback(self.executable.close)
            self.root = root
            root.mkdir(mode=0o700)
            self.state = root / "native-runtime"
            self.state.mkdir(mode=0o700)
            descriptor = os.open(self.state / "policy-verifier.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                assert os.write(descriptor, bytes([7]) * 32) == 32
            finally:
                os.close(descriptor)
            environment = {
                key: value for key, value in os.environ.items() if not key.startswith("HOL_GUARD_NATIVE_PHASE_")
            }
            environment.update(diagnostic_environment)
            self.environment = environment
            self.process: subprocess.Popen[bytes] = subprocess.Popen(
                [str(runtime), "resident-client-stream", "--stdin", str(self.state)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=True,
            )
            self.handles: dict[tuple[int, int], tuple[ProcessIdentity, int]] = {}
            self.closed = False
            self.completed_requests = 0
            self.cleanup: dict[str, Any] | None = None
            try:
                self.identity, role = read_process(self.process.pid, self.executable)
                assert role == "persistent_client"
                assert self.identity.parent == os.getpid()
                assert self.identity.group == self.identity.session == self.identity.pid
                self.capture_owned_processes()
            except BaseException:
                # No request has been written: this exact stream cannot yet have
                # spawned a managed resident. Retire only the owned direct child.
                try:
                    self.process.kill()
                    self.process.wait(timeout=3)
                finally:
                    for _row, handle in self.handles.values():
                        os.close(handle)
                    for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                        if stream is not None:
                            stream.close()
                raise
            _ = construction.pop_all()

    def capture_owned_processes(self) -> None:
        """Capture only this live session's exact native executable generations."""
        current, _ = read_process(self.process.pid, self.executable)
        assert current == self.identity, "original native session leader changed"
        for path in _bounded_proc_entries():
            if not path.name.isdecimal():
                continue
            pid = int(path.name)
            try:
                with (path / "stat").open("rb") as stream:
                    raw = stream.read(4097)
                assert len(raw) <= 4096
                try:
                    row = parse_stat(raw, pid)
                except ValueError:
                    # Dead/zombie entries are not live cleanup targets.
                    continue
                if row.session != self.identity.session:
                    continue
                verified, _ = read_process(pid)
                assert verified == row and row.start_ticks >= self.identity.start_ticks
                metadata = os.stat(path / "exe")
                identity = (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
                assert identity == self.executable.identity, "unrecognized binary in owned native session"
                key = row.pid, row.start_ticks
                if key in self.handles:
                    continue
                assert len(self.handles) < MAX_CONTROL_PROCESSES
                handle = os.pidfd_open(pid, 0)
                try:
                    assert read_process(pid)[0] == row
                except BaseException:
                    os.close(handle)
                    raise
                self.handles[key] = row, handle
            except (FileNotFoundError, ProcessLookupError):
                continue
        assert read_process(self.process.pid, self.executable)[0] == self.identity

    def request(self, payload: bytes) -> bytes:
        assert self.process.stdin is not None and self.process.stdout is not None
        assert 0 < len(payload) <= 4096
        deadline = time.monotonic() + 3.0
        self.process.stdin.write(len(payload).to_bytes(4, "big") + payload)
        self.process.stdin.flush()
        header = _read_exact(self.process.stdout, 4, deadline)
        length = int.from_bytes(header, "big")
        assert 0 < length <= 65536
        result = _read_exact(self.process.stdout, length, deadline)
        self.capture_owned_processes()
        self.completed_requests += 1
        return result

    def _live_handles(self) -> list[int]:
        return [handle for _row, handle in self.handles.values() if not select.select([handle], [], [], 0)[0]]

    def close(self, expected_returncode: int = 0) -> dict[str, Any]:
        if self.closed:
            assert self.cleanup is not None
            return self.cleanup
        self.closed = True
        result: dict[str, Any] = {
            "scope": "existing_resident_stop_then_retained_owned_generation_pidfds",
            "stop_returncode": None,
            "client_returncode": None,
            "original_session_capture_failed": False,
            "forced_signals": [],
            "no_live_retained_generations": False,
            "state_files_remaining": None,
            "passed": False,
            "never_started_partial_header_control": (
                expected_returncode == 2
                and self.completed_requests == 0
                and set(self.handles) == {(self.identity.pid, self.identity.start_ticks)}
                and not list(self.state.glob("resident-v3-*/generation-*.json"))
            ),
            "stop_response_expected": False,
        }
        try:
            if self.process.poll() is None:
                try:
                    self.capture_owned_processes()
                except Exception:
                    result["original_session_capture_failed"] = True
            stop_environment = {
                key: value for key, value in self.environment.items() if not key.startswith("HOL_GUARD_NATIVE_PHASE_")
            }
            try:
                stopped = subprocess.run(
                    [str(self.runtime), "resident-stop", "--state-dir", str(self.state)],
                    env=stop_environment,
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                assert len(stopped.stdout) + len(stopped.stderr) <= 4096
                result["stop_returncode"] = stopped.returncode
                result["stop_response_expected"] = (stopped.returncode, stopped.stdout, stopped.stderr) == (
                    (2, b"", b"native_resident_stop_unavailable\n")
                    if result["never_started_partial_header_control"]
                    else (0, b"", b"")
                )
            except (subprocess.TimeoutExpired, OSError):
                result["stop_failed"] = True
            if self.process.stdin is not None:
                self.process.stdin.close()
            try:
                result["client_returncode"] = self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                result["client_timeout"] = True
            # The original supervisor joins its 50 ms watcher after serving
            # stops. Observe that normal retirement before any fallback signal.
            passive_deadline = time.monotonic() + 2
            while time.monotonic() < passive_deadline and self._live_handles():
                self.process.poll()
                time.sleep(0.01)
            for signum in (signal.SIGTERM, signal.SIGKILL):
                live = self._live_handles()
                if not live:
                    break
                for handle in live:
                    try:
                        signal.pidfd_send_signal(handle, signum)
                        result["forced_signals"].append(int(signum))
                    except ProcessLookupError:
                        pass
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and self._live_handles():
                    self.process.poll()
                    time.sleep(0.01)
            self.process.poll()
            result["client_returncode"] = self.process.returncode
            result["no_live_retained_generations"] = not self._live_handles()
            result["retained_generation_count"] = len(self.handles)
            result["state_files_remaining"] = len(list(self.state.glob("resident-v3-*/generation-*.json")))
            result["passed"] = (
                result["stop_response_expected"]
                and result["client_returncode"] == expected_returncode
                and result["no_live_retained_generations"]
                and not result["original_session_capture_failed"]
                and result["state_files_remaining"] == 0
                and not result["forced_signals"]
            )
        finally:
            for _row, handle in self.handles.values():
                os.close(handle)
            self.handles.clear()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
            self.executable.close()
            self.cleanup = result
        return result


def keep_record(record_property: Any, label: str, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True)
    assert len(encoded.encode("utf-8")) <= 1024 * 1024
    record_property(label, encoded)
