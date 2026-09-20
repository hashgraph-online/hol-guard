"""A bounded, credential-checked Linux receiver for native phase diagnostics.

Only the receiver's thread reads diagnostic datagrams. It does not send hook
requests, change original deadlines, select an ingress, or stop native workers.
"""

from __future__ import annotations

import array
import copy
import os
import select
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from scripts.native_slo_rust_phase_process import Executable, OwnedCohort
from scripts.native_slo_rust_phase_schema import MAX_DATAGRAM_BYTES, decode_frame, require_progress

MAX_PROCESSES = 16
MAX_RECEIVED_DATAGRAMS = 4096
MAX_RECEIVED_BYTES = MAX_RECEIVED_DATAGRAMS * MAX_DATAGRAM_BYTES
MAX_RECEIVER_SECONDS = 60.0
_RECEIVE_SLICE_SECONDS = 0.05
_CREDENTIAL_BYTES = struct.calcsize("iII")
_RIGHTS_LIMIT = 64


def supported() -> bool:
    return sys.platform == "linux" and all(
        hasattr(socket, name)
        for name in ("SO_PASSCRED", "SCM_CREDENTIALS", "SCM_RIGHTS", "MSG_CMSG_CLOEXEC", "CMSG_SPACE")
    )


def _path_identity(path: Path) -> tuple[int, int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino, metadata.st_uid


def _credentials(ancillary: list[tuple[int, int, bytes]]) -> tuple[int, int, int] | None:
    """Close every received rights descriptor before refusing non-credential data."""
    credentials: list[tuple[int, int, int]] = []
    invalid = False
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array.array("i")
            descriptors.frombytes(data[: len(data) - len(data) % descriptors.itemsize])
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    invalid = True
            invalid = True
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == _CREDENTIAL_BYTES:
            credentials.append(struct.unpack("iII", data))
        else:
            invalid = True
    if invalid or len(credentials) != 1:
        return None
    return credentials[0]


class NativePhaseReceiver:
    def __init__(self, runtime: Path) -> None:
        if not supported():
            raise ValueError("native_phase_platform_unsupported")
        self.executable = Executable(runtime)
        self.directory: Path | None = None
        self.socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._cohort: OwnedCohort | None = None
        self._latest: dict[tuple[int, int], dict[str, Any]] = {}
        self._latest_snapshot: dict[tuple[int, int], dict[str, Any]] = {}
        self._counts = {"received": 0, "received_bytes": 0, "accepted": 0, "refused": 0, "ordinal_gaps": 0}
        self._status = "prepared"
        self._loss = False
        self._terminal = False
        self._file_identity_last_check: bool | None = None
        try:
            self.directory = Path(tempfile.mkdtemp(prefix="guard-native-phase-", dir="/tmp"))
            self._directory_identity = _path_identity(self.directory)
            metadata = self.directory.lstat()
            if (
                self.directory.resolve() != self.directory
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ValueError("native_phase_endpoint_refused")
            self.path = self.directory / "phase.sock"
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.socket.setblocking(False)
            self.socket.bind(str(self.path))
            self.path.chmod(0o600)
            self._socket_identity = _path_identity(self.path)
        except BaseException:
            self.close()
            raise

    def environment(self) -> dict[str, str]:
        if self.directory is None or self.socket is None or self._status != "prepared":
            raise ValueError("native_phase_receiver_not_prepared")
        if (
            _path_identity(self.directory) != self._directory_identity
            or _path_identity(self.path) != self._socket_identity
        ):
            raise ValueError("native_phase_endpoint_changed")
        device, inode, _uid = self._socket_identity
        return {
            "HOL_GUARD_NATIVE_PHASE_SOCKET": str(self.path),
            "HOL_GUARD_NATIVE_PHASE_DEVICE": str(device),
            "HOL_GUARD_NATIVE_PHASE_INODE": str(inode),
        }

    def attach(self, fixture_pid: int) -> None:
        if self._cohort is not None or self._thread is not None or self._status != "prepared":
            raise ValueError("native_phase_receiver_already_attached")
        self._cohort = OwnedCohort(fixture_pid, self.executable)
        self._status = "receiving"
        self._thread = threading.Thread(target=self._receive, name="guard-phase-receiver", daemon=True)
        self._thread.start()

    def _admit(self, payload: bytes, ancillary: list[tuple[int, int, bytes]], flags: int) -> None:
        credentials = _credentials(ancillary)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or credentials is None:
            raise ValueError("native_phase_transport_refused")
        pid, uid, gid = credentials
        if uid != os.geteuid() or gid != os.getegid():
            raise ValueError("native_phase_sender_refused")
        frame = decode_frame(payload)
        if pid != frame["sender_pid"] or self._cohort is None:
            raise ValueError("native_phase_sender_refused")
        sender = self._cohort.admit(pid, frame["sender_start_ticks"], frame["role"])
        key = sender.pid, sender.start_ticks
        with self._lock:
            self._retain(frame, key)

    def _retain(self, frame: dict[str, Any], key: tuple[int, int]) -> None:
        previous = self._latest.get(key)
        if previous is not None:
            require_progress(previous, frame)
        elif len(self._latest) >= MAX_PROCESSES:
            raise ValueError("native_phase_process_cap")
        previous_snapshot = self._latest_snapshot.get(key)
        if previous_snapshot is not None and frame["snapshot"] is not None:
            require_progress(previous_snapshot, frame)
        expected = previous["ordinal"] + 1 if previous is not None else 1
        if frame["ordinal"] != expected:
            self._counts["ordinal_gaps"] += 1
            self._loss = True
        self._loss |= frame["prior_export_loss_observed"] or frame["snapshot"] is None
        self._latest[key] = frame
        if frame["snapshot"] is not None:
            self._latest_snapshot[key] = frame
        self._counts["accepted"] += 1

    def _receive(self) -> None:
        deadline = time.monotonic() + MAX_RECEIVER_SECONDS
        ancillary_bound = socket.CMSG_SPACE(_CREDENTIAL_BYTES) + socket.CMSG_SPACE(
            _RIGHTS_LIMIT * array.array("i").itemsize
        )
        try:
            while not self._stop.is_set():
                if time.monotonic() >= deadline:
                    with self._lock:
                        self._status = "receiver_time_cap"
                        self._loss = True
                    break
                with self._lock:
                    at_cap = (
                        self._counts["received"] >= MAX_RECEIVED_DATAGRAMS
                        or self._counts["received_bytes"] + MAX_DATAGRAM_BYTES + 1 > MAX_RECEIVED_BYTES
                    )
                    if at_cap:
                        self._status = "receiver_data_cap"
                        self._loss = True
                        break
                channel = self.socket
                if channel is None:
                    raise ValueError("native_phase_receiver_closed")
                readable, _, _ = select.select([channel], [], [], _RECEIVE_SLICE_SECONDS)
                if not readable:
                    continue
                try:
                    payload, ancillary, flags, _address = channel.recvmsg(
                        MAX_DATAGRAM_BYTES + 1, ancillary_bound, socket.MSG_CMSG_CLOEXEC
                    )
                except BlockingIOError:
                    continue
                with self._lock:
                    self._counts["received"] += 1
                    self._counts["received_bytes"] += len(payload)
                try:
                    self._admit(payload, ancillary, flags)
                except Exception:
                    with self._lock:
                        self._counts["refused"] += 1
                        self._loss = True
        except Exception:
            with self._lock:
                self._status = "receiver_failed"
                self._loss = True
        finally:
            with self._lock:
                self._terminal = True
                if self._status == "receiving":
                    self._status = "receiver_stopped"

    def report(self) -> dict[str, object]:
        identity_observation = self._file_identity_last_check
        if identity_observation is None:
            try:
                identity_observation = self.executable.current()
            except OSError:
                identity_observation = None
        # A concurrent close may complete after the preceding descriptor read.
        # Prefer its retained observation; neither observation is atomic with
        # the aggregate snapshot and neither runs under the snapshot lock.
        if self._file_identity_last_check is not None:
            identity_observation = self._file_identity_last_check
        with self._lock:
            processes: list[dict[str, object]] = []
            for index, (key, frame) in enumerate(self._latest.items(), 1):
                sample = self._latest_snapshot.get(key)
                processes.append(
                    {
                        "slot": index,
                        "role": frame["role"],
                        "last_frame_ordinal": frame["ordinal"],
                        "snapshot_ordinal": None if sample is None else sample["ordinal"],
                        "run_state_when_last_sampled": frame["run_state_when_sampled"],
                        "export_window_exhausted": frame["last_allowed_attempt"],
                        "prior_export_loss_observed": frame["prior_export_loss_observed"],
                        "diagnostic_socket_opens": 1,
                        "snapshot": None if sample is None else copy.deepcopy(sample["snapshot"]),
                    }
                )
            return {
                "schema": "hol-guard-native-phase-receiver.v1",
                "scope": "diagnostic_instrumented_owned_live_process_observations",
                "platform_support": "linux",
                "headline_timing_eligible": False,
                "qualification_complete": False,
                "complete_run": False,
                "runtime_sha256": self.executable.sha256,
                "runtime_file_identity_unchanged_at_last_check": identity_observation,
                "runtime_file_identity_scope": "last_observation_outside_snapshot_lock",
                "receiver_status": self._status,
                "receiver_terminal": self._terminal,
                "receiver_loss_observed": self._loss,
                "counts": dict(self._counts),
                "bounds": {
                    "processes": MAX_PROCESSES,
                    "datagrams": MAX_RECEIVED_DATAGRAMS,
                    "received_bytes": MAX_RECEIVED_BYTES,
                    "seconds": MAX_RECEIVER_SECONDS,
                    "datagram_bytes": MAX_DATAGRAM_BYTES,
                },
                "processes": processes,
                "snapshot_aggregation": "latest_retained_per_process_do_not_sum_cumulative_frames",
                "observed_call_scope": "actual_boundaries_include_startup_control_and_request_calls",
                "unobserved_phase": "null_missing_or_unretained_not_zero_cost",
                "request_socket_counts": "observed_successful_creation_returns_only_not_live_fd_counts",
                "diagnostic_sockets_excluded_from_request_counts": True,
                "final_tail_delivery_guaranteed": False,
            }

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            if self._thread.is_alive():
                self._status = "receiver_stop_unverified"
                self._loss = True
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.directory is not None:
            try:
                if _path_identity(self.directory) == getattr(self, "_directory_identity", None):
                    if hasattr(self, "_socket_identity") and _path_identity(self.path) == self._socket_identity:
                        self.path.unlink()
                    self.directory.rmdir()
            except OSError:
                self._loss = True
            self.directory = None
        if self.executable.descriptor >= 0 and (self._thread is None or not self._thread.is_alive()):
            self._file_identity_last_check = self.executable.current()
            self.executable.close()
