"""Owned finite sender fixtures; these do not execute the native product."""

from __future__ import annotations

import copy
import json
import os
import select
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from scripts.native_slo_rust_phase_schema import MAX_DATAGRAM_BYTES, MAX_DURATION_NS, MAX_OBSERVATIONS, PHASES

SENDER = r"""
import json
import os
import signal
import socket
import sys

signal.alarm(10)
print("ready", flush=True)
request = json.loads(sys.stdin.buffer.readline(65537))
fields = open("/proc/self/stat", encoding="utf-8").read(4097).rsplit(") ", 1)[1].split()
start = int(fields[19])
channel = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
channel.connect(sys.argv[1])
for original in request["frames"]:
    frame = dict(original)
    frame["sender_pid"] = os.getpid() + request.get("pid_delta", 0)
    frame["sender_start_ticks"] = start + request.get("start_delta", 0)
    channel.send(json.dumps(frame, separators=(",", ":")).encode("utf-8"))
print("sent", flush=True)
sys.stdin.buffer.read(1)
"""


def sample_frame(ordinal: int = 1, count: int = 1) -> dict[str, Any]:
    statistics = {
        "retained_count": count,
        "returned_ok": count,
        "returned_err": 0,
        "unwound": 0,
        "abandoned": 0,
        "duration_ns_sum": count,
        "duration_ns_min": 1,
        "duration_ns_max": 1,
        "duration_clipped": False,
        "observations_discarded_at_cap": False,
    }
    snapshot = {
        "schema": "hol-guard-native-phase-diagnostics.v1",
        "scope": "diagnostic_instrumented_process_snapshot",
        "span_semantics": "inclusive_do_not_sum",
        "headline_timing_eligible": False,
        "complete_run": False,
        "snapshot_atomic": False,
        "collector_loss_observed": False,
        "active_observations_when_read": 0,
        "max_observations_per_phase": MAX_OBSERVATIONS,
        "max_duration_ns": MAX_DURATION_NS,
        "unobserved_phase": "null_missing_or_unretained_not_zero_cost",
        "loopback_failed_internal_socket_creations": None,
        "all_platform_socket_opens": None,
        "phases": [
            {"phase": phase, "statistics": copy.deepcopy(statistics) if index == 0 else None}
            for index, phase in enumerate(PHASES)
        ],
    }
    return {
        "schema": "hol-guard-native-phase-frame.v1",
        "sender_pid": 123,
        "sender_start_ticks": 1,
        "role": "resident_client",
        "ordinal": ordinal,
        "max_export_attempts": 256,
        "export_interval_ms": 50,
        "max_datagram_bytes": MAX_DATAGRAM_BYTES,
        "diagnostic_socket_opens": 1,
        "diagnostic_socket_in_request_counts": False,
        "prior_export_loss_observed": False,
        "last_allowed_attempt": ordinal == 256,
        "run_state_when_sampled": "running",
        "complete_run": False,
        "headline_timing_eligible": False,
        "snapshot": snapshot,
    }


def _stderr_observation(process: subprocess.Popen[bytes]) -> dict[str, Any]:
    captured = bytearray()
    complete = False
    error = None
    if process.stderr is not None:
        try:
            descriptor = process.stderr.fileno()
            os.set_blocking(descriptor, False)
            while len(captured) <= 4096:
                try:
                    chunk = os.read(descriptor, 4097 - len(captured))
                except BlockingIOError:
                    break
                if not chunk:
                    complete = True
                    break
                captured.extend(chunk)
        except OSError as failure:
            error = type(failure).__name__
    return {
        "data": bytes(captured),
        "complete": complete,
        "byte_limit": 4096,
        "capture_byte_limit": 4097,
        "limit_exceeded": len(captured) > 4096,
        "unavailable": process.stderr is None,
        "read_error": error,
    }


def line(process: subprocess.Popen[bytes], expected: bytes) -> None:
    if process.stdout is None:
        raise AssertionError("owned sender stdout unavailable")
    deadline = time.monotonic() + 3
    value = bytearray()
    while time.monotonic() < deadline and len(value) <= 32:
        if not select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        chunk = os.read(process.stdout.fileno(), 1)
        if not chunk:
            break
        value.extend(chunk)
        if chunk == b"\n":
            break
    if bytes(value) != expected:
        raise AssertionError(
            {
                "expected": expected,
                "received": bytes(value),
                "returncode": process.poll(),
                "stderr": _stderr_observation(process),
            }
        )


@contextmanager
def sender(directory: Path, endpoint: Path) -> Iterator[subprocess.Popen[bytes]]:
    script = directory / "resident-client"
    script.write_text(SENDER, encoding="utf-8")
    environment = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"}
    process = subprocess.Popen(
        [str(Path(sys.executable).resolve()), "resident-client", str(endpoint)],
        cwd=directory,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        line(process, b"ready\n")
        yield process
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def transmit(process: subprocess.Popen[bytes], frames: list[dict[str, Any]], **changes: int) -> None:
    assert len(frames) <= 4 and process.stdin is not None
    payload = json.dumps({"frames": frames, **changes}).encode("utf-8") + b"\n"
    assert len(payload) < 65537
    process.stdin.write(payload)
    process.stdin.flush()
    line(process, b"sent\n")


def wait_received(receiver: Any, count: int) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        report = receiver.report()
        processed = report["counts"]["accepted"] + report["counts"]["refused"]
        if processed >= count or report["receiver_terminal"]:
            return report
        time.sleep(0.005)
    raise AssertionError("owned receiver did not retain the finite datagram count")
