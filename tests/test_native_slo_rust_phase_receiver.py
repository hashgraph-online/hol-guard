"""Real Unix datagram, process-generation and cleanup controls."""

from __future__ import annotations

import array
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

from scripts import native_slo_rust_phase_receiver as receiver_module
from scripts.native_slo_rust_phase_process import parse_stat
from scripts.native_slo_rust_phase_receiver import NativePhaseReceiver, _credentials, supported
from tests.native_slo_rust_phase_test_support import sample_frame, sender, transmit, wait_received

pytestmark = pytest.mark.skipif(not supported(), reason="Linux kernel credential controls")


def test_live_owned_sender_binds_actual_process_and_exports_only_aggregate_fields(tmp_path: Path) -> None:
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    try:
        endpoint = receiver.path
        with sender(tmp_path, endpoint) as process:
            receiver.attach(process.pid)
            transmit(process, [sample_frame(1, 1), sample_frame(2, 2)])
            report = wait_received(receiver, 2)
            assert report["counts"]["accepted"] == 2
            assert report["counts"]["refused"] == 0
            assert len(report["processes"]) == 1
            retained = report["processes"][0]
            assert retained["last_frame_ordinal"] == 2
            assert retained["snapshot"]["phases"][0]["statistics"]["retained_count"] == 2
            # Cumulative snapshots are retained once, never summed to three.
            assert retained["snapshot"]["phases"][1]["statistics"] is None
            encoded = json.dumps(report)
            assert "sender_pid" not in encoded and "sender_start_ticks" not in encoded
            assert str(endpoint) not in encoded
            receiver.close()
            finished = receiver.report()
            receiver.close()
            assert receiver.report() == finished
            assert finished["receiver_terminal"] is True
            assert finished["runtime_file_identity_unchanged_at_last_check"] is True
            assert finished["complete_run"] is False
    finally:
        receiver.close()


@pytest.mark.parametrize("mismatch", ["kernel_pid", "generation", "actual_role"])
def test_sender_identity_mismatches_are_refused(tmp_path: Path, mismatch: str) -> None:
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    try:
        with sender(tmp_path, receiver.path) as process:
            receiver.attach(process.pid)
            frame = sample_frame()
            changes = {}
            if mismatch == "kernel_pid":
                changes["pid_delta"] = 1
            elif mismatch == "generation":
                changes["start_delta"] = 1
            else:
                frame["role"] = "managed_resident"
            transmit(process, [frame], **changes)
            report = wait_received(receiver, 1)
            assert report["counts"]["accepted"] == 0
            assert report["counts"]["refused"] == 1
            assert report["processes"] == []
            assert report["receiver_loss_observed"] is True
    finally:
        receiver.close()


def test_same_user_same_executable_outside_owned_fixture_tree_is_refused(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    try:
        with sender(first, receiver.path) as owned, sender(second, receiver.path) as foreign:
            receiver.attach(owned.pid)
            transmit(owned, [])
            transmit(foreign, [sample_frame()])
            report = wait_received(receiver, 1)
            assert report["counts"]["accepted"] == 0
            assert report["counts"]["refused"] == 1
            assert report["processes"] == []
    finally:
        receiver.close()


def test_replayed_frame_cannot_replace_the_last_valid_snapshot(tmp_path: Path) -> None:
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    try:
        with sender(tmp_path, receiver.path) as process:
            receiver.attach(process.pid)
            transmit(process, [sample_frame(1, 1), sample_frame(1, 1)])
            report = wait_received(receiver, 2)
            assert report["counts"]["accepted"] == 1
            assert report["counts"]["refused"] == 1
            assert report["processes"][0]["last_frame_ordinal"] == 1
    finally:
        receiver.close()


def test_data_cap_stops_before_another_receive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(receiver_module, "MAX_RECEIVED_DATAGRAMS", 1)
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    try:
        with sender(tmp_path, receiver.path) as process:
            receiver.attach(process.pid)
            transmit(process, [sample_frame(1, 1), sample_frame(2, 2)])
            deadline = time.monotonic() + 3
            report = wait_received(receiver, 1)
            while not report["receiver_terminal"] and time.monotonic() < deadline:
                time.sleep(0.005)
                report = receiver.report()
            assert report["receiver_terminal"] is True
            assert report["receiver_status"] == "receiver_data_cap"
            assert report["counts"]["received"] == 1
            assert report["counts"]["accepted"] == 1
            assert report["receiver_loss_observed"] is True
    finally:
        receiver.close()


def test_unrequested_kernel_rights_are_closed_and_original_descriptor_survives(tmp_path: Path) -> None:
    original = os.open(tmp_path / "owned-data", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    outgoing, incoming = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    incoming.settimeout(1)
    try:
        rights = array.array("i", [original])
        outgoing.sendmsg([b"controlled"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        _payload, ancillary, flags, _address = incoming.recvmsg(
            32, socket.CMSG_SPACE(rights.itemsize * 4), socket.MSG_CMSG_CLOEXEC
        )
        assert flags & ~socket.MSG_CMSG_CLOEXEC == 0
        received = array.array("i")
        received.frombytes(ancillary[0][2])
        assert len(received) == 1
        assert _credentials(ancillary) is None
        for descriptor in received:
            with pytest.raises(OSError):
                os.fstat(descriptor)
        assert os.fstat(original).st_ino > 0
    finally:
        os.close(original)
        outgoing.close()
        incoming.close()


def test_process_stat_parser_binds_the_real_generation_and_delimited_name() -> None:
    actual = Path(f"/proc/{os.getpid()}/stat").read_bytes()
    identity = parse_stat(actual, os.getpid())
    assert identity.pid == os.getpid() and identity.parent == os.getppid()
    controlled = (
        f"{os.getpid()} (controlled ) name) S {os.getppid()} {os.getpgrp()} {os.getsid(0)} " + "0 " * 15 + "777"
    )
    assert parse_stat(controlled.encode(), os.getpid()).start_ticks == 777
    with pytest.raises(ValueError):
        parse_stat(actual, os.getpid() + 1)
    with pytest.raises(ValueError):
        parse_stat(b"1 (truncated) S", 1)


def test_report_identity_io_stays_outside_lock_and_concurrent_close_keeps_last_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    began, release = threading.Event(), threading.Event()
    original = receiver.executable.current
    results: list[dict[str, object]] = []
    failures: list[BaseException] = []

    def observe() -> bool:
        if threading.current_thread() is reader:
            acquired = receiver._lock.acquire(blocking=False)
            assert acquired, "metadata observation ran under report lock"
            receiver._lock.release()
            began.set()
            assert release.wait(timeout=1)
        return original()

    def read() -> None:
        try:
            results.append(receiver.report())
        except BaseException as error:
            failures.append(error)

    reader = threading.Thread(target=read, daemon=True)
    monkeypatch.setattr(receiver.executable, "current", observe)
    try:
        reader.start()
        assert began.wait(timeout=1)
        receiver.close()
        release.set()
        reader.join(timeout=1)
        assert not reader.is_alive() and failures == []
        assert len(results) == 1
        assert results[0]["runtime_file_identity_unchanged_at_last_check"] is True
        assert results[0]["runtime_file_identity_scope"] == "last_observation_outside_snapshot_lock"
    finally:
        release.set()
        reader.join(timeout=1)
        receiver.close()


def test_unavailable_file_observation_is_null_without_losing_aggregate_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    original = receiver.executable.current

    def unavailable() -> bool:
        raise OSError("controlled descriptor observation failure")

    try:
        monkeypatch.setattr(receiver.executable, "current", unavailable)
        report = receiver.report()
        assert report["runtime_file_identity_unchanged_at_last_check"] is None
        assert report["processes"] == []
        assert report["complete_run"] is False
    finally:
        monkeypatch.setattr(receiver.executable, "current", original)
        receiver.close()
