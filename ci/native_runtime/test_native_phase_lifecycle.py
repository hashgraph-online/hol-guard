"""Real default/diagnostic native processes; no emulated product or timing qualification."""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from ci.native_runtime.native_phase_lifecycle_support import (
    HEALTH,
    HEALTH_RESPONSE,
    INVALID,
    INVALID_RESPONSE,
    OwnedNativeStream,
    fill_owned_receiver,
    keep_record,
    retain_native_stderr,
    statistics,
    wait_report,
)
from scripts.native_slo_rust_phase_receiver import NativePhaseReceiver, supported

pytestmark = pytest.mark.skipif(not supported(), reason="Linux native diagnostic lifecycle controls")


@pytest.fixture(scope="module")
def phase_binaries() -> dict[str, Path]:
    values = {
        "default": os.environ.get("HOL_GUARD_NATIVE_PHASE_DEFAULT_BINARY"),
        "diagnostic": os.environ.get("HOL_GUARD_NATIVE_PHASE_DIAGNOSTIC_BINARY"),
    }
    if any(value is None for value in values.values()):
        pytest.skip("both exact compiled native feature variants are required")
    result = {name: Path(str(value)).resolve(strict=True) for name, value in values.items()}
    assert result["default"] != result["diagnostic"]
    assert hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
    assert sys.platform == "linux"
    return result


def _client(
    runtime: Path,
    root: Path,
    receiver: NativePhaseReceiver,
    environment: dict[str, str],
) -> OwnedNativeStream:
    try:
        return OwnedNativeStream(runtime, root, environment)
    except BaseException:
        receiver.close()
        raise


def _responses(client: OwnedNativeStream) -> tuple[bytes, bytes]:
    responses = [client.request(HEALTH) for _ in range(3)]
    assert responses == [HEALTH_RESPONSE] * 3
    invalid = client.request(INVALID)
    assert invalid == INVALID_RESPONSE
    return responses[0], invalid


def _all_boundaries(report: dict[str, Any]) -> bool:
    client = "persistent_client"
    phases = [
        "client_connect_inclusive",
        "client_authenticate",
        "client_request_write_flush",
        "client_committed_response_read",
    ]
    return (
        all(any(row["returned_ok"] > 0 for row in statistics(report, client, phase)) for phase in phases)
        and any(row["returned_ok"] > 0 for row in statistics(report, client, "unix_socket_creation"))
        and any(
            row["returned_ok"] > 0 and row["returned_err"] > 0
            for row in statistics(report, "managed_resident", "resident_evaluate_inclusive")
        )
    )


def _close(
    client: OwnedNativeStream,
    receiver: NativePhaseReceiver,
    record_property: Any,
    *,
    expected_returncode: int = 0,
) -> None:
    cleanup: dict[str, Any] = {"passed": False, "close_did_not_return": True}
    try:
        cleanup = client.close(expected_returncode)
    finally:
        receiver.close()
        keep_record(record_property, "native_cleanup", cleanup)
        keep_record(record_property, "native_diagnostic", receiver.report())
    assert cleanup["passed"] is True


def test_real_enabled_macros_preserve_default_health_and_error_responses(
    phase_binaries: dict[str, Path],
    tmp_path: Path,
    record_property: Any,
) -> None:
    actual: dict[str, tuple[bytes, bytes]] = {}
    for variant, runtime in phase_binaries.items():
        receiver = NativePhaseReceiver(runtime)
        client = _client(runtime, tmp_path / variant, receiver, receiver.environment())
        try:
            receiver.attach(client.process.pid)
            actual[variant] = _responses(client)
            if variant == "diagnostic":
                report = wait_report(receiver, _all_boundaries)
                assert {row["role"] for row in report["processes"]} == {"persistent_client", "managed_resident"}
                assert report["complete_run"] is report["qualification_complete"] is False
            else:
                time.sleep(0.15)
                report = receiver.report()
                assert report["counts"]["received"] == 0 and not report["processes"]
            keep_record(record_property, variant + "_boundaries", report)
        finally:
            _close(client, receiver, record_property)
    assert actual["default"] == actual["diagnostic"]


@pytest.mark.parametrize("mode", ["missing", "wrong_inode"])
def test_real_feature_build_with_unadmitted_endpoint_preserves_protocol_and_emits_nothing(
    phase_binaries: dict[str, Path],
    tmp_path: Path,
    record_property: Any,
    mode: str,
) -> None:
    runtime = phase_binaries["diagnostic"]
    receiver = NativePhaseReceiver(runtime)
    environment = {} if mode == "missing" else receiver.environment()
    if mode == "wrong_inode":
        environment["HOL_GUARD_NATIVE_PHASE_INODE"] = str(int(environment["HOL_GUARD_NATIVE_PHASE_INODE"]) + 1)
    client = _client(runtime, tmp_path / mode, receiver, environment)
    try:
        receiver.attach(client.process.pid)
        _responses(client)
        time.sleep(0.15)
        report = receiver.report()
        assert report["counts"]["received"] == 0 and not report["processes"]
    finally:
        _close(client, receiver, record_property)


def test_real_closed_diagnostic_receiver_does_not_change_requests_or_native_exit(
    phase_binaries: dict[str, Path],
    tmp_path: Path,
    record_property: Any,
) -> None:
    runtime = phase_binaries["diagnostic"]
    receiver = NativePhaseReceiver(runtime)
    client = _client(runtime, tmp_path / "closed", receiver, receiver.environment())
    try:
        receiver.attach(client.process.pid)
        original = _responses(client)
        wait_report(receiver, _all_boundaries)
        receiver.close()
        assert _responses(client) == original
        assert client.process.poll() is None
    finally:
        _close(client, receiver, record_property)


def test_real_exporter_backpressure_is_reported_without_blocking_the_original_protocol(
    phase_binaries: dict[str, Path],
    tmp_path: Path,
    record_property: Any,
) -> None:
    runtime = phase_binaries["diagnostic"]
    receiver = NativePhaseReceiver(runtime)
    admission: dict[str, Any] = {}
    try:
        with fill_owned_receiver(receiver, admission):
            client = _client(runtime, tmp_path / "backpressure", receiver, receiver.environment())
            stderr_duplicate: int | None = None
            try:
                assert client.process.stderr is not None
                stderr_duplicate = os.dup(client.process.stderr.fileno())
                _responses(client)
                # This pause belongs only to the synthetic receiver control. It neither
                # holds a native request open nor changes any original native deadline.
                time.sleep(0.2)
                receiver.attach(client.process.pid)
                report = wait_report(
                    receiver,
                    lambda value: (
                        _all_boundaries(value) and any(row["prior_export_loss_observed"] for row in value["processes"])
                    ),
                )
                assert report["receiver_loss_observed"] is True
                assert report["counts"]["refused"] > 0
                assert _responses(client) == (HEALTH_RESPONSE, INVALID_RESPONSE)
            finally:
                try:
                    _close(client, receiver, record_property)
                finally:
                    if stderr_duplicate is not None:
                        stderr = retain_native_stderr(stderr_duplicate)
                        keep_record(record_property, "native_backpressure_stderr", stderr)
                        assert stderr["descriptor_closed"] is True
    finally:
        receiver.close()
        keep_record(record_property, "native_backpressure_admission", admission)
        assert admission.get("all_fillers_closed") is True


def test_real_exporter_stops_at_its_unchanged_cap_while_the_native_client_keeps_working(
    phase_binaries: dict[str, Path],
    tmp_path: Path,
    record_property: Any,
) -> None:
    runtime = phase_binaries["diagnostic"]
    receiver = NativePhaseReceiver(runtime)
    client = _client(runtime, tmp_path / "cap", receiver, receiver.environment())
    try:
        receiver.attach(client.process.pid)
        original = _responses(client)
        report = wait_report(
            receiver,
            lambda value: (
                _all_boundaries(value)
                and len(value["processes"]) == 2
                and all(row["export_window_exhausted"] for row in value["processes"])
            ),
            seconds=20,
        )
        assert all(row["last_frame_ordinal"] == 256 for row in report["processes"])
        assert all(row["run_state_when_last_sampled"] == "running" for row in report["processes"])
        accepted = report["counts"]["accepted"]
        assert _responses(client) == original and client.process.poll() is None
        time.sleep(0.15)
        after = receiver.report()
        assert after["counts"]["accepted"] == accepted
        assert after["processes"] == report["processes"]
        keep_record(record_property, "exhausted_export_window", after)
    finally:
        _close(client, receiver, record_property)


def test_real_partial_stream_header_keeps_the_original_error_and_exit_code_in_both_builds(
    phase_binaries: dict[str, Path],
    tmp_path: Path,
    record_property: Any,
) -> None:
    observed: dict[str, tuple[int, bytes, bytes]] = {}
    for variant, runtime in phase_binaries.items():
        receiver = NativePhaseReceiver(runtime)
        client = _client(runtime, tmp_path / variant, receiver, receiver.environment())
        try:
            receiver.attach(client.process.pid)
            assert client.process.stdin is not None
            client.process.stdin.write(b"\x00\x00")
            client.process.stdin.close()
            code = client.process.wait(timeout=3)
            assert client.process.stdout is not None and client.process.stderr is not None
            stdout, stderr = client.process.stdout.read(4097), client.process.stderr.read(4097)
            assert (code, stdout, stderr) == (2, b"", b"native_client_stream_frame_truncated\n")
            observed[variant] = code, stdout, stderr
        finally:
            _close(client, receiver, record_property, expected_returncode=2)
    assert observed["default"] == observed["diagnostic"]
