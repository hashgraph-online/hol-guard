from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

import codex_plugin_scanner.guard.native_runtime_resident as resident
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_approval_errors import FINITE_FAILURE_CODES
from codex_plugin_scanner.guard.native_command_model import review_command_model_native
from codex_plugin_scanner.guard.native_decision_receipt import receipt_matches_edge, validate_native_decision_receipt
from codex_plugin_scanner.guard.native_policy_test_support import native_policy_snapshot
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code
from codex_plugin_scanner.guard.native_runtime import (
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.native_runtime_resilience import native_runtime_health_snapshot
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest
from codex_plugin_scanner.guard.windows_paths import (
    windows_process_creation_time,
    windows_process_liveness,
    windows_terminate_process_if_creation_time,
)

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")


def _failure_code(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) and value in FINITE_FAILURE_CODES else "other"


def _review_failure_evidence(
    request: HookReviewRequest, snapshot: Mapping[str, object], captured: Mapping[str, Any]
) -> dict[str, object]:
    """Classify the original failure without another request or raw output."""
    health = native_runtime_health_snapshot(str(snapshot.get("runtime_identity")), request.guard_home)
    evidence: dict[str, object] = {
        "native_client_calls": captured["calls"],
        "native_client_returned": captured["returned"],
        "client_failure_code": _failure_code(native_resident_client_failure_code()),
        "health_reason": _failure_code(health.reason),
        "resident_failures": health.resident_failures,
        "overloads": health.overloads,
        "circuit_open": health.circuit_open,
    }
    output = captured.get("output")
    evidence["response_present"] = output is not None
    if not isinstance(output, bytes) or len(output) > 2 * 1024 * 1024:
        evidence["response_shape"] = "none" if output is None else "invalid_type_or_bound"
        return evidence
    evidence["response_sha256"] = hashlib.sha256(output).hexdigest()
    try:
        payload = json.loads(output)
    except (ValueError, RecursionError):
        evidence["response_shape"] = "invalid_json"
        return evidence
    if not isinstance(payload, dict):
        evidence["response_shape"] = "non_object"
        return evidence
    evidence["native_error"] = _failure_code(payload.get("error"))
    edge = payload.get("schema") == "guard-hook-edge-result.v2"
    evidence["response_shape"] = "hook_edge" if edge else "other_object"
    if edge:
        receipt = validate_native_decision_receipt(payload.get("receipt"))
        evidence["receipt_valid"] = receipt is not None
        evidence["receipt_matches_edge"] = receipt_matches_edge(payload, receipt)
        if receipt is not None:
            evidence["receipt_matches_ack"] = all(
                receipt.get(field) == snapshot.get(source)
                for field, source in (
                    ("policy_generation", "generation"),
                    ("policy_digest", "policy_digest"),
                    ("runtime_identity", "runtime_identity"),
                )
            )
    return evidence


def _require_initial_allow(request: HookReviewRequest, snapshot: Mapping[str, object]) -> None:
    original = native_runtime.native_resident_client_request
    captured: dict[str, Any] = {"calls": 0, "returned": False}

    def observe(**kwargs: Any) -> bytes | None:
        captured["calls"] += 1
        output = original(**kwargs)
        captured.update(returned=True, output=output)
        return output

    with patch.object(native_runtime, "native_resident_client_request", observe):
        result = review_post_tool_native(request, observe_mode=False, policy_snapshot=snapshot)
    # Parse evidence only after the original operation failed. This retains
    # the original assertion, request budget and single client invocation.
    assert result is not None and result.decision == "allow", _review_failure_evidence(request, snapshot, captured)


def _request(tmp_path: Path, request_id: str) -> HookReviewRequest:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700, exist_ok=True)
    return HookReviewRequest(
        harness="claude-code",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_response": [{"type": "text", "text": "const value = 1;\n"}],
        },
        payload_kind="inline",
        config_path=None,
        cwd=tmp_path,
        home_dir=tmp_path,
        guard_home=guard_home,
        source_scope="project",
        request_id=request_id,
    )


def _rust_resident_state_signature(guard_home: Path) -> tuple[tuple[object, ...], ...]:
    state_paths = sorted((guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))
    signatures: list[tuple[object, ...]] = []
    for state_path in state_paths:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        assert isinstance(payload, dict)
        signatures.append(
            tuple(payload.get(field) for field in ("generation", "process_id", "owner_process_id", "runtime_sha256"))
        )
    return tuple(signatures)


def test_invalid_loopback_server_proof_receives_no_authenticated_payload() -> None:
    token = b"t" * resident._AUTH_TOKEN_BYTES
    received_after_invalid_proof: list[bytes] = []
    ready = threading.Event()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()[:2]

        def malicious_server() -> None:
            ready.set()
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1.0)
                nonce = resident._read_exact(connection, resident._AUTH_NONCE_BYTES)
                assert nonce is not None
                connection.sendall(b"\x00" * resident._AUTH_PROOF_BYTES)
                try:
                    extra = connection.recv(4096)
                except OSError:
                    extra = b""
                received_after_invalid_proof.append(extra)

        thread = threading.Thread(target=malicious_server, daemon=True)
        thread.start()
        assert ready.wait(timeout=1.0)
        client = resident._authenticated_loopback_client(
            (str(host), int(port)),
            token,
            timeout_seconds=1.0,
        )
        assert client is None
        thread.join(timeout=2.0)

    assert received_after_invalid_proof == [b""]


def test_loopback_proof_is_role_bound_and_matches_known_vector() -> None:
    token = bytes([7]) * resident._AUTH_TOKEN_BYTES
    nonce = bytes([9]) * resident._AUTH_NONCE_BYTES
    server = resident._proof(token, resident._SERVER_PROOF_LABEL, nonce)
    client = resident._proof(token, resident._CLIENT_PROOF_LABEL, nonce)
    assert server.hex() == "b819898f11878c1c148423d0361a9de20d9eca3bb86ce1214cee957f95bb06c4"
    assert client.hex() == "fef83d9ff5988922ef5c4c7b54d9c666abf42fdfa839448b579f650741d06d97"
    assert len(server) == resident._AUTH_PROOF_BYTES
    assert not hmac.compare_digest(server, client)


def test_windows_service_rotates_auth_secret_and_stays_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "runtime.exe"
    executable.write_bytes(b"runtime")
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    service = resident._ResidentService(
        executable=executable,
        identity_sha256="a" * 64,
        guard_home=guard_home,
        environment={},
    )
    service.loopback_address = ("127.0.0.1", 65534)
    generated = iter(
        (
            b"a" * resident._AUTH_TOKEN_BYTES,
            b"b" * resident._AUTH_TOKEN_BYTES,
        )
    )
    observed: list[bytes | None] = []

    monkeypatch.setattr(resident.os, "name", "nt")
    monkeypatch.setattr(
        resident.secrets,
        "token_bytes",
        lambda _size: next(generated),
    )
    monkeypatch.setattr(
        service,
        "_transport_accepts_authenticated_connections",
        lambda *, timeout_seconds: timeout_seconds < 0,
    )
    monkeypatch.setattr(
        service,
        "_run",
        lambda _stop_event, auth_token, _generation: observed.append(auth_token),
    )

    assert not service._ensure_started(timeout_seconds=0.1)
    assert not service._ensure_started(timeout_seconds=0.1)
    assert observed == [
        b"a" * resident._AUTH_TOKEN_BYTES,
        b"b" * resident._AUTH_TOKEN_BYTES,
    ]
    assert service.starts == 2

    service.close()
    assert not service._ensure_started(timeout_seconds=0.1)
    assert service._auth_token is None


@pytest.mark.skipif(
    os.name != "nt" or not _NATIVE_BINARY,
    reason="compiled Windows native runtime is required",
)
def test_windows_native_runtime_reuses_authenticated_resident_service(
    tmp_path: Path,
) -> None:
    status = native_runtime_status()
    assert status.available and status.compatible, status
    assert status.identity is not None
    assert status.capabilities is not None
    assert "authenticated-loopback-resident-v1" in status.capabilities.features
    assert "resident-command-model-shadow-v1" in status.capabilities.features
    assert "pre-tool-command-model-shadow-v1" in status.capabilities.features

    first_request = _request(tmp_path, "windows-resident-first")
    second_request = _request(tmp_path, "windows-resident-second")
    try:
        with native_policy_snapshot(first_request.guard_home) as snapshot:
            first = review_post_tool_native(first_request, observe_mode=False, policy_snapshot=snapshot)
            first_state = _rust_resident_state_signature(first_request.guard_home)
            second = review_post_tool_native(second_request, observe_mode=False, policy_snapshot=snapshot)
            command_model = review_command_model_native(
                "git status --short",
                guard_home=first_request.guard_home,
            )
            command_failure = native_resident_client_failure_code()
        second_state = _rust_resident_state_signature(first_request.guard_home)
        assert first is not None, native_resident_client_failure_code()
        assert first.decision == "allow"
        assert second is not None and second.decision == "allow"
        assert len(first_state) == 1
        assert second_state == first_state
        assert command_model is not None, command_failure
        assert command_model["confidence"] == "exact"
        assert command_model["segments"][0]["executable"] == "git"
    finally:
        resident.close_resident_native_runtimes()


@pytest.mark.skipif(
    os.name != "nt" or not _NATIVE_BINARY,
    reason="compiled Windows native runtime is required",
)
def test_windows_abrupt_supervisor_exit_retires_its_serving_child(tmp_path: Path) -> None:
    request = _request(tmp_path, "windows-supervisor-crash")
    serving_identity: tuple[int, int] | None = None
    try:
        with native_policy_snapshot(request.guard_home) as snapshot:
            _require_initial_allow(request, snapshot)
            states = list((request.guard_home / "native-runtime").glob("resident-v3-*/generation-*.json"))
            assert len(states) == 1
            state = json.loads(states[0].read_text(encoding="utf-8"))
            supervisor = int(state["owner_process_id"])
            serving = int(state["process_id"])
            owner_marker = str(state["owner_process_start_marker"])
            serving_marker = str(state["process_start_marker"])
            assert owner_marker.startswith("windows:") and serving_marker.startswith("windows:")
            owner_creation = int(owner_marker.removeprefix("windows:"), 16)
            serving_creation = int(serving_marker.removeprefix("windows:"), 16)
            assert supervisor != serving and supervisor != os.getpid()
            assert windows_process_creation_time(supervisor) == owner_creation
            assert windows_process_creation_time(serving) == serving_creation
            serving_identity = (serving, serving_creation)
            assert windows_process_liveness(serving) is True
            assert windows_terminate_process_if_creation_time(supervisor, owner_creation)
            deadline = time.monotonic() + 2.0
            while windows_process_liveness(serving) is not False and time.monotonic() < deadline:
                time.sleep(0.01)
            assert windows_process_liveness(serving) is False, "serving child survived abrupt supervisor exit"
    finally:
        if serving_identity is not None:
            windows_terminate_process_if_creation_time(*serving_identity)
        resident.close_resident_native_runtimes()
