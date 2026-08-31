from __future__ import annotations

import hmac
import os
import socket
import threading
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_runtime_resident as resident
from codex_plugin_scanner.guard.native_command_model import review_command_model_native
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code
from codex_plugin_scanner.guard.native_runtime import (
    native_runtime_status,
    review_post_tool_native,
)
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest

_NATIVE_BINARY = os.environ.get("HOL_GUARD_NATIVE_BINARY")


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
        lambda: False,
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

    first_request = _request(tmp_path, "windows-resident-first")
    second_request = _request(tmp_path, "windows-resident-second")
    try:
        first = review_post_tool_native(first_request, observe_mode=False)
        second = review_post_tool_native(second_request, observe_mode=False)
        command_model = review_command_model_native(
            "git status --short",
            guard_home=first_request.guard_home,
        )
        assert first is not None, native_resident_client_failure_code()
        assert first.decision == "allow"
        assert second is not None and second.decision == "allow"
        assert command_model is not None
        assert command_model["confidence"] == "exact"
        assert command_model["segments"][0]["executable"] == "git"
        assert (
            resident.resident_service_starts(
                executable=status.identity.path,
                identity_sha256=status.identity.sha256,
                guard_home=first_request.guard_home,
            )
            == 1
        )
    finally:
        resident.close_resident_native_runtimes()
