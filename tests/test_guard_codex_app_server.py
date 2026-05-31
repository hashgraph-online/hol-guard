"""Focused tests for Codex app-server websocket frame handling."""

from __future__ import annotations

import struct

import pytest

from codex_plugin_scanner.guard import codex_app_server as codex_app_server_module


class _UnexpectedRecvSocket:
    def recv(self, _size: int) -> bytes:
        raise AssertionError("oversized websocket frame should be rejected before payload read")


def test_read_websocket_frame_rejects_oversized_payload_before_reading() -> None:
    pending = bytearray(bytes([0x81, 0x7F]) + struct.pack("!Q", codex_app_server_module._MAX_WEBSOCKET_FRAME_BYTES + 1))

    with pytest.raises(ValueError, match="websocket_frame_too_large"):
        codex_app_server_module._read_websocket_frame(_UnexpectedRecvSocket(), pending)
