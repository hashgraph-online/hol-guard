"""Shared fixtures for native policy snapshot tests."""

from __future__ import annotations

import ctypes
import json
import time
import types
from pathlib import Path
from types import SimpleNamespace


def _config() -> dict[str, object]:
    return {
        "mode": "prompt",
        "protection_posture": "protected",
        "security_level": "balanced",
        "default_action": "warn",
        "unknown_publisher_action": "review",
        "changed_hash_action": "require-reapproval",
        "new_network_domain_action": "warn",
        "subprocess_action": "warn",
        "risk_actions": {"prompt_injection": "block"},
        "harness_risk_actions": {},
        "harness_actions": {},
        "publisher_actions": {},
        "artifact_actions": {},
        "sandbox_analysis": "off",
        "receipt_redaction_level": "full",
    }


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/tmp/hol-guard-runtime"), sha256="a" * 64),
        capabilities=SimpleNamespace(
            rule_digest="b" * 64,
            features=(
                "resident-protocol-v2",
                "policy-snapshot-v3",
                "policy-snapshot-push-v1",
                "native-policy-in-memory-v1",
                "native-resident-client-v1",
            ),
        ),
    )


def _ack(payload: bytes) -> bytes:
    snapshot = json.loads(payload)["request"]["snapshot"]
    return json.dumps(
        {
            "status": "accepted",
            "generation": snapshot["generation"],
            "policy_digest": snapshot["policy_digest"],
            "idempotent": False,
        }
    ).encode()


class _DeterministicClock:
    def __init__(self) -> None:
        self.wall = time.time()
        self.monotonic = time.monotonic()

    def wall_time(self) -> float:
        return self.wall

    def monotonic_time(self) -> float:
        return self.monotonic


def _fake_windows_snapshot_kernel(
    data: bytes,
    *,
    reported_size: int | None = None,
    read_result: bool = True,
) -> tuple[object, types.SimpleNamespace, list[object]]:
    offset = 0
    closed: list[object] = []
    expected_size = len(data) if reported_size is None else reported_size

    def read_file(
        _handle: object,
        buffer: object,
        request_size: int,
        count_pointer: object,
        _overlapped: object,
    ) -> int:
        nonlocal offset
        if not read_result:
            return 0
        chunk = data[offset : offset + request_size]
        ctypes.memmove(buffer, chunk, len(chunk))
        ctypes.cast(count_pointer, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(chunk)
        offset += len(chunk)
        return 1

    kernel32 = types.SimpleNamespace(ReadFile=read_file)
    information = types.SimpleNamespace(
        nFileSizeHigh=expected_size >> 32,
        nFileSizeLow=expected_size & 0xFFFFFFFF,
    )
    return kernel32, information, closed
