from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_runtime_detectors
from codex_plugin_scanner.guard.native_runtime_detectors import (
    NativeRuntimeDetectorError,
    native_runtime_detector_entries,
)
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: dict[str, object]) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def fake_request(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        request = kwargs["request"]
        assert isinstance(request, dict)
        return {
            "request_id": request["request_id"],
            "request_sha256": native_runtime_detectors._canonical_request_sha256(request),
            **reply,
        }

    monkeypatch.setattr(native_runtime_detectors, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(native_runtime_detectors, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_runtime_detectors.native_execution, "_resident_request", fake_request)
    native_runtime_detector_entries(
        cast(
            "GuardActionEnvelope",
            SimpleNamespace(
                action_type="tool_call",
                command="ls",
                prompt_text=None,
                prompt_excerpt=None,
                mcp_tool=None,
                target_paths=(),
            ),
        ),
        workspace=None,
        guard_home=tmp_path,
        timeout_ms=30_000,
        disabled_detector_ids=(),
        enabled_categories=None,
    )
    return calls


def _reply(status: str) -> dict[str, object]:
    return {
        "schema": "guard-runtime-detector-run-result.v1",
        "status": status,
        "code": "ok",
        "payload": {"detectors": []},
    }


def test_error_status_with_ok_code_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    with pytest.raises(NativeRuntimeDetectorError, match="invalid_result"):
        _run(monkeypatch, tmp_path, _reply("error"))


def test_transport_waits_for_resident_ceiling_and_frame_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (call,) = _run(monkeypatch, tmp_path, _reply("ok"))
    assert call["timeout_seconds"] == 9.0
    assert call["max_request_bytes"] == 6 * 1024 * 1024
