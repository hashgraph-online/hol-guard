"""Bound native context verdicts are reused without a classifier round trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_request_context
from codex_plugin_scanner.guard.runtime import shell_execution_context


def _payload(command: str, cwd: str | None, matched: object) -> dict:
    return {
        "schema": "guard-request-context.v1",
        "context_sha256": "sha256:" + "ab" * 32,
        "admission": {},
        "shell": {
            "context": {
                "command_text": command,
                "initial_cwd": cwd,
                "workspace_root": cwd,
                "workspace_identity": None,
                "segments": [],
                "complete": True,
                "reason_code": None,
                "directory_change_present": False,
            },
            "context_hash": "sha256:" + "cd" * 32,
            "segment_hashes": [],
            "metadata": {},
        },
        "launch": None,
        "target": None,
        "environment_secret_dump": matched,
    }


def _prime(monkeypatch: pytest.MonkeyPatch, answers: list[object]) -> list[dict]:
    captured = []
    results = iter(answers)
    monkeypatch.setattr(native_request_context, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(native_request_context, "_resolve_digest_home", lambda _: Path("/tmp"))

    def resident(**kwargs):
        request = kwargs["request"]
        captured.append(request)
        body = request["action"]["body"]
        return {
            "schema": "guard-request-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + native_request_context._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": _payload(body["script"], body["cwd"], next(results)),
        }

    monkeypatch.setattr(native_request_context, "_resident_request", resident)
    return captured


def test_unrelated_context_build_does_not_request_secret_scan(tmp_path: Path, monkeypatch) -> None:
    calls = _prime(monkeypatch, [None])
    context = shell_execution_context.model_shell_execution_context("ls", cwd=tmp_path, home_dir=tmp_path)
    assert context.native is not None
    assert context.environment_secret_dump is None
    assert "classify_environment_secrets" not in calls[0]["action"]["body"]
