from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import native_workspace_review_transport as transport


def _request(request_id: str = "request-1") -> dict[str, object]:
    return {
        "request_id": request_id,
        "status": "pending",
        "harness": "codex",
        "artifact_id": "artifact-1",
        "artifact_type": "command",
        "workspace": "/workspace",
        "action_identity": "action-1",
        "action_envelope_json": {"command": "git status"},
        "launch_target": "git",
        "raw_command_text": "git status",
        "browser_intent_json": None,
        "created_at": "2026-09-25T12:00:00+00:00",
        "last_seen_at": "2026-09-25T12:00:00+00:00",
        "dedupe_count": 1,
        "guard_version": "3.0.0",
        "first_seen_guard_version": "3.0.0",
        "last_seen_guard_version": "3.0.0",
        "policy_action": "review",
        "recommended_scope": "artifact",
        "source_scope": "artifact",
        "decision_v2_json": {"action": "review"},
        "resolution_action": None,
        "resolution_scope": None,
    }


class _Store:
    def __init__(self, request: dict[str, object]):
        self.request = request
        self.sync_payloads: dict[str, object] = {}

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        if request_id != self.request["request_id"]:
            return None
        return copy.deepcopy(self.request)

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        return cast(dict[str, object] | list[object] | None, self.sync_payloads.get(state_key))

    def resolve_native_workspace_review_request(self, request_id: str, **kwargs: object) -> dict[str, object]:
        assert request_id == self.request["request_id"]
        expected = cast(dict[str, object], kwargs["expected_request"])
        assert expected["status"] == "pending"
        action = kwargs["resolution_action"]
        self.request["status"] = "resolved"
        self.request["resolution_action"] = action
        self.request["resolution_scope"] = "artifact"
        return {"resolved": True, "resolved_request": copy.deepcopy(self.request), "replayed": False}


def _status() -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native/hol-guard-runtime")),
        capabilities=SimpleNamespace(
            features=(
                "resident-protocol-v2",
                "native-workspace-review-decision-v1",
                "native-workspace-review-consumption-query-v1",
            )
        ),
    )


def _staged_digest(guard_home: Path, request_id: str) -> str:
    path = guard_home / "native-runtime" / "workspace-review-requests" / f"{request_id}.json"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verified_body(*, digest: str, replayed: bool) -> bytes:
    return json.dumps(
        {
            "status": "replayed" if replayed else "verified",
            "replayed": replayed,
            "request_id": "request-1",
            "decision": "allow",
            "claim_id": "a" * 64,
            "envelope_digest": "b" * 64,
            "request_snapshot_digest": digest,
        }
    ).encode("utf-8")


def _bind_native_client(monkeypatch: pytest.MonkeyPatch, responder) -> None:
    from codex_plugin_scanner.guard.native_resident_client import record_native_resident_client_failure_code

    monkeypatch.setattr(transport, "native_resident_client_failure_context", lambda: None)

    monkeypatch.setattr(transport, "native_runtime_status", _status)
    monkeypatch.setattr(transport, "_isolated_environment", lambda: {})

    def request(**kwargs: object) -> bytes | None:
        encoded = responder(kwargs)
        if encoded is None:
            code = kwargs.get("failure_code")
            if isinstance(code, str):
                record_native_resident_client_failure_code(code)
        return encoded

    monkeypatch.setattr(transport, "native_resident_client_request", request)
