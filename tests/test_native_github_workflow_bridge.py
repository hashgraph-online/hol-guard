"""Failure-path and framing coverage for the resident GitHub workflow bridge."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_github_workflow as bridge
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from tests.github_workflow_test_support import approval_record

_FEATURES = frozenset({"resident-protocol-v2", "github-workflow-prepare-v1"})
_COMMAND = "/usr/bin/gh issue lock 17 --repo example/repo"


def _status(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "available": True,
        "compatible": True,
        "identity": SimpleNamespace(path=Path("/runtime/hol-guard-runtime"), sha256="a" * 64),
        "capabilities": SimpleNamespace(features=_FEATURES),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class _Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.failures: list[str] = []
        self.requests: list[dict[str, Any]] = []
        self.reply: Any = None
        self.status = _status()
        monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: self.status)
        monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/guard-home"))
        monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
        monkeypatch.setattr(
            bridge, "native_runtime_health_snapshot", lambda *_a, **_kw: SimpleNamespace(circuit_open=False)
        )
        monkeypatch.setattr(bridge, "_isolated_environment", lambda: {})
        monkeypatch.setattr(bridge, "native_resident_client_request", self._request)
        monkeypatch.setattr(
            bridge, "native_record_resident_failure", lambda _i, _h, *, reason: self.failures.append(reason)
        )
        monkeypatch.setattr(bridge, "native_record_overload", lambda _i, _h: None)
        monkeypatch.setattr(bridge, "native_record_resident_success", lambda _i, _h: None)

    def _request(self, *, payload: bytes, **_kwargs: object) -> bytes | None:
        request = json.loads(payload)["request"]
        self.requests.append(request)
        reply = self.reply(request) if callable(self.reply) else self.reply
        if reply is None or isinstance(reply, bytes):
            return reply
        return json.dumps(reply).encode()


def _reply(request: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    reply: dict[str, Any] = {
        "schema": "guard-github-workflow-prepare-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + _canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
    }
    reply.update(overrides)
    return reply


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> _Harness:
    return _Harness(monkeypatch)


@pytest.mark.parametrize(("verified", "expected"), ((True, True), (False, False), ("yes", False)))
def test_persisted_command_verification_only_trusts_an_explicit_true(
    harness: _Harness, verified: object, expected: bool
) -> None:
    harness.reply = lambda request: _reply(request, verified=verified)
    assert bridge.github_workflow_persisted_command_matches(_COMMAND, approval_record()) is expected
    assert harness.requests[0]["mode"] == "verify"


def test_persisted_command_verification_fails_closed_on_mismatch(harness: _Harness) -> None:
    harness.reply = lambda request: _reply(request, verified=True, request_sha256="sha256:" + "0" * 64)
    assert not bridge.github_workflow_persisted_command_matches(_COMMAND, approval_record())


def _lineage() -> bridge.GitHubWorkflowLineage | None:
    return bridge.github_workflow_validated_lineage(
        {"request_id": "req-1"}, {"operation_id": "op-1"}, {"session_id": "sess-1"}
    )


def _lineage_reply(request: dict[str, Any], **lineage_overrides: Any) -> dict[str, Any]:
    lineage: dict[str, Any] = {
        "request_id": "req-1",
        "operation_id": "op-1",
        "session_id": "sess-1",
        "record": approval_record().to_dict(),
        "capability_id": "gwc-cap-1",
        "nonce": "nonce-1",
    }
    lineage.update(lineage_overrides)
    return _reply(request, lineage=lineage)


def test_lineage_forwards_the_rows_and_decodes_the_resident_verdict(harness: _Harness) -> None:
    harness.reply = _lineage_reply
    assert _lineage() == bridge.GitHubWorkflowLineage(
        request_id="req-1",
        operation_id="op-1",
        session_id="sess-1",
        record=approval_record(),
        capability_id="gwc-cap-1",
        nonce="nonce-1",
    )
    request = harness.requests[0]
    assert request["mode"] == "lineage"
    assert request["approval_request"] == {"request_id": "req-1"}
    assert request["operation"] == {"operation_id": "op-1"}
    assert request["session"] == {"session_id": "sess-1"}


@pytest.mark.parametrize(
    "reply",
    (
        lambda request: _reply(request, code="none"),
        lambda request: _reply(request),
        lambda request: _reply(request, lineage=[]),
        lambda request: _lineage_reply(request, request_id=""),
        lambda request: _lineage_reply(request, operation_id=None),
        lambda request: _lineage_reply(request, session_id=7),
        lambda request: _lineage_reply(request, record="record"),
        lambda request: _lineage_reply(request, record={"schema_version": "bad"}),
        lambda request: _lineage_reply(request, capability_id=""),
        lambda request: _lineage_reply(request, capability_id=None),
        lambda request: _lineage_reply(request, nonce=""),
        lambda request: _lineage_reply(request, nonce=11),
        lambda request: {**_lineage_reply(request), "request_sha256": "sha256:" + "0" * 64},
    ),
)
def test_lineage_fails_closed_on_any_unexpected_reply(harness: _Harness, reply: Any) -> None:
    harness.reply = reply
    assert _lineage() is None
