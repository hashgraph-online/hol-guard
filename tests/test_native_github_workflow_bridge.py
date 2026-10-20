"""Failure-path and framing coverage for the resident GitHub workflow bridge."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_github_workflow as bridge
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from tests.github_workflow_test_support import descriptor

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


def _describe_reply(request: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    source = descriptor()
    return _reply(
        request,
        record=source.record.to_dict(),
        command_identity=source.command_identity,
        **overrides,
    )


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> _Harness:
    return _Harness(monkeypatch)


def _describe(**overrides: Any) -> bridge.GitHubWorkflowDescriptor | None:
    return bridge.github_workflow_describe_native(
        _COMMAND,
        workspace=Path("/workspace"),
        config_path="config.toml",
        configuration={},
        sandbox={},
        policy_version="policy.v1",
        environment={"PATH": "/usr/bin"},
        **overrides,
    )


def test_describe_decodes_the_native_record_and_forwards_context(harness: _Harness) -> None:
    harness.reply = _describe_reply
    result = _describe()
    assert result == descriptor()
    request = harness.requests[0]
    assert request["mode"] == "describe"
    assert request["policy_version"] == "policy.v1"
    assert request["environment"] == {"PATH": "/usr/bin"}


def test_describe_without_gh_spelling_makes_no_round_trip(harness: _Harness) -> None:
    harness.reply = _describe_reply
    assert (
        bridge.github_workflow_describe_native(
            "ls -la",
            workspace=Path("/workspace"),
            config_path="c",
            configuration={},
            sandbox={},
            policy_version="policy.v1",
        )
        is None
    )
    assert harness.requests == []


def test_describe_requires_a_workspace(harness: _Harness) -> None:
    harness.reply = _describe_reply
    assert (
        bridge.github_workflow_describe_native(
            _COMMAND, workspace=None, config_path="c", configuration={}, sandbox={}, policy_version="p"
        )
        is None
    )
    assert harness.requests == []


@pytest.mark.parametrize(
    "mutate",
    (
        lambda reply: {**reply, "code": "none"},
        lambda reply: {**reply, "status": "error"},
        lambda reply: {**reply, "request_sha256": "sha256:" + "0" * 64},
        lambda reply: {**reply, "request_id": "other"},
        lambda reply: {**reply, "schema": "guard-other.v1"},
        lambda reply: {**reply, "record": {"schema_version": "bad"}},
        lambda reply: {**reply, "command_identity": ""},
    ),
)
def test_describe_fails_closed_on_any_unexpected_reply(harness: _Harness, mutate: Any) -> None:
    harness.reply = lambda request: mutate(_describe_reply(request))
    assert _describe() is None


@pytest.mark.parametrize(
    "status",
    (
        _status(available=False),
        _status(compatible=False),
        _status(identity=None),
        _status(capabilities=None),
        _status(capabilities=SimpleNamespace(features=frozenset({"resident-protocol-v2"}))),
    ),
)
def test_describe_fails_closed_when_the_resident_is_unavailable(harness: _Harness, status: SimpleNamespace) -> None:
    harness.status = status
    harness.reply = _describe_reply
    assert _describe() is None
    assert harness.requests == []


def test_transport_failure_is_recorded_and_fails_closed(harness: _Harness) -> None:
    harness.reply = None
    assert _describe() is None
    assert harness.failures == ["native_github_workflow_prepare_unavailable"]


@pytest.mark.parametrize(("verified", "expected"), ((True, True), (False, False), ("yes", False)))
def test_persisted_command_verification_only_trusts_an_explicit_true(
    harness: _Harness, verified: object, expected: bool
) -> None:
    harness.reply = lambda request: _reply(request, verified=verified)
    assert bridge.github_workflow_persisted_command_matches(_COMMAND, descriptor().record) is expected
    assert harness.requests[0]["mode"] == "verify"


def test_persisted_command_verification_fails_closed_on_mismatch(harness: _Harness) -> None:
    harness.reply = lambda request: _reply(request, verified=True, request_sha256="sha256:" + "0" * 64)
    assert not bridge.github_workflow_persisted_command_matches(_COMMAND, descriptor().record)


def _lineage() -> bridge.GitHubWorkflowLineage | None:
    return bridge.github_workflow_validated_lineage(
        {"request_id": "req-1"}, {"operation_id": "op-1"}, {"session_id": "sess-1"}
    )


def _lineage_reply(request: dict[str, Any], **lineage_overrides: Any) -> dict[str, Any]:
    lineage: dict[str, Any] = {
        "request_id": "req-1",
        "operation_id": "op-1",
        "session_id": "sess-1",
        "record": descriptor().record.to_dict(),
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
        record=descriptor().record,
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
