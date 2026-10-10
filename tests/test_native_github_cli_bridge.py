"""Failure-path coverage for the resident GitHub CLI classification bridge."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_github_cli as bridge
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_ARGS = ("pr", "view", "1")
_FEATURES = frozenset({"resident-protocol-v2", "github-cli-classify-v1"})


def _status(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "mode": "on",
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
        self.overloads = 0
        self.successes = 0
        self.requests: list[dict[str, Any]] = []
        self.reply: Any = None
        monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: _status())
        monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/guard-home"))
        monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
        monkeypatch.setattr(
            bridge,
            "native_runtime_health_snapshot",
            lambda *_a, **_kw: SimpleNamespace(circuit_open=False),
        )
        monkeypatch.setattr(bridge, "_isolated_environment", lambda: {})
        monkeypatch.setattr(bridge, "native_resident_client_request", self._request)
        monkeypatch.setattr(
            bridge, "native_record_resident_failure", lambda _i, _h, *, reason: self.failures.append(reason)
        )
        monkeypatch.setattr(bridge, "native_record_overload", lambda _i, _h: setattr(self, "overloads", 1))
        monkeypatch.setattr(bridge, "native_record_resident_success", lambda _i, _h: setattr(self, "successes", 1))

    def _request(self, *, payload: bytes, **_kwargs: object) -> bytes | None:
        request = json.loads(payload)["request"]
        self.requests.append(request)
        reply = self.reply(request) if callable(self.reply) else self.reply
        if reply is None or isinstance(reply, bytes):
            return reply
        return json.dumps(reply).encode()


def _good_reply(request: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    reply: dict[str, Any] = {
        "schema": "guard-github-cli-classify-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + _canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "assessment": {
            "capability": "read_remote",
            "reason_code": "github.command.proven-read",
            "detail": "ok",
            "capabilities": ["read_remote"],
        },
        "pr_body_file_operand": "notes.md",
    }
    reply.update(overrides)
    return reply


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> _Harness:
    return _Harness(monkeypatch)


def test_valid_reply_is_decoded(harness: _Harness) -> None:
    harness.reply = _good_reply
    result = bridge.github_cli_classify_native(_ARGS)
    assert result == bridge.NativeGitHubCliClassification(
        "read_remote", "github.command.proven-read", "ok", ("read_remote",), "notes.md"
    )
    assert harness.successes == 1 and harness.failures == []


def test_unicode_request_digest_matches_the_rust_vector() -> None:
    request = {
        "schema": "guard-github-cli-classify-request.v1",
        "request_id": "gh-1",
        "args": ["pr", "view", "é☃\u0001\U0001f600"],
    }
    # Same vector as unicode_request_digest_matches_the_python_canonical_digest in
    # rust/crates/guard-runtime/src/github_cli_classify_op_tests.rs.
    assert _canonical_request_sha256(request) == "6dc5cc1707396312c4de9eb38f15257ec72438090b658bc4fa80a973440204d8"


def test_unicode_arguments_round_trip(harness: _Harness) -> None:
    harness.reply = _good_reply
    assert bridge.github_cli_classify_native(("pr", "view", "é☃\U0001f600")) is not None


@pytest.mark.parametrize(
    "status",
    [
        _status(mode="off"),
        _status(available=False),
        _status(compatible=False),
        _status(identity=None),
        _status(capabilities=None),
        _status(capabilities=SimpleNamespace(features=frozenset({"resident-protocol-v2"}))),
        _status(capabilities=SimpleNamespace(features=frozenset({"github-cli-classify-v1"}))),
    ],
)
def test_unavailable_runtime_returns_none_without_a_request(
    harness: _Harness, monkeypatch: pytest.MonkeyPatch, status: SimpleNamespace
) -> None:
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: status)
    harness.reply = _good_reply
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.requests == []


def test_open_circuit_returns_none(harness: _Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "native_runtime_health_snapshot", lambda *_a, **_kw: SimpleNamespace(circuit_open=True))
    harness.reply = _good_reply
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.requests == []


def test_expired_deadline_returns_none(harness: _Harness) -> None:
    harness.reply = _good_reply
    assert bridge.github_cli_classify_native(_ARGS, deadline_monotonic=0.0) is None
    assert harness.requests == []


def test_oversized_request_is_not_sent(harness: _Harness) -> None:
    harness.reply = _good_reply
    assert bridge.github_cli_classify_native(("pr", "x" * bridge._MAX_REQUEST_BYTES)) is None
    assert harness.requests == []


def test_no_resident_response_records_failure(harness: _Harness) -> None:
    harness.reply = None
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.failures == ["native_github_cli_classify_unavailable"]


def test_undecodable_response_records_failure(harness: _Harness) -> None:
    harness.reply = b"\xff not json"
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.failures == ["native_github_cli_classify_decode_failed"]


def test_overloaded_resident_records_overload_not_failure(harness: _Harness) -> None:
    harness.reply = {"error": "native_overloaded", "retryable": True}
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.overloads == 1 and harness.failures == []


@pytest.mark.parametrize(
    "tamper",
    [
        {"schema": "other"},
        {"request_id": "gh-other"},
        {"request_sha256": "sha256:" + "0" * 64},
    ],
)
def test_mismatched_binding_records_schema_failure(harness: _Harness, tamper: dict[str, str]) -> None:
    harness.reply = lambda request: _good_reply(request, **tamper)
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.failures == ["native_github_cli_classify_schema_mismatch"]


def test_non_object_response_records_schema_failure(harness: _Harness) -> None:
    harness.reply = ["not", "an", "object"]
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.failures == ["native_github_cli_classify_schema_mismatch"]


@pytest.mark.parametrize(
    "tamper",
    [
        {"status": "error"},
        {"code": "native_github_cli_classify_too_large"},
        {"assessment": None},
        {"assessment": {"capability": 1, "reason_code": "r", "detail": "d", "capabilities": ["x"]}},
        {"assessment": {"capability": "c", "reason_code": "r", "detail": "d", "capabilities": []}},
        {"assessment": {"capability": "c", "reason_code": "r", "detail": "d", "capabilities": [1]}},
        {"pr_body_file_operand": 7},
    ],
)
def test_malformed_result_records_bad_result(harness: _Harness, tamper: dict[str, Any]) -> None:
    harness.reply = lambda request: _good_reply(request, **tamper)
    assert bridge.github_cli_classify_native(_ARGS) is None
    assert harness.failures == ["native_github_cli_classify_bad_result"]


def test_unrecognized_capability_classifies_as_unknown(harness: _Harness) -> None:
    from codex_plugin_scanner.guard.runtime import github_command_capabilities as capabilities

    harness.reply = lambda request: _good_reply(
        request,
        assessment={
            "capability": "teleport_remote",
            "reason_code": "github.x",
            "detail": "d",
            "capabilities": ["teleport_remote"],
        },
    )
    capabilities._NATIVE_CACHE.clear()
    try:
        assessment = capabilities.classify_github_cli(_ARGS)
    finally:
        capabilities._NATIVE_CACHE.clear()
    assert assessment.capability == "unknown"
    assert assessment.reason_code == "github.native.malformed"
