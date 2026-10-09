from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_git_execution_safety as bridge

_FEATURES = ("resident-protocol-v2", "git-execution-safety-v1")


def _status(*, features: tuple[str, ...] = _FEATURES, available: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        mode="on",
        available=available,
        compatible=True,
        identity=SimpleNamespace(path=Path("/runtime"), sha256="a" * 64),
        capabilities=SimpleNamespace(features=features),
    )


class _Recorder:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.successes = 0
        self.overloads = 0
        self.payloads: list[dict[str, object]] = []
        self.overrides: dict[str, object] = {}
        self.raw_output: bytes | None = None
        self.answer = True

    def reply(self) -> bytes | None:
        if not self.answer:
            return self.raw_output
        request = self.payloads[-1]["request"]
        assert isinstance(request, dict)
        envelope: dict[str, object] = {
            "schema": bridge._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + bridge._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "allowed": True,
            "resolved_path": "/usr/bin/git",
        }
        envelope.update(self.overrides)
        return json.dumps(envelope).encode()


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Recorder:
    state = _Recorder()
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: _status())
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(bridge, "native_runtime_health_snapshot", lambda *_a: SimpleNamespace(circuit_open=False))
    monkeypatch.setattr(bridge, "native_record_resident_failure", lambda *_a, reason: state.failures.append(reason))
    monkeypatch.setattr(
        bridge, "native_record_resident_success", lambda *_a: setattr(state, "successes", state.successes + 1)
    )
    monkeypatch.setattr(bridge, "native_record_overload", lambda *_a: setattr(state, "overloads", state.overloads + 1))

    def transport(*, payload: bytes, **_kw: object) -> bytes | None:
        state.payloads.append(json.loads(payload))
        return state.reply()

    monkeypatch.setattr(bridge, "native_resident_client_request", transport)
    return state


def _ask(state: _Recorder, **overrides: object) -> bridge.GitSafetyAnswer | None:
    state.overrides = overrides
    return bridge.git_execution_safety_native("resolve_binary", cwd=Path("."))


def test_valid_reply_is_returned_and_cwd_is_made_absolute(recorder: _Recorder) -> None:
    answer = _ask(recorder)

    assert answer == bridge.GitSafetyAnswer(True, "/usr/bin/git")
    request = recorder.payloads[-1]["request"]
    assert isinstance(request, dict)
    assert request["cwd"] == os.path.abspath(".")
    assert recorder.successes == 1


def test_resident_denial_is_returned_without_a_path(recorder: _Recorder) -> None:
    assert _ask(recorder, allowed=False, status="denied", code="untrusted") == bridge.GitSafetyAnswer(False, None)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        (
            {"request_sha256": "sha256:" + hashlib.sha256(b"other").hexdigest()},
            "native_git_execution_safety_schema_mismatch",
        ),
        ({"request_id": "ges-other"}, "native_git_execution_safety_schema_mismatch"),
        ({"schema": "other"}, "native_git_execution_safety_schema_mismatch"),
        ({"allowed": "yes"}, "native_git_execution_safety_schema_mismatch"),
    ],
)
def test_mismatched_replies_are_refused_and_recorded(
    recorder: _Recorder, overrides: dict[str, object], reason: str
) -> None:
    assert _ask(recorder, **overrides) is None
    assert recorder.failures == [reason]
    assert recorder.successes == 0


def test_undecodable_reply_is_refused(recorder: _Recorder) -> None:
    recorder.answer = False
    recorder.raw_output = b"not json"

    assert bridge.git_execution_safety_native("config_environment_clean") is None
    assert recorder.failures == ["native_git_execution_safety_decode_failed"]


def test_unavailable_transport_is_refused_and_recorded(recorder: _Recorder) -> None:
    recorder.answer = False
    recorder.raw_output = None

    assert bridge.git_execution_safety_native("config_environment_clean") is None
    assert recorder.failures == ["native_git_execution_safety_unavailable"]


def test_overloaded_resident_is_refused(recorder: _Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_native_error", lambda _envelope: "native_overloaded")
    recorder.answer = False
    recorder.raw_output = b"{}"

    assert bridge.git_execution_safety_native("config_environment_clean") is None
    assert recorder.overloads == 1


@pytest.mark.parametrize(
    "status",
    [
        _status(features=("resident-protocol-v2",)),
        _status(features=("git-execution-safety-v1",)),
        _status(available=False),
    ],
)
def test_missing_capability_or_runtime_never_reaches_the_resident(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch, status: SimpleNamespace
) -> None:
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: status)

    assert bridge.git_execution_safety_native("config_environment_clean") is None
    assert recorder.payloads == []


def test_open_circuit_or_missing_prerequisite_never_reaches_the_resident(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    assert bridge.git_execution_safety_native("config_environment_clean") is None

    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(bridge, "native_runtime_health_snapshot", lambda *_a: SimpleNamespace(circuit_open=True))
    assert bridge.git_execution_safety_native("config_environment_clean") is None
    assert recorder.payloads == []
