from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

from codex_plugin_scanner.guard import native_compound_git_inspection as bridge
from codex_plugin_scanner.guard.native_compound_git_inspection import CompoundGitAnswer
from codex_plugin_scanner.guard.native_path_anchor import anchor_to_process_directory
from codex_plugin_scanner.guard.runtime.shell_execution_context import ShellExecutionSegment

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.runtime.shell_execution_context import ShellExecutionContext

_FEATURES = ("resident-protocol-v2", "compound-git-inspection-v1")


def _status(*, features: tuple[str, ...] = _FEATURES, available: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        mode="on",
        available=available,
        compatible=True,
        identity=SimpleNamespace(path=Path("/runtime"), sha256="a" * 64),
        capabilities=SimpleNamespace(features=features),
    )


def _segment(tokens: tuple[str, ...], cwd: Path | None) -> ShellExecutionSegment:
    return ShellExecutionSegment(
        tokens=tokens,
        segment_index=0,
        control_before=(),
        control_after=("&&",),
        effective_cwd=cwd,
        cwd_identity=None,
        cwd_path_proofs=(),
        cwd_source="test",
        directory_stack=(),
        complete=True,
        directory_operation=None,
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
            "value": "~/repo",
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


def _ask(state: _Recorder, **overrides: object) -> CompoundGitAnswer:
    state.overrides = overrides
    return bridge.compound_git_inspection_native("home_git_c_path", command_text="git -C ~/repo status")


def test_valid_reply_is_returned_with_the_extracted_value(recorder: _Recorder) -> None:
    assert _ask(recorder) == CompoundGitAnswer(True, "~/repo", None)
    assert recorder.successes == 1


def test_request_carries_absolute_paths_and_modeled_segments(recorder: _Recorder, tmp_path: Path) -> None:
    segment = _segment(("git", "status"), Path("relative/dir"))
    bridge.compound_git_inspection_native(
        "segment", segments=(segment,), complete=True, home_dir=Path("home"), cwd=Path(".")
    )
    request = recorder.payloads[-1]["request"]
    assert isinstance(request, dict)
    assert request["segments"] == [
        {
            "tokens": ["git", "status"],
            "control_before": [],
            "control_after": ["&&"],
            "effective_cwd": os.path.join(os.getcwd(), "relative/dir"),
        }
    ]
    assert request["home_dir"] == os.path.join(os.getcwd(), "home")
    assert request["cwd"] == os.path.join(os.getcwd(), ".")
    assert request["complete"] is True
    assert request["check"] == "segment"
    assert str(request["request_id"]).startswith("cgi-")


def test_resident_denial_is_a_typed_error_without_a_value(recorder: _Recorder) -> None:
    answer = _ask(recorder, allowed=False, status="error", code="native_compound_git_inspection_invalid")
    assert answer == CompoundGitAnswer(False, None, "native_compound_git_inspection_invalid")


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + hashlib.sha256(b"other").hexdigest()},
        {"request_id": "cgi-other"},
        {"schema": "other"},
        {"allowed": "yes"},
    ],
)
def test_mismatched_replies_are_denied_and_recorded(recorder: _Recorder, overrides: dict[str, object]) -> None:
    answer = _ask(recorder, **overrides)
    assert answer == CompoundGitAnswer(False, None, "native_compound_git_inspection_schema_mismatch")
    assert recorder.failures == ["native_compound_git_inspection_schema_mismatch"]
    assert recorder.successes == 0


def test_undecodable_reply_is_denied(recorder: _Recorder) -> None:
    recorder.answer = False
    recorder.raw_output = b"not json"
    answer = bridge.compound_git_inspection_native("repository_path", value=".")
    assert answer.allowed is False
    assert answer.error_code == "native_compound_git_inspection_decode_failed"
    assert recorder.failures == ["native_compound_git_inspection_decode_failed"]


def test_unavailable_transport_is_denied_and_recorded(recorder: _Recorder) -> None:
    recorder.answer = False
    recorder.raw_output = None
    answer = bridge.compound_git_inspection_native("repository_path", value=".")
    assert answer == CompoundGitAnswer(False, None, "native_compound_git_inspection_unavailable")
    assert recorder.failures == ["native_compound_git_inspection_unavailable"]


def test_overloaded_resident_is_denied(recorder: _Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_native_error", lambda _envelope: "native_overloaded")
    recorder.answer = False
    recorder.raw_output = b"{}"
    assert bridge.compound_git_inspection_native("repository_path", value=".").allowed is False
    assert recorder.overloads == 1


@pytest.mark.parametrize(
    "status",
    [
        _status(features=("resident-protocol-v2",)),
        _status(features=("compound-git-inspection-v1",)),
        _status(available=False),
    ],
)
def test_missing_capability_or_runtime_never_reaches_the_resident(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch, status: SimpleNamespace
) -> None:
    monkeypatch.setattr(bridge, "native_runtime_status", lambda **_kw: status)
    answer = bridge.compound_git_inspection_native("repository_path", value=".")
    assert answer == CompoundGitAnswer(False, None, "native_compound_git_inspection_unavailable")
    assert recorder.payloads == []


def test_open_circuit_or_missing_prerequisite_never_reaches_the_resident(
    recorder: _Recorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    assert bridge.compound_git_inspection_native("repository_path", value=".").allowed is False
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(bridge, "native_runtime_health_snapshot", lambda *_a: SimpleNamespace(circuit_open=True))
    assert bridge.compound_git_inspection_native("repository_path", value=".").allowed is False
    assert recorder.payloads == []


def test_batched_pathspecs_are_one_resident_request(recorder: _Recorder) -> None:
    answer = bridge.compound_git_inspection_native("cached_diff_pathspecs", values=("src", ":!vendor", "docs"))
    assert answer.allowed is True
    assert len(recorder.payloads) == 1
    request = recorder.payloads[0]["request"]
    assert isinstance(request, dict)
    assert request["check"] == "cached_diff_pathspecs"
    assert request["values"] == ["src", ":!vendor", "docs"]
    assert "value" not in request


def test_cached_diff_operands_make_one_resident_request(recorder: _Recorder) -> None:
    from codex_plugin_scanner.guard.runtime.git_index_inspection import _cached_diff_operands_are_safe

    operands = ("--cached", "--", *(f"path{index}" for index in range(16)))
    assert _cached_diff_operands_are_safe(operands) is True
    assert len(recorder.payloads) == 1
    assert _cached_diff_operands_are_safe(("--cached", "--")) is False
    assert len(recorder.payloads) == 1


def test_compound_inspection_skips_the_resident_for_shapes_that_cannot_match(recorder: _Recorder) -> None:
    from codex_plugin_scanner.guard.runtime.compound_git_inspection import is_low_risk_compound_git_inspection

    cd = replace(_segment(("cd", "repo"), Path("/repo")), directory_operation="cd")
    git = _segment(("git", "status"), Path("/repo"))
    incomplete = SimpleNamespace(complete=False, segments=(cd, git))
    single = SimpleNamespace(complete=True, segments=(git,))
    no_cd = SimpleNamespace(complete=True, segments=(git, git))
    for context in (incomplete, single, no_cd):
        assert is_low_risk_compound_git_inspection(cast("ShellExecutionContext", context)) is False
    assert recorder.payloads == []
    complete = SimpleNamespace(complete=True, segments=(cd, git))
    assert is_low_risk_compound_git_inspection(cast("ShellExecutionContext", complete)) is True
    assert len(recorder.payloads) == 1


def test_relative_paths_are_anchored_with_the_shared_helper() -> None:
    assert anchor_to_process_directory("a/b") == os.path.join(os.getcwd(), "a/b")
    absolute = os.path.abspath(os.sep)
    assert anchor_to_process_directory(absolute) == absolute
