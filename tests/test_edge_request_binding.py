"""Golden vectors for binding a resident's answer to the review that asked."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_route_receipt import native_hook_route
from codex_plugin_scanner.guard.native_runtime import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "edge-request-binding.v1.json").read_text(encoding="utf-8")
)
_BINDING_FEATURE = "edge-request-binding-v1"
_FEATURES = (
    "hook-envelope-v2",
    "hook-harness-response-v1",
    "edge-self-check-v1",
    "native-resident-client-v1",
    "pre-tool-generic-authority-v1",
    "git-execution-context-v1",
)


def _install_resident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    answer,
    *,
    binding: bool = True,
) -> list[dict[str, object]]:
    """Answer every request with ``answer`` and return what the review sent."""

    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"runtime")
    status = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ready",
        identity=NativeRuntimeIdentity(
            path=runtime,
            size=runtime.stat().st_size,
            mtime_ns=runtime.stat().st_mtime_ns,
            sha256="a" * 64,
        ),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="test",
            rule_digest="b" * 64,
            build_sha="c" * 40,
            target="test",
            features=(*_FEATURES, *((_BINDING_FEATURE,) if binding else ())),
        ),
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.native_hook_edge.native_runtime_status", lambda: status)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_hook_edge.native_record_resident_failure",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_hook_edge.native_record_resident_success",
        lambda *args, **kwargs: None,
    )
    sent: list[dict[str, object]] = []

    def client(**kwargs: object) -> bytes:
        envelope = json.loads(kwargs["payload"])
        sent.append(envelope)
        return json.dumps(answer(envelope), separators=(",", ":")).encode()

    monkeypatch.setattr("codex_plugin_scanner.guard.native_hook_edge.native_resident_client_request", client)
    return sent


def _review(tmp_path: Path, **overrides: object) -> dict[str, object] | None:
    arguments: dict[str, object] = dict(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
        harness="claude",
        event="PreToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=None,
        policy_snapshot={"generation": 1},
    )
    arguments.update(overrides)
    return review_raw_hook_native(**arguments)


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda vector: vector["name"])
def test_only_an_answer_naming_this_request_is_read_as_its_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, vector: dict[str, object]
) -> None:
    # Every vector is a well-formed edge result, so shape alone cannot separate
    # them: the id the review sent is the only thing that tells them apart.
    _install_resident(tmp_path, monkeypatch, lambda envelope: vector["edge"])
    result = _review(tmp_path, request_id=VECTORS["request_id"])
    if vector["bound"]:
        assert result == vector["edge"], vector["why"]
        assert native_hook_route() == "native_resident"
    else:
        assert result is None, vector["why"]
        assert native_hook_route() == "native_fail_safe"


def test_a_review_that_was_given_no_request_id_mints_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Without an id of its own the hot path had nothing to bind: a stale answer
    # on a reused stream would have been read as this review's verdict.
    def echo(envelope: dict[str, object]) -> dict[str, object]:
        answer = json.loads(json.dumps(VECTORS["vectors"][0]["edge"]))
        answer["request_id"] = envelope["request_id"]
        answer["receipt"]["request_id"] = envelope["request_id"]
        return answer

    sent = _install_resident(tmp_path, monkeypatch, echo)
    assert _review(tmp_path) is not None
    assert _review(tmp_path) is not None
    minted = [envelope["request_id"] for envelope in sent]
    assert all(isinstance(value, str) and len(value) == 32 for value in minted)
    assert all(value.isalnum() and value.islower() for value in minted)
    assert minted[0] != minted[1]


def test_a_minted_id_still_refuses_another_request_s_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_resident(tmp_path, monkeypatch, lambda envelope: VECTORS["vectors"][0]["edge"])
    assert _review(tmp_path) is None
    assert native_hook_route() == "native_fail_safe"


def test_a_resident_that_predates_the_echo_keeps_the_caller_s_own_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Such a resident derives its own id, so minting one would fail every
    # review closed. It keeps answering, bound only when the caller named one.
    sent = _install_resident(tmp_path, monkeypatch, lambda envelope: VECTORS["vectors"][0]["edge"], binding=False)
    assert _review(tmp_path) is not None
    assert sent[-1]["request_id"] is None
    assert _review(tmp_path, request_id=VECTORS["foreign_request_id"]) is None
