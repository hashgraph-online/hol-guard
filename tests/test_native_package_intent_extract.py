"""Shim tests for the native package-intent extract client: transport only."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_package_authority

_FEATURES = ["resident-protocol-v2", "package-authority-v1", "package-intent-extract-v1"]


def _install(monkeypatch: pytest.MonkeyPatch, *, features: list[str] = _FEATURES, payload: object = None):
    sent: list[dict[str, Any]] = []
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/runtime"), sha256="0" * 64),
        capabilities=SimpleNamespace(features=features),
    )

    def fake(*, payload: bytes, **_kwargs: object) -> bytes:
        envelope = json.loads(payload)
        sent.append(envelope)
        return json.dumps(
            {
                "schema": "guard-package-authority-result.v1",
                "request_id": envelope["request"]["request_id"],
                "request_sha256": "0" * 64,
                "status": "ok",
                "code": "ok",
                "payload": reply_payload,
            }
        ).encode()

    reply_payload = payload
    monkeypatch.setattr(native_package_authority, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_package_authority, "_isolated_environment", lambda: {})
    monkeypatch.setattr(native_package_authority, "native_resident_client_request", fake)
    monkeypatch.setattr(native_package_authority, "native_record_resident_failure", lambda *_a, **_k: None)
    monkeypatch.setattr(native_package_authority, "native_record_resident_success", lambda *_a, **_k: None)
    return sent


def test_one_request_carries_the_whole_call(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install(monkeypatch)

    intent = native_package_authority.package_intent_extract_native(
        "Bash",
        {
            "command": "npm install left-pad",
            "timeout": 30,
            "score": float("nan"),
            "nested": [{"commands": ["pip install requests"]}, True],
            "bad": "\ud800",
            "bad-\udfff": {"command": "npm install kept"},
            7: "dropped",
        },
        action_envelope_command="",
        workspace=tmp_path,
        environment={"PATH": "/usr/bin"},
        guard_home=tmp_path,
    )

    assert intent is None
    assert len(sent) == 1
    assert sent[0]["operation"] == "package_intent_extract"
    request = sent[0]["request"]
    assert request["tool_name"] == "Bash"
    # Only strings, lists and objects can hold a command; nothing else spends
    # the budget or fails the encoding.
    assert request["arguments"] == {
        "command": "npm install left-pad",
        "timeout": None,
        "score": None,
        "nested": [{"commands": ["pip install requests"]}, None],
        "bad": None,
        # The value under a key JSON cannot carry is still walked.
        repr("bad-\udfff"): {"command": "npm install kept"},
    }
    assert request["action_envelope_command"] is None
    assert request["workspace"] == str(tmp_path)
    assert request["environment"] == {"PATH": "/usr/bin"}


def test_nesting_past_the_bound_is_sent_as_null(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install(monkeypatch)
    deep: object = "npm install left-pad"
    for _ in range(200):
        deep = [deep]

    native_package_authority.package_intent_extract_native(
        "bash", {"command": "ls", "deep": deep}, action_envelope_command=None, guard_home=tmp_path
    )

    depth, node = 0, sent[0]["request"]["arguments"]["deep"]
    while isinstance(node, list):
        depth, node = depth + 1, node[0]
    assert node is None
    assert depth < 128


def test_a_runtime_without_the_feature_is_never_asked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install(monkeypatch, features=_FEATURES[:2])

    assert (
        native_package_authority.package_intent_extract_native(
            "bash", {"command": "npm install left-pad"}, action_envelope_command=None, guard_home=tmp_path
        )
        is None
    )
    assert sent == []


def test_a_non_string_tool_name_names_no_shell(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install(monkeypatch)

    native_package_authority.package_intent_extract_native(
        7, {"command": "ls"}, action_envelope_command="npm install left-pad", guard_home=tmp_path
    )

    assert sent[0]["request"]["tool_name"] is None
    assert sent[0]["request"]["action_envelope_command"] == "npm install left-pad"


_BUDGET = native_package_authority._EXTRACT_MAX_REQUEST_BYTES - native_package_authority._EXTRACT_ENVELOPE_RESERVE_BYTES


def test_arguments_too_large_to_send_leave_the_envelope_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install(monkeypatch)

    native_package_authority.package_intent_extract_native(
        "mcp__files__write",
        {"command": "npm install left-pad", "content": "\u00e9" * (1024 * 1024)},
        action_envelope_command="npm install left-pad",
        guard_home=tmp_path,
    )

    assert len(sent) == 1
    assert sent[0]["request"]["arguments"] is None
    assert sent[0]["request"]["action_envelope_command"] == "npm install left-pad"


def test_arguments_and_envelope_too_large_together_are_asked_in_turn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install(monkeypatch)
    arguments = {"argv": ["npm", "install", "left-pad"], "content": "x" * (_BUDGET - 128 * 1024)}
    envelope = "npm install left-pad " + "y" * (256 * 1024)

    native_package_authority.package_intent_extract_native(
        "bash", arguments, action_envelope_command=envelope, guard_home=tmp_path
    )

    # The resident walks the arguments before the envelope command, so they
    # go first and whole; the envelope command follows only when they name
    # no package.
    assert len(sent) == 2
    assert sent[0]["request"]["arguments"] == arguments
    assert sent[0]["request"]["action_envelope_command"] is None
    assert sent[1]["request"]["arguments"] is None
    assert sent[1]["request"]["action_envelope_command"] == envelope
    assert sent[0]["request"]["request_id"] != sent[1]["request"]["request_id"]


def test_an_intent_in_the_arguments_ends_the_turns(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install(monkeypatch)
    intent = object()
    monkeypatch.setattr(native_package_authority, "_intent_from_response", lambda *_a, **_k: intent)
    arguments = {"argv": ["npm", "install", "left-pad"], "content": "x" * (_BUDGET - 128 * 1024)}

    answer = native_package_authority.package_intent_extract_native(
        "bash", arguments, action_envelope_command="pip install " + "y" * (256 * 1024), guard_home=tmp_path
    )

    assert answer is intent
    assert len(sent) == 1
    assert sent[0]["request"]["action_envelope_command"] is None


def test_arguments_within_the_budget_are_sent_whole(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install(monkeypatch)
    arguments = {"command": "npm install left-pad", "content": "x" * (1024 * 1024)}

    native_package_authority.package_intent_extract_native(
        "bash", arguments, action_envelope_command=None, guard_home=tmp_path
    )

    assert sent[0]["request"]["arguments"] == arguments
