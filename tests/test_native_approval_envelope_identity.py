"""Native approval envelopes preserve opaque source and invocation identities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict, cast

import pytest

from codex_plugin_scanner.guard.native_approval_models import _build_envelope


class _Arguments(TypedDict):
    payload: dict[str, object]
    harness: str
    guard_home: Path
    home_dir: Path
    cwd: Path
    policy_snapshot: dict[str, object]
    deadline_budget_ms: int


def _arguments() -> _Arguments:
    return {
        "payload": {"event": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "printf 'synthetic'"}},
        "harness": "claude-code",
        "guard_home": Path("/synthetic/guard"),
        "home_dir": Path("/synthetic/home"),
        "cwd": Path("/synthetic/project"),
        "policy_snapshot": {"generation": 7, "policy_digest": "a" * 64, "runtime_identity": "b" * 64},
        "deadline_budget_ms": 500,
    }


def test_scoped_approval_keeps_the_exact_snapshot_source_reference() -> None:
    arguments = _arguments()
    reference = arguments["policy_snapshot"]
    assert isinstance(reference, dict)
    reference["source_input_digest"] = "c" * 64
    result = _build_envelope(**arguments)
    assert result is not None
    envelope, encoded = result
    assert envelope["policy_snapshot"] == reference
    assert json.loads(encoded)["policy_snapshot"] == reference


@pytest.mark.parametrize("digest", [None, True, "", "A" * 64, "c" * 63, "c" * 65])
def test_scoped_approval_refuses_invalid_present_source_identity(digest: object) -> None:
    arguments = _arguments()
    reference = arguments["policy_snapshot"]
    assert isinstance(reference, dict)
    reference["source_input_digest"] = digest
    assert _build_envelope(**arguments) is None


def test_outer_request_identity_preserves_original_payload_bytes() -> None:
    arguments = _arguments()
    original = json.dumps(arguments["payload"], separators=(",", ":"))
    result = _build_envelope(**arguments, request_id="native-request-1")
    assert result is not None
    envelope, encoded = result
    assert envelope["request_id"] == "native-request-1"
    assert json.dumps(envelope["raw_payload"], separators=(",", ":")) == original
    assert json.dumps(arguments["payload"], separators=(",", ":")) == original
    assert json.loads(encoded)["raw_payload"] == arguments["payload"]
    raw = envelope["raw_payload"]
    assert isinstance(raw, dict)
    assert "request_id" not in raw


@pytest.mark.parametrize("request_id", ["", True, "bad request", "x" * 300])
def test_outer_request_identity_is_bounded(request_id: object) -> None:
    assert _build_envelope(**_arguments(), request_id=cast(str, request_id)) is None


@pytest.mark.parametrize("payload_request", ["other-request", True, "bad request"])
def test_outer_request_identity_cannot_override_a_payload_identity(payload_request: object) -> None:
    arguments = _arguments()
    payload = arguments["payload"]
    assert isinstance(payload, dict)
    payload["request_id"] = payload_request
    assert _build_envelope(**arguments, request_id="native-request-1") is None


def test_identical_outer_and_payload_identity_is_retained() -> None:
    arguments = _arguments()
    payload = arguments["payload"]
    assert isinstance(payload, dict)
    payload["request_id"] = "native-request-1"
    result = _build_envelope(**arguments, request_id="native-request-1")
    assert result is not None
    assert result[0]["request_id"] == "native-request-1"
    assert result[0]["raw_payload"] == payload


def test_legacy_snapshot_and_payload_identity_are_unchanged() -> None:
    arguments = _arguments()
    result = _build_envelope(**arguments)
    assert result is not None
    assert result[0]["request_id"] is None
    assert result[0]["policy_snapshot"] == arguments["policy_snapshot"]
    payload = arguments["payload"]
    assert isinstance(payload, dict)
    payload["request_id"] = "legacy-request-1"
    result = _build_envelope(**arguments)
    assert result is not None
    assert result[0]["request_id"] == "legacy-request-1"
