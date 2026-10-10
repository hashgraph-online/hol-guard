"""Per-harness hook payload handling is answered by the native runtime.

Behaviour vectors live in ``rust/crates/guard-command/testdata`` (recorded from the
pre-port Python adapters); these tests cover the Python transport: strict request
binding, typed rejection mapping, bounded sizes, and fail-closed unavailability.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_adapter as adapter
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload


def _resident_returning(monkeypatch: pytest.MonkeyPatch, reply) -> None:
    monkeypatch.setattr(adapter, "_resolve_digest_home", lambda _home: Path("/tmp/hook-adapter-home"))
    monkeypatch.setattr(adapter, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        return reply(request)

    monkeypatch.setattr(adapter, "_resident_request", fake)


def _good(request: dict[str, object], **overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "schema": "guard-hook-adapter-result.v1",
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + adapter._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": {"text": "echo hi"},
    }
    reply.update(overrides)
    return reply


def test_bound_answer_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    assert adapter.native_command_detail("echo hi", home_dir=None) == "echo hi"


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_sha256": "sha256:" + "0" * 64},
        {"request_id": "someone-else"},
        {"schema": "wrong"},
    ],
)
def test_unbound_answers_fail_closed(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_command_detail("echo hi", home_dir=None)
    assert error.value.code == "native_hook_adapter_unavailable"


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "ok", "code": "other"},
        {"payload": None},
        {"payload": {"text": 1}},
        {"payload": {"text": "x", "extra": 1}},
        {"status": "error", "code": "arbitrary text", "payload": None},
    ],
)
def test_malformed_answers_raise(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, **overrides))
    with pytest.raises(adapter.NativeHookAdapterError):
        adapter.native_command_detail("echo hi", home_dir=None)


def test_missing_resident_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: None)
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_command_detail("echo hi", home_dir=None)
    assert error.value.code == "native_hook_adapter_unavailable"
    monkeypatch.setattr(adapter, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(adapter.NativeHookAdapterError):
        adapter.native_command_detail("echo hi", home_dir=None)


def test_cline_rejection_maps_to_cline_payload_error(monkeypatch: pytest.MonkeyPatch) -> None:
    reply = {"status": "error", "code": "native_hook_adapter_cline_payload", "payload": {"message": "no hook"}}
    _resident_returning(monkeypatch, lambda request: _good(request, **reply))
    with pytest.raises(adapter.ClinePayloadError, match="no hook"):
        adapter.native_prepare_payload("cline", {"x": 1})


def test_unsupported_harness_maps_to_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    reply = {"status": "error", "code": "native_hook_adapter_unsupported_harness", "payload": {"harness": "nope"}}
    _resident_returning(monkeypatch, lambda request: _good(request, **reply))
    with pytest.raises(ValueError, match="Unsupported Guard harness for action normalization: nope"):
        normalize_harness_payload("nope", "PreToolUse", {})


def test_unrepresentable_payload_fails_before_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_resident_request", lambda **_kwargs: pytest.fail("must not reach the resident"))
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_prepare_payload("codex", {"value": float("nan")})
    assert error.value.code == "native_hook_adapter_request_invalid"
    with pytest.raises(adapter.NativeHookAdapterError):
        adapter.native_prepare_payload("codex", {1: "non-string key"})  # type: ignore[dict-item]


def test_expired_deadline_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request))
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_action_envelope(
            "codex", "PreToolUse", {}, workspace=None, home_dir=None, deadline=adapter.time.monotonic() - 1
        )
    assert error.value.code == "native_hook_adapter_deadline_expired"


def test_envelope_must_carry_exactly_the_envelope_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident_returning(monkeypatch, lambda request: _good(request, payload=["d", "harness", "codex"]))
    with pytest.raises(adapter.NativeHookAdapterError):
        adapter.native_action_envelope("codex", "PreToolUse", {}, workspace=None, home_dir=None)


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_round_trip_preserves_key_order_and_redacts(native_approval_reuse_runtime: Path) -> None:
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi", "zeta": 1, "alpha": 2},
        "tool_response": {"stdout": "secret output"},
    }
    prepared = adapter.native_prepare_payload("codex", payload, guard_home=native_approval_reuse_runtime)
    assert list(prepared["tool_input"]) == ["command", "zeta", "alpha"]  # type: ignore[call-overload]
    envelope = normalize_harness_payload(
        "claude-code",
        "PreToolUse",
        payload,
        workspace=native_approval_reuse_runtime,
        home_dir=native_approval_reuse_runtime,
        guard_home=native_approval_reuse_runtime,
    )
    assert envelope.action_type == "shell_command"
    assert envelope.command == "echo hi"
    assert envelope.raw_payload_redacted["tool_response"] == "[redacted]"


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_rejects_unsupported_harness(native_approval_reuse_runtime: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported Guard harness"):
        normalize_harness_payload("no-such-harness", "PreToolUse", {}, guard_home=native_approval_reuse_runtime)
