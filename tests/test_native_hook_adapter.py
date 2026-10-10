"""Per-harness hook payload handling is answered by the native runtime.

Behaviour vectors live in ``rust/crates/guard-command/testdata`` (recorded from the
pre-port Python adapters); these tests cover the Python transport: strict request
binding, typed rejection mapping, bounded sizes, and fail-closed unavailability.
"""

from __future__ import annotations

import hashlib
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


def _recording_resident(monkeypatch: pytest.MonkeyPatch, reply) -> list[dict[str, object]]:
    seen: list[dict[str, object]] = []

    def respond(request: dict[str, object]) -> dict[str, object]:
        seen.append(request)
        return reply(request)

    _resident_returning(monkeypatch, respond)
    return seen


def _wire_json(request: dict[str, object]) -> str:
    return adapter.json.dumps(request)


def _decode_wire(value: object) -> object:
    """Independent decoder of the request wire form (tags d, l, c)."""

    if not isinstance(value, list):
        return value
    tag, body = value[0], value[1:]
    if tag == "c":
        return "".join(body)
    if tag == "l":
        return [_decode_wire(item) for item in body]
    return {body[i]: _decode_wire(body[i + 1]) for i in range(0, len(body), 2)}


def test_policy_fields_reach_the_resident_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _recording_resident(monkeypatch, lambda request: _good(request, payload={"text": "x"}))
    command = "echo " + "a" * (1024 * 1024 + 7)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command, "content": "c" * 300_000, "file_path": "/tmp/" + "p" * 300_000},
        "prompt": "p" * 300_000,
    }
    assert adapter.native_command_text("Bash", payload["tool_input"], guard_home=Path("/tmp/g")) == "x"
    with pytest.raises(adapter.NativeHookAdapterError):  # the stub answer is not an envelope
        adapter.native_action_envelope("codex", "PreToolUse", payload, workspace=None, home_dir=None)
    assert len(seen) == 2
    assert _decode_wire(seen[0]["query"]["tool_input"]) == payload["tool_input"]  # type: ignore[index]
    assert _decode_wire(seen[1]["query"]["payload"]) == payload  # type: ignore[index]
    for request in seen:
        assert "guard-elided" not in _wire_json(request)


def test_long_strings_travel_in_lossless_chunks() -> None:
    tagger = adapter._Tagger()
    text = "é" * 400_000 + "\U0001f600" * 10
    tagged = tagger.tag({"k": text, "n": [text, "short"]})
    assert tagged[0] == "d" and tagged[2][0] == "c"  # type: ignore[index]
    assert all(len(part.encode()) <= 512 * 1024 for part in tagged[2][1:])  # type: ignore[index]
    assert _decode_wire(tagged) == {"k": text, "n": [text, "short"]}
    assert hashlib.sha256(text.encode()).hexdigest() in tagger.refs


@pytest.mark.parametrize(
    "payload",
    [
        {"k" * 200_000: 1},
        {f"k{index}": 1 for index in range(2100)},
        {"l": list(range(4100))},
        {"deep": __import__("functools").reduce(lambda inner, _: {"d": inner}, range(40), {})},
    ],
    ids=["key", "dict-items", "list-items", "depth"],
)
def test_shapes_the_resident_cannot_parse_fail_with_the_size_code(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]
) -> None:
    monkeypatch.setattr(adapter, "_resident_request", lambda **_kwargs: pytest.fail("must not reach the resident"))
    monkeypatch.setattr(adapter, "_resolve_digest_home", lambda _home: Path("/tmp/hook-adapter-home"))
    monkeypatch.setattr(adapter, "ensure_resident_prerequisite", lambda _home: True)
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_prepare_payload("codex", payload)
    assert error.value.code == "native_hook_adapter_request_too_large"


def test_plain_text_over_the_string_slot_fails_with_the_size_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_resident_request", lambda **_kwargs: pytest.fail("must not reach the resident"))
    monkeypatch.setattr(adapter, "_resolve_digest_home", lambda _home: Path("/tmp/hook-adapter-home"))
    monkeypatch.setattr(adapter, "ensure_resident_prerequisite", lambda _home: True)
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_command_detail("x" * (1024 * 1024 + 1), home_dir=None)
    assert error.value.code == "native_hook_adapter_request_too_large"


def test_oversize_policy_input_fails_closed_with_an_explicit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_resident_request", lambda **_kwargs: pytest.fail("must not reach the resident"))
    monkeypatch.setattr(adapter, "_resolve_digest_home", lambda _home: Path("/tmp/hook-adapter-home"))
    monkeypatch.setattr(adapter, "ensure_resident_prerequisite", lambda _home: True)
    huge = {"command": "x" * (4 * 1024 * 1024 + 1)}
    for call in (
        lambda: adapter.native_prepare_payload("codex", {"tool_input": huge}),
        lambda: adapter.native_command_text("Bash", huge),
        lambda: adapter.native_apply_patch_paths({"input": huge["command"]}),
        lambda: adapter.native_action_envelope(
            "codex", "PreToolUse", {"tool_input": huge, "tool_response": "y" * 100}, workspace=None, home_dir=None
        ),
    ):
        with pytest.raises(adapter.NativeHookAdapterError) as error:
            call()
        assert error.value.code == "native_hook_adapter_request_too_large"


def test_over_cap_envelope_request_only_substitutes_root_output_blobs(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _recording_resident(monkeypatch, lambda request: _good(request, payload=["d"]))
    blob = "o" * (3 * 1024 * 1024)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"},
        "tool_response": {"stdout": blob},
        "stdout": blob,
        "output": [blob],
    }
    with pytest.raises(adapter.NativeHookAdapterError):  # the reply is not a full envelope
        adapter.native_action_envelope("codex", "PreToolUse", payload, workspace=None, home_dir=None)
    sent = seen[0]["query"]["payload"]  # type: ignore[index]
    assert sent == [
        "d",
        "tool_name",
        "Bash",
        "tool_input",
        ["d", "command", "echo hi"],
        "tool_response",
        "[redacted]",
        "stdout",
        "[redacted]",
        "output",
        "[redacted]",
    ]


def test_digest_references_resolve_against_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    big = "r" * 100_000
    digest = hashlib.sha256(big.encode()).hexdigest()
    _recording_resident(monkeypatch, lambda request: _good(request, payload=["d", "blob", ["r", digest]]))
    assert adapter.native_prepare_payload("codex", {"blob": big}) == {"blob": big}


@pytest.mark.parametrize("answer", [["d", "blob", ["r", "0" * 64]], ["d", "blob", ["r"]], ["x", 1]])
def test_unknown_references_and_tags_fail_closed(monkeypatch: pytest.MonkeyPatch, answer: list[object]) -> None:
    _recording_resident(monkeypatch, lambda request: _good(request, payload=answer))
    with pytest.raises(adapter.NativeHookAdapterError):
        adapter.native_prepare_payload("codex", {"blob": "r" * 100_000})


def test_late_answers_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    deadline = adapter.time.monotonic() + 5

    def slow(request: dict[str, object]) -> dict[str, object]:
        monkeypatch.setattr(adapter.time, "monotonic", lambda: deadline + 1)
        return _good(request, payload=["d"] + [item for key in adapter._ENVELOPE_KEYS for item in (key, None)])

    _recording_resident(monkeypatch, slow)
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_action_envelope("codex", "PreToolUse", {}, workspace=None, home_dir=None, deadline=deadline)
    assert error.value.code == "native_hook_adapter_deadline_expired"


def test_prerequisite_time_counts_against_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    now = adapter.time.monotonic()
    clock = [now]
    monkeypatch.setattr(adapter.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(adapter, "_resolve_digest_home", lambda _home: Path("/tmp/hook-adapter-home"))

    def slow_prerequisite(_home: Path) -> bool:
        clock[0] += 10
        return True

    monkeypatch.setattr(adapter, "ensure_resident_prerequisite", slow_prerequisite)
    monkeypatch.setattr(adapter, "_resident_request", lambda **_kwargs: pytest.fail("deadline already spent"))
    with pytest.raises(adapter.NativeHookAdapterError) as error:
        adapter.native_action_envelope("codex", "PreToolUse", {}, workspace=None, home_dir=None, deadline=now + 5)
    assert error.value.code == "native_hook_adapter_deadline_expired"


def test_one_hook_invocation_asks_each_query_once(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _recording_resident(monkeypatch, lambda request: _good(request, payload={"text": "echo hi"}))
    tool_input = {"command": "echo hi"}
    with adapter.hook_adapter_memo():
        results = [adapter.native_command_text("Bash", tool_input) for _ in range(5)]
        other = adapter.native_command_text("Bash", {"command": "echo other"})
    assert results == ["echo hi"] * 5
    assert other == "echo hi"
    assert len(seen) == 2
    adapter.native_command_text("Bash", tool_input)
    adapter.native_command_text("Bash", tool_input)
    assert len(seen) == 4


def test_failures_are_not_memoized(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter([None, "echo hi"])

    def reply(request: dict[str, object]) -> dict[str, object] | None:
        answer = next(answers)
        return None if answer is None else _good(request, payload={"text": answer})

    _recording_resident(monkeypatch, reply)
    with adapter.hook_adapter_memo():
        with pytest.raises(adapter.NativeHookAdapterError):
            adapter.native_command_text("Bash", {"command": "echo hi"})
        assert adapter.native_command_text("Bash", {"command": "echo hi"}) == "echo hi"


def test_hook_scope_binds_the_hook_guard_home_for_ambient_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard import native_context

    seen_homes: list[Path | None] = []
    monkeypatch.setattr(adapter, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        seen_homes.append(native_context._BOUND_GUARD_HOME.get())
        return _good(request, payload={"text": "echo hi"})

    monkeypatch.setattr(adapter, "_resident_request", fake)
    # Other enforcement paths bind the ambient home without resetting it, so an
    # earlier test on this worker may have left one; start from a known state.
    baseline = native_context._BOUND_GUARD_HOME.set(None)
    try:
        with adapter.hook_adapter_memo(tmp_path):
            assert adapter.native_command_text("Bash", {"command": "echo hi"}) == "echo hi"
        assert seen_homes == [tmp_path]
        assert native_context._BOUND_GUARD_HOME.get() is None
    finally:
        native_context._BOUND_GUARD_HOME.reset(baseline)
