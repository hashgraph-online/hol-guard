from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
    derive_proven_request_correlation,
    load_existing_installation_correlation_key,
)
from codex_plugin_scanner.guard.runtime.command_activity_privacy import InstallationCorrelationKey
from tests.command_activity_correlation_key_support import write_correlation_key
from tests.cursor_hook_payload_support import prepare_cursor_hook_payload

_STRONG_ID = "01J3ABCD9XYZ7NATIVEID"


def test_existing_key_read_is_private_bounded_and_does_not_create_or_repair(tmp_path):
    guard = tmp_path / "guard"
    assert load_existing_installation_correlation_key(guard) is None
    assert not guard.exists()
    key = write_correlation_key(guard)
    path = guard / COMMAND_ACTIVITY_CORRELATION_KEY_FILE
    before = path.stat()
    loaded = load_existing_installation_correlation_key(guard)
    assert loaded is not None and loaded.derive(b"probe") == key.derive(b"probe")
    after = path.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_mode) == (before.st_ino, before.st_mtime_ns, before.st_mode)
    if os.name != "nt":
        path.chmod(0o644)
        assert load_existing_installation_correlation_key(guard) is None
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
        path.chmod(0o600)
    path.write_bytes(b"x" * 4097)
    assert load_existing_installation_correlation_key(guard) is None


def _fixed_key() -> InstallationCorrelationKey:
    return InstallationCorrelationKey(key_id="correlation.v1.test", material=b"k" * 32)


@pytest.mark.parametrize(
    ("harness", "event", "field"),
    [
        ("codex", "PreToolUse", "tool_call_id"),
        ("codex", "PostToolUse", "tool_call_id"),
        ("codex", "PostToolUseFailure", "tool_call_id"),
        ("claude-code", "PreToolUse", "tool_use_id"),
        ("claude-code", "PostToolUse", "tool_use_id"),
        ("claude-code", "PostToolUseFailure", "tool_use_id"),
        ("pi", "PreToolUse", "tool_call_id"),
        ("pi", "PostToolUse", "tool_call_id"),
    ],
)
def test_adapter_allowlist_derives_only_native_request_ids(harness: str, event: str, field: str) -> None:
    key = _fixed_key()

    result = derive_proven_request_correlation(
        harness=harness,
        event=event,
        payload={field: _STRONG_ID},
        key=key,
    )

    assert result is not None
    assert result.harness == harness
    assert result.key_id == key.key_id


@pytest.mark.parametrize(
    "source_event",
    ["beforeShellExecution", "beforeMCPExecution", "afterShellExecution", "afterMCPExecution"],
)
def test_cursor_allowlist_uses_prepared_event_provenance(source_event: str) -> None:
    prepared = prepare_cursor_hook_payload(
        {
            "hook_event_name": source_event,
            "generation_id": _STRONG_ID,
            "command": "true",
        }
    )
    event = prepared.get("hook_event_name")
    assert isinstance(event, str)

    result = derive_proven_request_correlation(
        harness="cursor",
        event=event,
        payload=prepared,
        key=_fixed_key(),
    )

    assert result is not None
    assert result.harness == "cursor"


def test_cursor_generic_pretool_event_cannot_claim_generation_proof() -> None:
    assert (
        derive_proven_request_correlation(
            harness="cursor",
            event="PreToolUse",
            payload={"generation_id": _STRONG_ID},
            key=_fixed_key(),
        )
        is None
    )


@pytest.mark.parametrize("event", ["preToolUse", "postToolUse", "postToolUseFailure"])
def test_copilot_has_no_documented_per_tool_proof_identifier(event: str) -> None:
    assert (
        derive_proven_request_correlation(
            harness="copilot",
            event=event,
            payload={
                "sessionId": _STRONG_ID,
                "tool_call_id": _STRONG_ID,
                "toolCallId": _STRONG_ID,
            },
            key=_fixed_key(),
        )
        is None
    )


@pytest.mark.parametrize(
    ("harness", "event"),
    [
        ("opencode", "PreToolUse"),
        ("gemini", "BeforeTool"),
        ("hermes", "PreToolUse"),
        ("openclaw", "PreToolUse"),
        ("antigravity", "PreToolUse"),
        ("kimi", "PreToolUse"),
        ("grok", "PreToolUse"),
        ("zcode", "PreToolUse"),
    ],
)
def test_harnesses_without_native_proof_return_none(harness: str, event: str) -> None:
    assert (
        derive_proven_request_correlation(
            harness=harness,
            event=event,
            payload={"tool_call_id": _STRONG_ID},
            key=_fixed_key(),
        )
        is None
    )


def test_missing_or_wrong_event_proof_returns_none() -> None:
    key = _fixed_key()
    assert derive_proven_request_correlation(harness="codex", event="PreToolUse", payload={}, key=key) is None
    assert (
        derive_proven_request_correlation(
            harness="codex",
            event="PermissionRequest",
            payload={"tool_call_id": _STRONG_ID},
            key=key,
        )
        is None
    )


@pytest.mark.parametrize("value", ["1", "request-123456789012345678901", "2026-07-18T20:00:00Z", "aaaaaaaaaaaaaaaa"])
def test_allowlisted_weak_identifiers_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="strong harness identifier"):
        _ = derive_proven_request_correlation(
            harness="codex",
            event="PreToolUse",
            payload={"tool_call_id": value},
            key=_fixed_key(),
        )


def test_adapter_never_guesses_from_content_sessions_or_nested_fields() -> None:
    payload: dict[str, object] = {
        "command": _STRONG_ID,
        "content": _STRONG_ID,
        "session_id": _STRONG_ID,
        "request_id": _STRONG_ID,
        "tool_input": {"tool_call_id": _STRONG_ID},
    }

    assert (
        derive_proven_request_correlation(
            harness="codex",
            event="PreToolUse",
            payload=payload,
            key=_fixed_key(),
        )
        is None
    )


def test_invalid_key_file_is_not_silently_replaced(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    key_path = guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE
    _ = key_path.write_text("{}", encoding="ascii")

    if os.name != "nt":
        guard_home.chmod(0o700)
        key_path.chmod(0o600)
    with pytest.raises(ValueError, match="key file shape"):
        _ = load_existing_installation_correlation_key(guard_home)


def test_key_file_symlink_is_rejected(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation is not generally available")
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    target = tmp_path / "target"
    _ = target.write_text("secret", encoding="ascii")
    (guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).symlink_to(target)

    assert load_existing_installation_correlation_key(guard_home) is None
