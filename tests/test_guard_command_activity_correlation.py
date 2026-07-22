# pyright: reportPrivateUsage=false
from __future__ import annotations

import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.cursor_hooks import prepare_cursor_hook_payload
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
    COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION,
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
    rotate_installation_correlation_key,
)
from codex_plugin_scanner.guard.runtime.command_activity_privacy import InstallationCorrelationKey

_STRONG_ID = "01J3ABCD9XYZ7NATIVEID"


def _fixed_key() -> InstallationCorrelationKey:
    return InstallationCorrelationKey(key_id="correlation.v1.test", material=b"k" * 32)


def test_key_is_private_versioned_and_reused_deterministically(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    first = load_or_create_installation_correlation_key(guard_home)
    second = load_or_create_installation_correlation_key(guard_home)
    key_path = guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE
    raw_payload = cast(object, json.loads(key_path.read_text(encoding="ascii")))
    assert isinstance(raw_payload, dict)
    payload = cast(dict[object, object], raw_payload)

    assert first.key_id == second.key_id
    assert first.derive(b"probe") == second.derive(b"probe")
    assert first.key_id.startswith("correlation.v1.")
    assert payload["schema_version"] == COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION
    assert payload["key_id"] == first.key_id
    if os.name != "nt":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_existing_key_permissions_are_repaired(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    original = load_or_create_installation_correlation_key(guard_home)
    key_path = guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE
    if os.name == "nt":
        pytest.skip("POSIX permission modes are not available")
    key_path.chmod(0o644)

    loaded = load_or_create_installation_correlation_key(guard_home)

    assert loaded.key_id == original.key_id
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_rotation_atomically_changes_key_identity(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    original = load_or_create_installation_correlation_key(guard_home)

    rotated = rotate_installation_correlation_key(guard_home)
    loaded = load_or_create_installation_correlation_key(guard_home)

    assert rotated.key_id == loaded.key_id
    assert rotated.key_id != original.key_id
    assert rotated.derive(b"probe") != original.derive(b"probe")


def test_concurrent_creation_converges_on_one_key(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"

    def load_key(_: int) -> InstallationCorrelationKey:
        return load_or_create_installation_correlation_key(guard_home)

    with ThreadPoolExecutor(max_workers=12) as executor:
        keys = list(executor.map(load_key, range(48)))

    assert len({key.key_id for key in keys}) == 1
    assert len({key.derive(b"probe") for key in keys}) == 1
    assert not list(guard_home.glob(f".{COMMAND_ACTIVITY_CORRELATION_KEY_FILE}.*"))


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

    with pytest.raises(ValueError, match="key file shape"):
        _ = load_or_create_installation_correlation_key(guard_home)


def test_key_file_symlink_is_rejected(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation is not generally available")
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    target = tmp_path / "target"
    _ = target.write_text("secret", encoding="ascii")
    (guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE).symlink_to(target)

    with pytest.raises(ValueError, match="regular file"):
        _ = load_or_create_installation_correlation_key(guard_home)
