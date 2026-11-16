"""A Claude daemon hook command written before the native runtime.

Guard installs the runtime's own `claude-hook-bridge` command, and an install
without a runtime stops and asks for repair, so no Python launcher is left. A
frozen hook command an older build wrote must still block the call rather than
let it through.
"""

from __future__ import annotations

import json
import time

import pytest

from codex_plugin_scanner.guard import claude_hook_entry as claude_code


def test_a_stale_frozen_daemon_hook_blocks_and_asks_for_repair(capsys: pytest.CaptureFixture[str]) -> None:
    result = claude_code.run_frozen_claude_hook([claude_code.CLAUDE_GUARD_DAEMON_HOOK_MARKER, "{}"])

    captured = capsys.readouterr()
    # Claude Code blocks a tool call on exit code 2 and shows stderr.
    assert result == 2
    assert captured.out == ""
    assert "hol-guard repair" in captured.err


def test_remaining_hint_preserves_unicode_and_omits_itself_when_it_will_not_fit() -> None:
    from scripts.daemon_hook_client import (
        _MAX_HOOK_REQUEST_BYTES,
        _with_remaining_hint,
    )

    prompt = "é" * 200_000
    original = json.dumps(
        {"hook_event_name": "PreToolUse", "prompt": prompt},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    ascii_form = json.dumps(json.loads(original), ensure_ascii=True, separators=(",", ":"))
    assert len(original.encode("utf-8")) < _MAX_HOOK_REQUEST_BYTES < len(ascii_form.encode("utf-8"))
    hinted = _with_remaining_hint(original, time.monotonic() + 5)
    parsed = json.loads(hinted)
    assert parsed["prompt"] == prompt
    assert "guard_remaining_ms" in parsed
    assert "\\u00e9" not in hinted
    assert len(hinted.encode("utf-8")) <= _MAX_HOOK_REQUEST_BYTES

    prefix = '{"hook_event_name":"PreToolUse","blob":"'
    suffix = '"}'
    room = _MAX_HOOK_REQUEST_BYTES - len(prefix.encode("utf-8")) - len(suffix.encode("utf-8"))
    packed = prefix + ("a" * room) + suffix
    assert len(packed.encode("utf-8")) == _MAX_HOOK_REQUEST_BYTES
    assert _with_remaining_hint(packed, time.monotonic() + 5) == packed
