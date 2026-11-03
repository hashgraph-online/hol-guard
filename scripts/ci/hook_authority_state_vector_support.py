"""Shared constants and action builders for the hook authority state vector recorder."""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard.cli import commands_support_hook_state as hook_state  # noqa: E402,F401

OUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/hook_authority_state_vectors.json.gz"
KEY = bytes(range(32))
KEY_ID = "vector-key-1"
OTHER_KEY_ID = "vector-key-2"
T0 = "2026-10-11T12:00:00.250000+00:00"
T1 = "2026-10-11T12:10:00.500000+00:00"
T2 = "2026-10-11T12:30:00.250000+00:00"
T3 = "2026-10-11T12:30:00.250001+00:00"
T4 = "2026-10-11T12:40:00.000000+00:00"
CODE = "0123456789ab"


def key_b64() -> str:
    return base64.urlsafe_b64encode(KEY).rstrip(b"=").decode("ascii")


def claude_pending_key(session_id: str, artifact_id: str) -> str:
    """The key a Claude pending permission is stored under.

    The derivation lives here rather than in the CLI module it was recorded
    from: the resident names these rows now, and the recorded vectors are the
    independent account of what the retired Python wrote.
    """

    fingerprint = hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:24]
    return f"claude_pending_permission:{session_id}:{fingerprint}"


def cursor_fingerprint(command: str) -> str:
    """The digest both Cursor state keys are built from.

    The derivation lives here rather than in the CLI module it was recorded
    from: the resident names these rows now, and the recorded vectors are the
    independent account of what the retired Python wrote.
    """

    from codex_plugin_scanner.guard.adapters.cursor_native_approval import normalize_cursor_shell_command

    return hashlib.sha256(normalize_cursor_shell_command(command).encode("utf-8")).hexdigest()[:24]


def cursor_pending_key(conversation_id: str, command: str) -> str:
    return f"cursor_pending_shell:{conversation_id}:{cursor_fingerprint(command)}"


def cursor_allow_key(conversation_id: str, command: str) -> str:
    return f"cursor_native_shell_allow:{conversation_id}:{cursor_fingerprint(command)}"


def pending_keys(session_id: str, *artifact_ids: str) -> list[str]:
    return [claude_pending_key(session_id, artifact_id) for artifact_id in artifact_ids]


def claude_artifact(artifact_id: str = "claude-code:runtime:file-read:.env", **extra: object) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "name": "Read",
        "artifact_type": "file_read_request",
        "config_path": "/workspace/.env",
        **extra,
    }


def record_notice(session: str = "s1", tool: str | None = "Read", artifact: dict | None = None, now: str = T0) -> dict:
    args: dict[str, object] = {
        "session_id": session,
        "reason": "HOL Guard intercepted Claude's attempt to read .env.",
        "artifact": artifact or claude_artifact(),
        "artifact_hash": "hash-authentic",
        "now": now,
    }
    if tool is not None:
        args["tool_name"] = tool
    return {"do": "op", "op": "claude_record_notice", "args": args}


def op(name: str, now: str = T0, **args: object) -> dict[str, object]:
    return {"do": "op", "op": name, "args": {"now": now, **args}}
