"""Regenerate immutable vectors from the pinned, unmodified Python authority."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

REVISION = "ae33987d0c8675c36a77375e03419aee920825f6"
SOURCE = "src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py"


def main() -> None:
    raw = subprocess.check_output(["git", "show", f"{REVISION}:{SOURCE}"])
    namespace: dict[str, object] = {"__name__": "frozen_python_daemon_auth"}
    exec(compile(raw, SOURCE, "exec"), namespace)
    key = bytes(range(32)).hex()
    payloads = [
        {"z": True, "a": [None, False, 0, 17, -8], "name": "plain"},
        {"path": "/synthetic/é/中文/🚀", "control": "\b\f\n\r\t\u0000\u001f\u007f", "quotes": '"\\/'},
        {"\uffff": "high", "🚀": "astral", "a": {"z": [1, {"β": "é"}], "a": "nested"}},
        {
            "protocol_version": 1,
            "nonce": "a" * 64,
            "state_id": "synthetic-state",
            "host": "127.0.0.1",
            "port": 32123,
            "pid": 1234,
            "started_at": "2026-09-17T00:00:00Z",
            "guard_home": "/synthetic/é/guard",
            "hook_event": "PreToolUse",
            "issued_at_ms": 1789603200000,
            "expires_at_ms": 1789603205000,
        },
    ]
    values = [
        {
            "payload": payload,
            "canonical": namespace["_canonical_discovery_payload"](payload).decode(),
            "mac": namespace["_sign_discovery_payload"](key, payload),
        }
        for payload in payloads
    ]
    report = {
        "schema": "guard-claude-python-auth-vectors.v1",
        "revision": REVISION,
        "module": SOURCE,
        "module_sha256": hashlib.sha256(raw).hexdigest(),
        "bridge_modules": {
            name: hashlib.sha256(
                subprocess.check_output(
                    [
                        "git",
                        "show",
                        f"{REVISION}:src/codex_plugin_scanner/guard/{name}",
                    ]
                )
            ).hexdigest()
            for name in (
                "adapters/claude_daemon_hook_bridge.py",
                "adapters/claude_daemon_hook_transport.py",
                "adapters/codex_daemon_hook_auth.py",
                "adapters/claude_daemon_state.py",
            )
        },
        "synthetic_key_hex": key,
        "vectors": values,
    }
    target = Path("tests/fixtures/claude-launcher-pilot-auth.json")
    target.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
