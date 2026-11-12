"""Write the per-install correlation key the resident creates, for tests.

The resident writes this file on its first evidence write. Tests that derive a
correlation before any write, or that swap the key mid-run, write the same
file here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
    COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION,
)
from codex_plugin_scanner.guard.runtime.command_activity_privacy import InstallationCorrelationKey


def write_correlation_key(guard_home: Path) -> InstallationCorrelationKey:
    """Write a fresh private key, replacing any key already there."""

    guard_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    material = secrets.token_bytes(32)
    key_id = f"correlation.v1.{hashlib.sha256(material).hexdigest()[:16]}"
    payload = {
        "schema_version": COMMAND_ACTIVITY_CORRELATION_KEY_SCHEMA_VERSION,
        "key_id": key_id,
        "material": base64.b64encode(material).decode("ascii"),
    }
    key_path = guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE
    temporary = guard_home / f".{COMMAND_ACTIVITY_CORRELATION_KEY_FILE}.tmp"
    temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    if os.name != "nt":
        temporary.chmod(0o600)
    os.replace(temporary, key_path)
    return InstallationCorrelationKey(key_id=key_id, material=material)
