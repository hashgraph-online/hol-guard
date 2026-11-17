"""Bounded authenticated identities for Codex hooks loaded before repair."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

NATIVE_CODEX_HOOK_COMMAND = "codex-hook-bridge"
NATIVE_CODEX_HOOK_FEATURE = "codex-hook-bridge-v1"


def python_bridge_argv(argv: Sequence[object]) -> list[object]:
    """The legacy Python bridge argv inside a native launcher prefix, else ``argv``.

    Older installs wrapped a Python bridge argv in the native subcommand, so a
    native and a Python registration of one bridge shared one identity. The
    current ``[runtime, subcommand, config]`` registration is its own identity.
    """
    values = list(argv)
    if len(values) > 3 and isinstance(values[0], str) and values[0] and values[1] == NATIVE_CODEX_HOOK_COMMAND:
        return values[2:]
    return values


def bridge_argv_sha256(argv: Sequence[object]) -> str:
    payload = json.dumps(python_bridge_argv(argv), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "NATIVE_CODEX_HOOK_COMMAND",
    "NATIVE_CODEX_HOOK_FEATURE",
    "bridge_argv_sha256",
    "python_bridge_argv",
]
