"""Cursor state the native adapter reads, built the way an install leaves it."""

from __future__ import annotations

import os
import secrets
from hashlib import sha256
from pathlib import Path

import pytest

HOOK_SCRIPT_NAME = "hol-guard-cursor-hook.py"


def cursor_hook_attestation_secret_path(guard_home: Path) -> Path:
    return guard_home / "secrets" / "cursor-hook-attestation.key"


def enroll_cursor_hook_key(guard_home: Path) -> None:
    """The key a prior install enrolled; preparation never creates one."""
    path = cursor_hook_attestation_secret_path(guard_home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(secrets.token_bytes(32))
    path.chmod(0o600)


def _managed(target: Path, guard_home: Path, suffix: str, prefix: str = "hooks-") -> Path:
    digest = sha256(str(target.resolve()).encode("utf-8")).hexdigest()[:12]
    return guard_home / "managed" / "cursor" / f"{prefix}{digest}.{suffix}.json"


def cursor_hooks_backup_path(target: Path, guard_home: Path) -> Path:
    return _managed(target, guard_home, "backup")


def cursor_hooks_state_path(target: Path, guard_home: Path) -> Path:
    return _managed(target, guard_home, "state")


def cursor_mcp_state_path(target: Path, guard_home: Path) -> Path:
    return _managed(target, guard_home, "state", prefix="")


def managed_cursor_hook_script(guard_cli: list[str]) -> str:
    """A script Guard recognises as one it wrote."""
    return (
        '"""Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home."""\n'
        f"GUARD_CLI = {guard_cli!r}\n"
        "GUARD_RECOVERY_COMMAND = ['true']\n"
    )


def cursor_agent_on_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, present: bool) -> None:
    """A PATH holding only a stand-in `cursor-agent`, or nothing at all."""
    directory = tmp_path / ("cursor-bin" if present else "cursor-bin-empty")
    directory.mkdir(exist_ok=True)
    if present:
        agent = directory / ("cursor-agent.exe" if os.name == "nt" else "cursor-agent")
        agent.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        agent.chmod(0o755)
    monkeypatch.setenv("PATH", str(directory))
