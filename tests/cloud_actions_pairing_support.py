"""A stand-in `hol-guard connect` pairing for the Cloud actions settings tests.

The settings commands read the pairing, exchange it for an AI tool's access
before writing, and end that access on restore. These tests are about the
settings file, so the pairing and Guard Cloud's answers are replaced here;
cloud_actions_access has its own tests against a real store and HTTP.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import cloud_actions_access
from codex_plugin_scanner.guard.cli.cloud_actions_access import (
    CloudActionsAccess,
    CloudActionsAccessError,
    CloudActionsPairing,
)

WS = "11111111-1111-4111-8111-111111111111"
ORIGIN = "https://hol.org"
URL = f"{ORIGIN}/api/guard/gateway/mcp"
LAUNCHER = "/opt/hol-guard/python"


def entry(tool: str, guard_home: Path | str = "/guard-home") -> dict[str, object]:
    """The bridge entry Guard writes for `tool`, with a fixed launcher."""

    args = ["-m", "codex_plugin_scanner.cli", "guard", "cloud-actions", "bridge", tool, "--guard-home", str(guard_home)]
    return {"command": LAUNCHER, "args": args}


def wanted(tool: str, guard_home: Path | str = "/guard-home") -> dict[str, object]:
    """`entry` as it reads back from the AI tool's settings file."""

    fields = entry(tool, guard_home)
    return {"type": "stdio", **fields} if tool == "claude-code" else fields


@dataclass
class FakeCloud:
    workspace_id: str | None = WS
    paired: bool = True
    exchange_error: CloudActionsAccessError | None = None
    revoke_error: CloudActionsAccessError | None = None
    exchanged: list[str] = field(default_factory=list)
    revoked: list[str | None] = field(default_factory=list)


def pair(monkeypatch: pytest.MonkeyPatch, cloud: FakeCloud | None = None) -> FakeCloud:
    cloud = cloud or FakeCloud()

    def read_pairing(store: object) -> CloudActionsPairing:
        del store
        if not cloud.paired:
            raise CloudActionsAccessError(
                "not_paired", "This computer is not paired with Guard Cloud. Run hol-guard connect first."
            )
        return CloudActionsPairing(origin=ORIGIN, workspace_id=cloud.workspace_id)

    def exchange(store: object, *, ai_tool: str) -> CloudActionsAccess:
        del store
        cloud.exchanged.append(ai_tool)
        if cloud.exchange_error is not None:
            raise cloud.exchange_error
        return CloudActionsAccess(
            access_token="exchanged-access", expires_at=time.time() + 300, workspace_id=WS, scopes=("gateway:invoke",)
        )

    def revoke(store: object, *, ai_tool: str | None) -> list[str]:
        del store
        cloud.revoked.append(ai_tool)
        if cloud.revoke_error is not None:
            raise cloud.revoke_error
        return [] if ai_tool is None else [ai_tool]

    def open_store(guard_home: Path) -> object:
        if not cloud.paired:
            raise CloudActionsAccessError(
                "not_paired", "This computer is not paired with Guard Cloud. Run hol-guard connect first."
            )
        return SimpleNamespace(guard_home=guard_home)

    monkeypatch.setattr(cloud_actions_access, "open_paired_store", open_store)
    monkeypatch.setattr(cloud_actions_access, "read_cloud_actions_pairing", read_pairing)
    monkeypatch.setattr(cloud_actions_access, "exchange_cloud_actions_access", exchange)
    monkeypatch.setattr(cloud_actions_access, "revoke_cloud_actions_access", revoke)
    monkeypatch.setattr("codex_plugin_scanner.guard.stable_guard_cli.guard_cli_launcher", lambda: LAUNCHER)
    return cloud


def guard_home_for(home: Path) -> Path:
    """The Guard home the settings commands use under `--home`."""

    from codex_plugin_scanner.guard.config import resolve_guard_home_for_user_home

    return resolve_guard_home_for_user_home(home)
