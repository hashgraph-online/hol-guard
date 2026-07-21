"""Small dependency-light runtime boundary for the Codex daemon bridge."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol, TypedDict


class BridgeConfig(TypedDict):
    state_path: str
    manifest_path: str
    fallback_command: tuple[str, ...]
    start_command: tuple[str, ...]
    query: str
    hook_timeouts: dict[str, int]
    config_json: str


class TrustedHookLaunch(Protocol):
    def run_start(self, command: Sequence[str], *, timeout_seconds: float) -> bool: ...

    def run_fallback(
        self,
        command: Sequence[str],
        *,
        data: str,
        timeout_seconds: float,
    ) -> str | None: ...


def bounded_hook_input(limit: int) -> str | None:
    data = sys.stdin.read(limit + 1)
    try:
        encoded_size = len(data.encode("utf-8"))
    except UnicodeError:
        return None
    if encoded_size > limit:
        return None
    return data if data.strip() else "{}"


def trusted_hook_launch(
    *,
    manifest_path: str | Path,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str,
) -> TrustedHookLaunch:
    from .codex_hook_runtime_trust import validate_codex_hook_launch

    return validate_codex_hook_launch(
        manifest_path=manifest_path,
        state_path=state_path,
        fallback_command=fallback_command,
        start_command=start_command,
        config_json=config_json,
    )


def bridge_config_from_argv(argv: Sequence[str], *, timeout_grace_seconds: int) -> BridgeConfig:
    if len(argv) != 2:
        raise SystemExit("codex_daemon_hook_bridge expects one JSON config argument")
    try:
        payload = json.loads(argv[1])
    except json.JSONDecodeError as exc:
        raise SystemExit("codex_daemon_hook_bridge config must be a JSON object") from exc
    if not isinstance(payload, dict):
        raise SystemExit("codex_daemon_hook_bridge config must be a JSON object")
    state_path = payload.get("state_path")
    manifest_path = payload.get("manifest_path")
    query = payload.get("query")
    if not isinstance(state_path, str):
        raise SystemExit("codex_daemon_hook_bridge config missing state_path")
    if not isinstance(manifest_path, str) or not manifest_path:
        raise SystemExit("codex_daemon_hook_bridge config missing manifest_path")
    if not isinstance(query, str):
        raise SystemExit("codex_daemon_hook_bridge config missing query")
    return BridgeConfig(
        state_path=state_path,
        manifest_path=manifest_path,
        fallback_command=_string_sequence(payload.get("fallback_command"), label="fallback_command"),
        start_command=_string_sequence(payload.get("start_command"), label="start_command"),
        query=query,
        hook_timeouts=_hook_timeout_mapping(
            payload.get("hook_timeouts"),
            timeout_grace_seconds=timeout_grace_seconds,
        ),
        config_json=argv[1],
    )


def _string_sequence(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise SystemExit(f"codex_daemon_hook_bridge config missing {label}")
    return tuple(value)


def _hook_timeout_mapping(value: object, *, timeout_grace_seconds: int) -> dict[str, int]:
    if not isinstance(value, dict):
        raise SystemExit("codex_daemon_hook_bridge config missing hook_timeouts")
    timeouts = {
        str(key): timeout
        for key, timeout in value.items()
        if isinstance(key, str) and isinstance(timeout, int) and timeout > timeout_grace_seconds
    }
    if not timeouts:
        raise SystemExit("codex_daemon_hook_bridge config has no valid hook_timeouts")
    return timeouts


__all__ = [
    "BridgeConfig",
    "TrustedHookLaunch",
    "bounded_hook_input",
    "bridge_config_from_argv",
    "trusted_hook_launch",
]
