"""Leaf command builders shared by frozen Guard harness adapters."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO, cast

from .stable_guard_cli import resolve_frozen_guard_cli

FROZEN_CODEX_BRIDGE_ARG = "--_hol-guard-codex-bridge"
FROZEN_DAEMON_RECOVER_ARG = "--_hol-guard-codex-daemon-recover"
FROZEN_DAEMON_RECOVERY_WORKER_ARG = "--_hol-guard-codex-daemon-recovery-worker"
FROZEN_DAEMON_SERVE_ARG = "--_hol-guard-daemon-serve"


def frozen_codex_bridge_tokens_are_live(tokens: Sequence[str]) -> bool:
    """Return whether argv matches the frozen Codex private-bridge contract."""

    try:
        flag_index = tokens.index(FROZEN_CODEX_BRIDGE_ARG)
    except ValueError:
        return False
    if flag_index + 1 >= len(tokens):
        return False
    try:
        payload = json.loads(tokens[flag_index + 1])
    except (json.JSONDecodeError, TypeError, ValueError):
        return False
    return isinstance(payload, dict)


def is_frozen_guard_runtime() -> bool:
    """Return whether this process is a PyInstaller-style frozen Guard binary."""

    return bool(getattr(sys, "frozen", False)) and Path(sys.executable).is_file()


def _recovery_executable(executable: str | None) -> str:
    if executable is not None:
        return executable
    if is_frozen_guard_runtime():
        return resolve_frozen_guard_cli()
    return sys.executable


def frozen_daemon_recovery_command(
    guard_home: Path,
    home_dir: Path,
    *,
    executable: str | None = None,
) -> tuple[str, ...]:
    """Build the authenticated frozen-Core daemon recovery command."""

    payload = json.dumps(
        {
            "guard_home": str(guard_home.resolve(strict=False)),
            "home_dir": str(home_dir.resolve(strict=False)),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (_recovery_executable(executable), FROZEN_DAEMON_RECOVER_ARG, payload)


def frozen_daemon_recovery_worker_command(
    guard_home: Path,
    home_dir: Path,
    failure_kind: str,
    recovery_token: str,
    *,
    executable: str | None = None,
) -> tuple[str, ...]:
    """Build the detached frozen-Core recovery worker command."""

    payload = json.dumps(
        {
            "failure_kind": failure_kind,
            "guard_home": str(guard_home.resolve(strict=False)),
            "home_dir": str(home_dir.resolve(strict=False)),
            "recovery_token": recovery_token,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (_recovery_executable(executable), FROZEN_DAEMON_RECOVERY_WORKER_ARG, payload)


def frozen_daemon_serve_command(
    guard_home: Path,
    home_dir: Path,
    port: int,
    *,
    executable: str | None = None,
) -> tuple[str, ...]:
    """Build the signed frozen daemon command whose stdin gate is held by the parent."""

    payload = json.dumps(
        {
            "guard_home": str(guard_home.resolve(strict=False)),
            "home_dir": str(home_dir.resolve(strict=False)),
            "port": port,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return (_recovery_executable(executable), FROZEN_DAEMON_SERVE_ARG, payload)


def decode_frozen_daemon_serve_payload(raw_payload: str) -> tuple[Path, Path, int]:
    """Validate the private frozen daemon serve context without touching Guard state."""

    try:
        payload = json.loads(raw_payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError("Frozen daemon serve payload must be valid JSON") from error
    if not isinstance(payload, dict) or set(payload) != {"guard_home", "home_dir", "port"}:
        raise ValueError("Frozen daemon serve payload has unexpected fields")
    guard_home_value = payload.get("guard_home")
    home_dir_value = payload.get("home_dir")
    port = payload.get("port")
    if not isinstance(guard_home_value, str) or not isinstance(home_dir_value, str):
        raise ValueError("Frozen daemon serve paths must be strings")
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("Frozen daemon serve port is invalid")
    guard_home = Path(guard_home_value)
    home_dir = Path(home_dir_value)
    if (
        not guard_home.is_absolute()
        or not home_dir.is_absolute()
        or guard_home != guard_home.resolve(strict=False)
        or home_dir != home_dir.resolve(strict=False)
    ):
        raise ValueError("Frozen daemon serve paths must be canonical absolute paths")
    return guard_home, home_dir, port


def consume_frozen_daemon_serve_gate(
    argv: Sequence[str] | None = None,
    *,
    stdin: object | None = None,
) -> bool:
    """Consume the one-byte frozen daemon gate before importing daemon code."""

    process_argv = tuple(sys.argv if argv is None else argv)
    if len(process_argv) != 3 or process_argv[1] != FROZEN_DAEMON_SERVE_ARG:
        return False
    decode_frozen_daemon_serve_payload(process_argv[2])
    try:
        if Path(process_argv[0]).expanduser().resolve(strict=True) != Path(sys.executable).expanduser().resolve(
            strict=True
        ):
            raise ValueError("Frozen daemon serve executable is not the current executable")
    except (OSError, RuntimeError) as error:
        raise ValueError("Frozen daemon serve executable is not trusted") from error
    stream = sys.stdin if stdin is None else stdin
    gate_stream = cast(BinaryIO, getattr(stream, "buffer", stream))
    try:
        gate = gate_stream.read(1)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        gate = b""
    if gate != b"1":
        raise SystemExit(70)
    return True


__all__ = [
    "FROZEN_CODEX_BRIDGE_ARG",
    "FROZEN_DAEMON_RECOVERY_WORKER_ARG",
    "FROZEN_DAEMON_RECOVER_ARG",
    "FROZEN_DAEMON_SERVE_ARG",
    "consume_frozen_daemon_serve_gate",
    "decode_frozen_daemon_serve_payload",
    "frozen_codex_bridge_tokens_are_live",
    "frozen_daemon_recovery_command",
    "frozen_daemon_recovery_worker_command",
    "frozen_daemon_serve_command",
    "is_frozen_guard_runtime",
]
