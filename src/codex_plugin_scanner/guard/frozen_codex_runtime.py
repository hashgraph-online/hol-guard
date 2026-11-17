"""Frozen-runtime compatibility for authenticated Guard-managed Codex hooks.

The Desktop Core sidecar is a PyInstaller executable. In that shape,
``sys.executable`` is the Guard executable itself rather than a Python
interpreter, and a one-file build's Python module ``__file__`` paths live in
PyInstaller's short-lived extraction directory. The normal Codex hook contract intentionally
binds source-package files and invokes the Python interpreter with ``-I``.

This module keeps that source-install contract unchanged and installs a strict
frozen-only equivalent that binds every managed hook role to the signed Guard
executable and routes private bridge/daemon operations back through that same
executable. The authenticated manifest therefore still fails closed if the
runtime bytes, command contract, Guard home, or hook configuration changes.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .native_daemon_manage import GuardDaemonHookFailureKind
    from .native_daemon_peer import DaemonArtifactBinding

from .frozen_runtime_commands import (
    FROZEN_CODEX_BRIDGE_ARG,
    FROZEN_DAEMON_RECOVER_ARG,
    FROZEN_DAEMON_SERVE_ARG,
    consume_frozen_daemon_serve_gate,
    decode_frozen_daemon_serve_payload,
    is_frozen_guard_runtime,
)

_FROZEN_BRIDGE_ARG = FROZEN_CODEX_BRIDGE_ARG
_FROZEN_DAEMON_RECOVER_ARG = FROZEN_DAEMON_RECOVER_ARG
_FROZEN_DAEMON_SERVE_ARG = FROZEN_DAEMON_SERVE_ARG
_STALE_BRIDGE_HOOK = "HOL Guard's Codex hook is out of date. Run `hol-guard repair` to restore protection."


def _decode_private_payload(raw: str, *, label: str) -> dict[str, object]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} payload must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} payload must be a JSON object")
    return {str(key): value for key, value in payload.items() if isinstance(key, str)}


def install_frozen_codex_runtime(*, force: bool = False) -> bool:
    """Install the frozen Codex launch contract into the current process.

    ``force`` exists only so focused tests can exercise the compatibility layer
    without constructing a PyInstaller process. Production callers leave it
    false and therefore cannot alter source/wheel installations.
    """

    if not force and not is_frozen_guard_runtime():
        return False

    from . import codex_harness_client as codex
    from . import codex_hook_runtime_trust as runtime_trust
    from . import native_caller

    if bool(getattr(codex, "_HOL_GUARD_FROZEN_CODEX_RUNTIME", False)):
        return True

    # The native runtime derives the frozen interpreter, fallback, daemon
    # recovery, bridge commands and every authenticated role's file from the
    # caller stamp that `install_frozen_contract` below marks frozen: each is
    # the resolved executable's immutable bytes. A mutable Desktop launcher can
    # select a different generation between publication and execution and
    # cannot satisfy that contract. Retention of this generation belongs to
    # the artifact lifecycle.
    runtime_trust.validate_codex_hook_launch = _validate_frozen_codex_hook_launch
    codex.__dict__["_HOL_GUARD_FROZEN_CODEX_RUNTIME"] = True
    native_caller.install_frozen_contract()
    return True


def run_frozen_internal_command(
    argv: Sequence[str] | None = None,
    *,
    gate_already_released: bool = False,
) -> int | None:
    """Run one private frozen-runtime operation before the public CLI parser."""

    process_argv = tuple(sys.argv if argv is None else argv)
    if len(process_argv) != 3:
        return None

    operation, raw_payload = process_argv[1], process_argv[2]
    if operation == _FROZEN_BRIDGE_ARG:
        # A hook written by an older frozen build names the removed Python
        # launcher. Codex blocks the call on exit code 2 and shows the hint;
        # repair rewrites the hook to the native runtime.
        sys.stderr.write(_STALE_BRIDGE_HOOK + "\n")
        return 2

    if operation == _FROZEN_DAEMON_RECOVER_ARG:
        return _schedule_frozen_daemon_recovery(raw_payload)
    if operation == _FROZEN_DAEMON_SERVE_ARG:
        if not gate_already_released:
            consume_frozen_daemon_serve_gate(process_argv)
        return _run_frozen_daemon_serve(raw_payload)
    return None


def _run_frozen_daemon_serve(raw_payload: str) -> int:
    guard_home, home_dir, port = decode_frozen_daemon_serve_payload(raw_payload)

    from codex_plugin_scanner.cli import main

    return main(
        [
            "daemon",
            "--serve",
            "--guard-home",
            str(guard_home),
            "--home",
            str(home_dir),
            "--port",
            str(port),
        ]
    )


def _schedule_frozen_daemon_recovery(raw_payload: str) -> int:
    payload = _decode_private_payload(raw_payload, label="Codex daemon recovery")
    if set(payload) != {"guard_home", "home_dir"}:
        raise ValueError("Codex daemon recovery payload has unexpected fields")
    guard_home, home_dir = _frozen_recovery_paths(payload)

    from .native_daemon_manage import schedule_guard_daemon_recovery

    schedule_guard_daemon_recovery(
        guard_home,
        home_dir=home_dir,
        failure_kind=_hook_failure_kind(),
        executable=Path(sys.executable).expanduser().resolve(strict=True),
    )
    return 0


def _frozen_recovery_paths(payload: Mapping[str, object]) -> tuple[Path, Path]:
    guard_home_value = payload.get("guard_home")
    home_dir_value = payload.get("home_dir")
    if not isinstance(guard_home_value, str) or not isinstance(home_dir_value, str):
        raise ValueError("Codex daemon recovery paths must be strings")
    guard_home = Path(guard_home_value)
    home_dir = Path(home_dir_value)
    if not guard_home.is_absolute() or not home_dir.is_absolute():
        raise ValueError("Codex daemon recovery paths must be absolute")
    return guard_home, home_dir


def _hook_failure_kind() -> GuardDaemonHookFailureKind:
    failure_kind = os.environ.get("HOL_GUARD_HOOK_FAILURE_KIND", "transport-failure")
    if failure_kind == "authenticated-control-plane-failure":
        return "authenticated-control-plane-failure"
    if failure_kind == "overload":
        return "overload"
    if failure_kind == "transport-failure":
        return "transport-failure"
    return "transport-failure"


def _validate_frozen_codex_hook_launch(
    *,
    manifest_path: str | Path,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str,
    expected_artifact: DaemonArtifactBinding | None = None,
):
    """Authenticate the frozen bridge and its child launch contracts.

    The ordinary bridge binds to this process. A transition observer may use
    its separately verified artifact filter to inspect the retained executable.
    This filter grants no lifecycle or hook authority: the private signed
    manifest, exact executable bytes, package version and launch contracts
    still have to agree. It never changes the process identity or environment.
    """

    from .codex_hook_runtime_trust import authenticate_codex_hook_launch

    artifact = None
    if expected_artifact is not None:
        artifact = {
            "executable": str(expected_artifact.executable),
            "sha256": expected_artifact.executable_sha256,
            "package_version": expected_artifact.package_version,
        }
    executable = (
        str(expected_artifact.executable)
        if expected_artifact is not None
        else str(Path(sys.executable).expanduser().resolve(strict=True))
    )
    return authenticate_codex_hook_launch(
        manifest_path=manifest_path,
        state_path=state_path,
        fallback_command=fallback_command,
        start_command=start_command,
        config_json=config_json,
        frozen={"executable": executable, "artifact": artifact},
    )
