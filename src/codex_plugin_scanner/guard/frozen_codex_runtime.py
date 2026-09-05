"""Frozen-runtime compatibility for authenticated Guard-managed Codex hooks.

The Desktop Core sidecar is a PyInstaller one-file executable. In that shape,
``sys.executable`` is the Guard executable itself rather than a Python
interpreter, and Python module ``__file__`` paths live in PyInstaller's
short-lived extraction directory. The normal Codex hook contract intentionally
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
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .daemon.manager import GuardDaemonHookFailureKind

from .frozen_runtime_commands import (
    FROZEN_DAEMON_RECOVER_ARG,
    FROZEN_DAEMON_RECOVERY_WORKER_ARG,
    frozen_daemon_recovery_command,
    is_frozen_guard_runtime,
)

_FROZEN_BRIDGE_ARG = "--_hol-guard-codex-bridge"
_FROZEN_DAEMON_RECOVER_ARG = FROZEN_DAEMON_RECOVER_ARG
_FROZEN_DAEMON_RECOVERY_WORKER_ARG = FROZEN_DAEMON_RECOVERY_WORKER_ARG


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

    from . import codex_hook_runtime_trust as runtime_trust
    from .adapters import codex

    if bool(getattr(codex, "_HOL_GUARD_FROZEN_CODEX_RUNTIME", False)):
        return True

    source_local_command = codex._local_hook_command_parts_for_home_mode
    source_hook_command = codex._hook_command_parts_for_home_mode
    source_packaged_paths = codex._hook_packaged_file_paths

    def frozen_local_command(
        context,
        *,
        home_is_current: bool,
        python_executable: str,
    ) -> tuple[str, ...]:
        source_argv = source_local_command(
            context,
            home_is_current=home_is_current,
            python_executable=python_executable,
        )
        if len(source_argv) < 6 or source_argv[1:3] != ("-I", "-c") or source_argv[4] != "guard":
            raise RuntimeError("Guard's source Codex fallback contract is not canonical")
        return (python_executable, *source_argv[5:])

    def frozen_daemon_start_command(
        guard_home: Path,
        home_dir: Path,
        *,
        python_executable: str = sys.executable,
    ) -> tuple[str, ...]:
        return frozen_daemon_recovery_command(guard_home, home_dir, executable=python_executable)

    def frozen_hook_command(
        context,
        *,
        home_is_current: bool,
        python_executable: str,
    ) -> tuple[str, ...]:
        # Reuse the established config builder after replacing only its child
        # launch contracts. This keeps query, timeout, home, manifest, and
        # workspace semantics identical to source installs.
        source_argv = source_hook_command(
            context,
            home_is_current=home_is_current,
            python_executable=python_executable,
        )
        if len(source_argv) != 4:
            raise RuntimeError("Guard's source Codex bridge contract is not canonical")
        config_json = source_argv[3]
        payload = _decode_private_payload(config_json, label="Codex bridge")
        if not payload:
            raise RuntimeError("Guard's Codex bridge config is empty")
        return (python_executable, _FROZEN_BRIDGE_ARG, config_json)

    def frozen_packaged_paths() -> tuple[tuple[str, Path], ...]:
        executable = Path(sys.executable).expanduser().resolve(strict=True)
        # Preserve the existing role set but bind every role to the immutable
        # frozen runtime bytes that actually implement those roles.
        return tuple((role, executable) for role, _path in source_packaged_paths())

    codex._local_hook_command_parts_for_home_mode = frozen_local_command
    codex._daemon_start_command = frozen_daemon_start_command
    codex._hook_command_parts_for_home_mode = frozen_hook_command
    codex._hook_packaged_file_paths = frozen_packaged_paths
    runtime_trust.validate_codex_hook_launch = _validate_frozen_codex_hook_launch
    codex.__dict__["_HOL_GUARD_FROZEN_CODEX_RUNTIME"] = True
    return True


def run_frozen_internal_command(argv: Sequence[str] | None = None) -> int | None:
    """Run one private frozen-runtime operation before the public CLI parser."""

    process_argv = tuple(sys.argv if argv is None else argv)
    if len(process_argv) != 3:
        return None

    operation, raw_payload = process_argv[1], process_argv[2]
    if operation == _FROZEN_BRIDGE_ARG:
        from .adapters.codex_daemon_hook_bridge import _bridge_config_from_argv
        from .adapters.codex_daemon_hook_bridge import main as bridge_main

        config = _bridge_config_from_argv(("codex_daemon_hook_bridge", raw_payload))
        return bridge_main(
            state_path=config["state_path"],
            manifest_path=config["manifest_path"],
            fallback_command=config["fallback_command"],
            start_command=config["start_command"],
            query=config["query"],
            hook_timeouts=config["hook_timeouts"],
            config_json=config["config_json"],
        )

    if operation == _FROZEN_DAEMON_RECOVER_ARG:
        return _schedule_frozen_daemon_recovery(raw_payload)
    if operation == _FROZEN_DAEMON_RECOVERY_WORKER_ARG:
        return _run_frozen_daemon_recovery_worker(raw_payload)
    return None


def _schedule_frozen_daemon_recovery(raw_payload: str) -> int:
    payload = _decode_private_payload(raw_payload, label="Codex daemon recovery")
    if set(payload) != {"guard_home", "home_dir"}:
        raise ValueError("Codex daemon recovery payload has unexpected fields")
    guard_home, home_dir = _frozen_recovery_paths(payload)

    from .daemon import schedule_guard_daemon_recovery

    schedule_guard_daemon_recovery(
        guard_home,
        home_dir=home_dir,
        failure_kind=_hook_failure_kind(),
        executable=Path(sys.executable).expanduser().resolve(strict=True),
    )
    return 0


def _run_frozen_daemon_recovery_worker(raw_payload: str) -> int:
    payload = _decode_private_payload(raw_payload, label="Codex daemon recovery worker")
    if set(payload) != {"failure_kind", "guard_home", "home_dir", "recovery_token"}:
        raise ValueError("Codex daemon recovery worker payload has unexpected fields")
    guard_home, home_dir = _frozen_recovery_paths(payload)
    failure_kind = payload.get("failure_kind")
    recovery_token = payload.get("recovery_token")
    typed_failure_kind: GuardDaemonHookFailureKind
    if failure_kind == "authenticated-control-plane-failure":
        typed_failure_kind = "authenticated-control-plane-failure"
    elif failure_kind == "overload":
        typed_failure_kind = "overload"
    elif failure_kind == "transport-failure":
        typed_failure_kind = "transport-failure"
    else:
        raise ValueError("Codex daemon recovery worker failure kind is invalid")
    if not isinstance(recovery_token, str) or not recovery_token:
        raise ValueError("Codex daemon recovery worker token is invalid")

    from .daemon.manager import (
        _GUARD_DAEMON_RECOVERY_WORKER_TIMEOUT_SECONDS,
        clear_guard_daemon_recovery_reservation,
        recover_guard_daemon_after_hook_failure,
    )

    try:
        recover_guard_daemon_after_hook_failure(
            guard_home,
            home_dir=home_dir,
            failure_kind=typed_failure_kind,
            recovery_lock_timeout_seconds=_GUARD_DAEMON_RECOVERY_WORKER_TIMEOUT_SECONDS,
        )
    finally:
        with suppress(OSError, RuntimeError, ValueError):
            clear_guard_daemon_recovery_reservation(guard_home, token=recovery_token)
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
):
    """Authenticate the frozen bridge and its child launch contracts."""

    from . import codex_hook_runtime_trust as trust
    from .codex_hook_file_integrity import verify_executable_file_identity
    from .codex_hook_integrity import load_authenticated_hook_manifest_path
    from .codex_hook_launch_runtime import isolated_hook_environment, private_hook_runtime_cwd

    state, configured_manifest, guard_home = trust._resolve_managed_hook_paths(state_path, manifest_path)
    manifest = load_authenticated_hook_manifest_path(guard_home, configured_manifest)
    trust._verify_manifest_context(manifest, guard_home=guard_home, manifest_path=configured_manifest)
    interpreter = trust._mapping(manifest.get("interpreter"), label="interpreter")
    verify_executable_file_identity(interpreter)
    packaged_by_role = trust._verified_packaged_files(manifest)

    invocation_path = interpreter.get("invocation_path")
    target = trust._mapping(interpreter.get("target"), label="interpreter target")
    target_path = target.get("path")
    current_invocation = str(Path(sys.executable).expanduser().absolute())
    if invocation_path != current_invocation or not isinstance(target_path, str):
        raise ValueError("managed frozen Codex hook executable identity is invalid")
    if any(identity.get("path") != target_path for identity in packaged_by_role.values()):
        raise ValueError("managed frozen Codex hook package identity is incomplete")

    _verify_frozen_transport(manifest, packaged_by_role)
    _verify_frozen_launch_contracts(
        manifest,
        interpreter=interpreter,
        guard_home=guard_home,
        fallback_command=fallback_command,
        start_command=start_command,
    )
    _verify_frozen_bridge_contract(
        manifest,
        interpreter=interpreter,
        state=state,
        configured_manifest=configured_manifest,
        fallback_command=fallback_command,
        start_command=start_command,
        config_json=config_json,
    )
    return trust.TrustedCodexHookLaunch(
        cwd=private_hook_runtime_cwd(configured_manifest),
        environment=isolated_hook_environment(),
    )


def _verify_frozen_transport(
    manifest: Mapping[str, object],
    packaged_by_role: Mapping[str, dict[str, object]],
) -> None:
    transport = manifest.get("transport")
    if not isinstance(transport, dict) or transport.get("wrapper") is not None:
        raise ValueError("managed frozen Codex hook transport identity is invalid")
    for role in ("bridge", "bridge_resume", "bridge_runtime", "launch_runtime", "runtime_trust", "windows_job"):
        if transport.get(role) != packaged_by_role.get(role):
            raise ValueError("managed frozen Codex hook transport identity is invalid")


def _verify_frozen_launch_contracts(
    manifest: Mapping[str, object],
    *,
    interpreter: Mapping[str, object],
    guard_home: Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
) -> None:
    from . import codex_hook_runtime_trust as trust
    from .codex_hook_file_integrity import canonical_path

    invocation_path = interpreter.get("invocation_path")
    if not isinstance(invocation_path, str):
        raise ValueError("managed frozen Codex hook interpreter path is invalid")

    fallback = trust._mapping(manifest.get("fallback"), label="fallback")
    fallback_argv = tuple(trust._string_list(fallback.get("argv"), label="fallback argv"))
    if (
        fallback_argv != tuple(fallback_command)
        or fallback.get("interpreter") != interpreter
        or fallback.get("package_roles") != ["fallback_entrypoint"]
        or fallback_argv[:4] != (invocation_path, "hook", "--harness", "codex")
    ):
        raise ValueError("managed frozen Codex hook fallback contract is invalid")

    daemon_start = trust._mapping(manifest.get("daemon_start"), label="daemon start")
    daemon_argv = tuple(trust._string_list(daemon_start.get("argv"), label="daemon start argv"))
    context = trust._mapping(manifest.get("context"), label="context")
    authenticated_guard_home = context.get("runtime_guard_home")
    authenticated_home_dir = context.get("home_dir")
    if (
        daemon_argv != tuple(start_command)
        or daemon_start.get("interpreter") != interpreter
        or daemon_start.get("package_roles") != ["daemon_entrypoint", "daemon_manager"]
        or len(daemon_argv) != 3
        or daemon_argv[:2] != (invocation_path, _FROZEN_DAEMON_RECOVER_ARG)
        or not isinstance(authenticated_guard_home, str)
        or not isinstance(authenticated_home_dir, str)
        or canonical_path(guard_home) != authenticated_guard_home
    ):
        raise ValueError("managed frozen Codex hook daemon-start contract is invalid")
    daemon_payload = _decode_private_payload(daemon_argv[2], label="Codex daemon recovery")
    if daemon_payload != {
        "guard_home": authenticated_guard_home,
        "home_dir": authenticated_home_dir,
    }:
        raise ValueError("managed frozen Codex hook daemon-start context is invalid")


def _verify_frozen_bridge_contract(
    manifest: Mapping[str, object],
    *,
    interpreter: Mapping[str, object],
    state: Path,
    configured_manifest: Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str,
) -> None:
    invocation_path = interpreter.get("invocation_path")
    if not isinstance(invocation_path, str):
        raise ValueError("managed frozen Codex hook interpreter path is invalid")
    config = _decode_private_payload(config_json, label="Codex bridge")
    if (
        config.get("state_path") != str(state)
        or config.get("manifest_path") != str(configured_manifest)
        or config.get("fallback_command") != list(fallback_command)
        or config.get("start_command") != list(start_command)
    ):
        raise ValueError("managed frozen Codex hook bridge config is invalid")
    expected_argv = [invocation_path, _FROZEN_BRIDGE_ARG, config_json]
    events = manifest.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("managed frozen Codex hook event identity is invalid")
    for event in events:
        if not isinstance(event, dict) or event.get("argv") != expected_argv:
            raise ValueError("managed frozen Codex hook bridge config changed after authentication")


__all__ = [
    "frozen_daemon_recovery_command",
    "install_frozen_codex_runtime",
    "is_frozen_guard_runtime",
    "run_frozen_internal_command",
]
