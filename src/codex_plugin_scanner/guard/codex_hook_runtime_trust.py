"""Runtime enforcement for authenticated managed Codex hook launchers."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .codex_hook_file_integrity import (
    canonical_path,
    verify_executable_file_identity,
    verify_regular_file_identity,
)
from .codex_hook_integrity import (
    HOOK_MANIFEST_SCHEMA_VERSION,
    hook_manifest_path,
    load_authenticated_hook_manifest_path,
)
from .codex_hook_launch_runtime import (
    isolated_daemon_start_command,
    isolated_guard_cli_command,
    isolated_hook_environment,
    private_hook_runtime_cwd,
    run_isolated_hook_process,
)

_REQUIRED_PACKAGE_ROLES = frozenset(
    {
        "bridge",
        "bridge_runtime",
        "daemon_entrypoint",
        "daemon_manager",
        "fallback_entrypoint",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    }
)


@dataclass(frozen=True, slots=True)
class TrustedCodexHookLaunch:
    """A live authenticated launch context safe for child execution."""

    cwd: Path
    environment: Mapping[str, str]

    def run_start(self, command: Sequence[str], *, timeout_seconds: float) -> bool:
        result = run_isolated_hook_process(
            command,
            input_text="",
            cwd=self.cwd,
            environment=self.environment,
            timeout_seconds=timeout_seconds,
        )
        return result.returncode == 0 and not result.output_limit_exceeded and not result.timed_out

    def run_fallback(
        self,
        command: Sequence[str],
        *,
        data: str,
        timeout_seconds: float,
    ) -> str | None:
        result = run_isolated_hook_process(
            command,
            input_text=data,
            cwd=self.cwd,
            environment=self.environment,
            timeout_seconds=timeout_seconds,
        )
        if result.returncode != 0 or result.output_limit_exceeded or result.timed_out:
            return None
        return result.stdout


def validate_codex_hook_launch(
    *,
    manifest_path: str | Path,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str,
) -> TrustedCodexHookLaunch:
    """Authenticate the complete current bridge config and child identities."""

    state = Path(state_path)
    configured_manifest = Path(manifest_path)
    if not state.is_absolute() or not configured_manifest.is_absolute():
        raise ValueError("managed Codex hook paths must be absolute")
    guard_home = state.parent.resolve(strict=False)
    expected_managed_directory = (guard_home / "managed" / "codex").resolve(strict=False)
    manifest_directory = configured_manifest.parent.resolve(strict=False)
    if state.name != "daemon-state.json" or manifest_directory != expected_managed_directory:
        raise ValueError("managed Codex hook paths do not belong to this Guard home")
    if not configured_manifest.name.startswith("hooks-") or not configured_manifest.name.endswith(".manifest.json"):
        raise ValueError("managed Codex hook manifest path is invalid")

    manifest = load_authenticated_hook_manifest_path(guard_home, configured_manifest)
    _verify_manifest_context(manifest, guard_home=guard_home, manifest_path=configured_manifest)
    interpreter = _mapping(manifest.get("interpreter"), label="interpreter")
    verify_executable_file_identity(interpreter)
    packaged_by_role = _verified_packaged_files(manifest)
    _verify_transport(packaged_by_role, manifest)
    _verify_launch_contracts(
        manifest,
        interpreter=interpreter,
        packaged_by_role=packaged_by_role,
        runtime_guard_home=guard_home,
        fallback_command=fallback_command,
        start_command=start_command,
    )
    _verify_registered_bridge_argv(
        manifest,
        interpreter=interpreter,
        bridge=packaged_by_role["bridge"],
        config_json=config_json,
    )
    return TrustedCodexHookLaunch(
        cwd=private_hook_runtime_cwd(configured_manifest),
        environment=isolated_hook_environment(),
    )


def _verify_manifest_context(manifest: Mapping[str, object], *, guard_home: Path, manifest_path: Path) -> None:
    if manifest.get("schema_version") != HOOK_MANIFEST_SCHEMA_VERSION or manifest.get("harness") != "codex":
        raise ValueError("managed Codex hook manifest schema is unsupported")
    context = _mapping(manifest.get("context"), label="context")
    if context.get("runtime_guard_home") != canonical_path(guard_home):
        raise ValueError("managed Codex hook manifest belongs to another Guard home")
    config = _mapping(manifest.get("config"), label="config")
    config_target = config.get("target")
    if not isinstance(config_target, str) or not Path(config_target).is_absolute():
        raise ValueError("managed Codex hook config target is invalid")
    expected_manifest = hook_manifest_path(guard_home, Path(config_target)).resolve(strict=False)
    if expected_manifest != manifest_path.resolve(strict=False):
        raise ValueError("managed Codex hook manifest target binding is invalid")


def _verified_packaged_files(manifest: Mapping[str, object]) -> dict[str, dict[str, object]]:
    packaged_files = manifest.get("packaged_files")
    if not isinstance(packaged_files, list):
        raise ValueError("managed Codex hook packaged-file identity is invalid")
    packaged_by_role: dict[str, dict[str, object]] = {}
    for value in packaged_files:
        identity = _mapping(value, label="packaged file")
        role = identity.get("role")
        if not isinstance(role, str) or role in packaged_by_role:
            raise ValueError("managed Codex hook packaged-file roles are invalid")
        verify_regular_file_identity(identity)
        packaged_by_role[role] = identity
    if set(packaged_by_role) != _REQUIRED_PACKAGE_ROLES:
        raise ValueError("managed Codex hook package identity is incomplete")
    return packaged_by_role


def _verify_transport(
    packaged_by_role: Mapping[str, dict[str, object]],
    manifest: Mapping[str, object],
) -> None:
    bridge_path = Path(__file__).with_name("adapters").joinpath("codex_daemon_hook_bridge.py").resolve()
    bridge_runtime_path = Path(__file__).with_name("codex_hook_bridge_runtime.py").resolve()
    launch_runtime_path = Path(__file__).with_name("codex_hook_launch_runtime.py").resolve()
    runtime_trust_path = Path(__file__).resolve()
    windows_job_path = Path(__file__).with_name("codex_hook_windows_job.py").resolve()
    if packaged_by_role["bridge"].get("path") != str(bridge_path):
        raise ValueError("managed Codex hook bridge path is invalid")
    if packaged_by_role["bridge_runtime"].get("path") != str(bridge_runtime_path):
        raise ValueError("managed Codex hook bridge runtime path is invalid")
    if packaged_by_role["launch_runtime"].get("path") != str(launch_runtime_path):
        raise ValueError("managed Codex hook launch runtime path is invalid")
    if packaged_by_role["runtime_trust"].get("path") != str(runtime_trust_path):
        raise ValueError("managed Codex hook runtime trust path is invalid")
    if packaged_by_role["windows_job"].get("path") != str(windows_job_path):
        raise ValueError("managed Codex hook Windows job path is invalid")
    transport = _mapping(manifest.get("transport"), label="transport")
    if (
        transport.get("bridge") != packaged_by_role["bridge"]
        or transport.get("bridge_runtime") != packaged_by_role["bridge_runtime"]
        or transport.get("launch_runtime") != packaged_by_role["launch_runtime"]
        or transport.get("runtime_trust") != packaged_by_role["runtime_trust"]
        or transport.get("windows_job") != packaged_by_role["windows_job"]
        or transport.get("wrapper") is not None
    ):
        raise ValueError("managed Codex hook transport identity is invalid")


def _verify_launch_contracts(
    manifest: Mapping[str, object],
    *,
    interpreter: Mapping[str, object],
    packaged_by_role: Mapping[str, dict[str, object]],
    runtime_guard_home: Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
) -> None:
    interpreter_path = interpreter.get("invocation_path")
    fallback_entrypoint = packaged_by_role["fallback_entrypoint"].get("path")
    if not isinstance(interpreter_path, str) or not isinstance(fallback_entrypoint, str):
        raise ValueError("managed Codex hook launch identity is invalid")
    fallback_path = Path(fallback_entrypoint)
    if fallback_path.name != "cli.py" or fallback_path.parent.name != "codex_plugin_scanner":
        raise ValueError("managed Codex hook fallback entrypoint is invalid")
    package_root = fallback_path.parent.parent
    fallback = _mapping(manifest.get("fallback"), label="fallback")
    fallback_argv = tuple(_string_list(fallback.get("argv"), label="fallback argv"))
    if (
        fallback_argv != tuple(fallback_command)
        or fallback.get("interpreter") != interpreter
        or fallback.get("package_roles") != ["fallback_entrypoint"]
        or fallback_argv[4:8] != ("guard", "hook", "--harness", "codex")
        or isolated_guard_cli_command(interpreter_path, package_root, fallback_argv[4:]) != fallback_argv
    ):
        raise ValueError("managed Codex hook fallback contract is invalid")

    daemon_start = _mapping(manifest.get("daemon_start"), label="daemon start")
    daemon_argv = tuple(_string_list(daemon_start.get("argv"), label="daemon start argv"))
    context = _mapping(manifest.get("context"), label="context")
    authenticated_guard_home = context.get("runtime_guard_home")
    authenticated_home_dir = context.get("home_dir")
    if (
        not isinstance(authenticated_guard_home, str)
        or not isinstance(authenticated_home_dir, str)
        or canonical_path(runtime_guard_home) != authenticated_guard_home
        or canonical_path(Path(authenticated_home_dir)) != authenticated_home_dir
        or daemon_argv != tuple(start_command)
        or daemon_start.get("interpreter") != interpreter
        or daemon_start.get("package_roles") != ["daemon_entrypoint", "daemon_manager"]
        or isolated_daemon_start_command(
            interpreter_path,
            package_root,
            runtime_guard_home,
            Path(authenticated_home_dir),
        )
        != daemon_argv
    ):
        raise ValueError("managed Codex hook daemon-start contract is invalid")


def _verify_registered_bridge_argv(
    manifest: Mapping[str, object],
    *,
    interpreter: Mapping[str, object],
    bridge: Mapping[str, object],
    config_json: str,
) -> None:
    try:
        config_payload = json.loads(config_json)
    except json.JSONDecodeError as exc:
        raise ValueError("managed Codex hook bridge config is malformed") from exc
    if not isinstance(config_payload, dict):
        raise ValueError("managed Codex hook bridge config is malformed")
    interpreter_path = interpreter.get("invocation_path")
    bridge_path = bridge.get("path")
    if not isinstance(interpreter_path, str) or not isinstance(bridge_path, str):
        raise ValueError("managed Codex hook bridge identity is invalid")
    expected_argv = [interpreter_path, "-I", bridge_path, config_json]
    events = manifest.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("managed Codex hook event identity is invalid")
    for event in events:
        binding = _mapping(event, label="event")
        if binding.get("argv") != expected_argv:
            raise ValueError("managed Codex hook bridge config changed after authentication")


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"managed Codex hook {label} identity is invalid")
    return {str(key): item for key, item in value.items() if isinstance(key, str)}


def _string_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValueError(f"managed Codex hook {label} is invalid")
    return [item for item in value if isinstance(item, str)]


__all__ = ["TrustedCodexHookLaunch", "validate_codex_hook_launch"]
