"""Runtime enforcement for authenticated managed Codex hook launchers."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .codex_hook_bridge_runtime import decode_bridge_config_argument
from .codex_hook_compatibility import bridge_argv_sha256
from .codex_hook_file_integrity import (
    active_hook_validation_deadline,
    canonical_path,
    check_hook_validation_deadline,
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
        "bridge_resume",
        "bridge_runtime",
        "daemon_entrypoint",
        "daemon_manager",
        "fallback_entrypoint",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    }
)
_OBSERVATION_PACKAGE_ROLES = _REQUIRED_PACKAGE_ROLES | {"hook_probe", "native_receipt"}


@dataclass(frozen=True, slots=True)
class TrustedCodexHookLaunch:
    """A live authenticated launch context safe for child execution."""

    cwd: Path
    environment: Mapping[str, str]
    deadline_monotonic: float | None = None

    def _launch_deadline(self, timeout_seconds: float) -> float | None:
        if self.deadline_monotonic is None:
            return None
        return min(self.deadline_monotonic, time.monotonic() + max(0.0, timeout_seconds))

    def run_start(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        failure_kind: str = "transport-failure",
    ) -> bool:
        if failure_kind not in {
            "authenticated-control-plane-failure",
            "overload",
            "transport-failure",
        }:
            failure_kind = "transport-failure"
        environment = dict(self.environment)
        environment["HOL_GUARD_HOOK_FAILURE_KIND"] = failure_kind
        result = run_isolated_hook_process(
            command,
            input_text="",
            cwd=self.cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            deadline_monotonic=self._launch_deadline(timeout_seconds),
            allow_windows_breakaway=True,
        )
        return (
            result.returncode == 0
            and not result.output_limit_exceeded
            and not result.timed_out
            and not result.containment_failed
        )

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
            deadline_monotonic=self._launch_deadline(timeout_seconds),
        )
        if result.returncode != 0 or result.output_limit_exceeded or result.timed_out or result.containment_failed:
            return None
        return result.stdout


def _resolve_managed_hook_paths(state_path: str | Path, manifest_path: str | Path) -> tuple[Path, Path, Path]:
    """Validate managed Codex hook paths; return (state, manifest, guard home)."""

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
    return state, configured_manifest, guard_home


def validate_codex_hook_launch(
    *,
    manifest_path: str | Path,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str,
) -> TrustedCodexHookLaunch:
    """Authenticate the complete current bridge config and child identities."""

    _state, configured_manifest, guard_home = _resolve_managed_hook_paths(state_path, manifest_path)
    manifest = load_authenticated_hook_manifest_path(guard_home, configured_manifest)
    _verify_manifest_context(manifest, guard_home=guard_home, manifest_path=configured_manifest)
    manifest = _selected_launch_generation(manifest, config_json=config_json)
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
        deadline_monotonic=active_hook_validation_deadline(),
    )


def _selected_launch_generation(manifest: dict[str, object], *, config_json: str) -> dict[str, object]:
    """Select only exact current or explicitly retained authenticated argv."""
    retained = manifest.get("retained_bridge_generations", [])
    allowed = manifest.get("compatible_bridge_argv_sha256", [])
    if not isinstance(retained, list) or len(retained) > 8 or not isinstance(allowed, list) or len(allowed) > 8:
        raise ValueError("managed Codex hook retained generation identity is invalid")
    if any(
        not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
        for value in allowed
    ):
        raise ValueError("managed Codex hook bridge compatibility identity is invalid")
    bridge_path = str(Path(__file__).with_name("adapters").joinpath("codex_daemon_hook_bridge.py").resolve())
    for candidate in [manifest, *reversed(retained)]:
        if not isinstance(candidate, dict):
            raise ValueError("managed Codex hook retained generation identity is invalid")
        interpreter = _mapping(candidate.get("interpreter"), label="interpreter")
        expected = [interpreter.get("invocation_path"), "-I", bridge_path, config_json]
        events = candidate.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError("managed Codex hook event identity is invalid")
        exact = all(_mapping(event, label="event").get("argv") == expected for event in events)
        if exact and (candidate is manifest or bridge_argv_sha256(expected) in allowed):
            if candidate.get("installation_id") != manifest.get("installation_id") or candidate.get(
                "context"
            ) != manifest.get("context"):
                raise ValueError("managed Codex hook retained generation context is invalid")
            return candidate
    # Legacy manifests have a compatibility hash but no complete old layout.
    # Their existing current-layout validation still applies; no old path is inferred.
    return manifest


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
    if set(packaged_by_role) not in (_REQUIRED_PACKAGE_ROLES, _OBSERVATION_PACKAGE_ROLES):
        raise ValueError("managed Codex hook package identity is incomplete")
    return packaged_by_role


def _verify_transport(
    packaged_by_role: Mapping[str, dict[str, object]],
    manifest: Mapping[str, object],
    *,
    recorded_runtime_path: Path | None = None,
) -> None:
    runtime_path = Path(__file__) if recorded_runtime_path is None else recorded_runtime_path
    for role, filename in (
        ("hook_probe", "runtime_transition_hook_probe.py"),
        ("native_receipt", "native_decision_receipt.py"),
    ):
        if role in packaged_by_role and packaged_by_role[role].get("path") != str(
            runtime_path.with_name(filename).resolve()
        ):
            raise ValueError("managed Codex observation package path is invalid")
    bridge_path = runtime_path.with_name("adapters").joinpath("codex_daemon_hook_bridge.py").resolve()
    bridge_resume_path = runtime_path.with_name("adapters").joinpath("codex_daemon_hook_resume.py").resolve()
    bridge_runtime_path = runtime_path.with_name("codex_hook_bridge_runtime.py").resolve()
    launch_runtime_path = runtime_path.with_name("codex_hook_launch_runtime.py").resolve()
    runtime_trust_path = runtime_path.resolve()
    windows_job_path = runtime_path.with_name("codex_hook_windows_job.py").resolve()
    if packaged_by_role["bridge"].get("path") != str(bridge_path):
        raise ValueError("managed Codex hook bridge path is invalid")
    if packaged_by_role["bridge_resume"].get("path") != str(bridge_resume_path):
        raise ValueError("managed Codex hook resume path is invalid")
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
        or transport.get("bridge_resume") != packaged_by_role["bridge_resume"]
        or transport.get("bridge_runtime") != packaged_by_role["bridge_runtime"]
        or transport.get("launch_runtime") != packaged_by_role["launch_runtime"]
        or transport.get("runtime_trust") != packaged_by_role["runtime_trust"]
        or transport.get("windows_job") != packaged_by_role["windows_job"]
        or transport.get("wrapper") is not None
    ):
        raise ValueError("managed Codex hook transport identity is invalid")


def verify_captured_launch_generation(
    manifest: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Validate an authenticated captured layout without selecting or spawning it.

    The caller must authenticate the enclosing manifest and retained argv
    membership first. Normal launch verification still binds this module's
    own physical path; this read-only check binds the recorded package root.
    """
    check_hook_validation_deadline()
    interpreter = _mapping(manifest.get("interpreter"), label="interpreter")
    verify_executable_file_identity(interpreter)
    packaged = _verified_packaged_files(manifest)
    events = manifest.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("managed Codex hook captured events are invalid")
    argv = _string_list(_mapping(events[0], label="event").get("argv"), label="bridge argv")
    if len(argv) not in (3, 4):
        raise ValueError("managed Codex hook captured argv is invalid")
    config_json = argv[-1]
    try:
        config = json.loads(decode_bridge_config_argument(config_json))
    except (ValueError, RecursionError) as exc:
        raise ValueError("managed Codex hook captured config is invalid") from exc
    config = _mapping(config, label="bridge config")
    context = _mapping(manifest.get("context"), label="context")
    registration = _mapping(manifest.get("config"), label="config target")
    home, runtime_home, target = (
        context.get("guard_home"),
        context.get("runtime_guard_home"),
        registration.get("target"),
    )
    if not all(isinstance(value, str) for value in (home, runtime_home, target)):
        raise ValueError("managed Codex hook captured context is invalid")
    assert isinstance(home, str) and isinstance(runtime_home, str) and isinstance(target, str)
    state = Path(runtime_home) / "daemon-state.json"
    configured_manifest = hook_manifest_path(Path(home), Path(target))
    if config.get("state_path") != str(state) or config.get("manifest_path") != str(configured_manifest):
        raise ValueError("managed Codex hook captured context changed")
    fallback = _string_list(config.get("fallback_command"), label="fallback command")
    start = _string_list(config.get("start_command"), label="start command")
    if len(argv) == 4 and argv[1] == "-I":
        trust_path = packaged["runtime_trust"].get("path")
        if not isinstance(trust_path, str):
            raise ValueError("managed Codex hook captured trust path is invalid")
        _verify_transport(packaged, manifest, recorded_runtime_path=Path(trust_path))
        _verify_launch_contracts(
            manifest,
            interpreter=interpreter,
            packaged_by_role=packaged,
            runtime_guard_home=Path(runtime_home),
            fallback_command=fallback,
            start_command=start,
        )
        _verify_registered_bridge_argv(
            manifest,
            interpreter=interpreter,
            bridge=packaged["bridge"],
            config_json=config_json,
        )
    else:
        from .frozen_codex_runtime import (
            _verify_frozen_bridge_contract,
            _verify_frozen_launch_contracts,
            _verify_frozen_transport,
        )

        target_identity = _mapping(interpreter.get("target"), label="interpreter target")
        if any(identity.get("path") != target_identity.get("path") for identity in packaged.values()):
            raise ValueError("managed frozen Codex captured package is incomplete")
        _verify_frozen_transport(manifest, packaged)
        _verify_frozen_launch_contracts(
            manifest,
            interpreter=interpreter,
            guard_home=Path(runtime_home),
            fallback_command=fallback,
            start_command=start,
        )
        _verify_frozen_bridge_contract(
            manifest,
            interpreter=interpreter,
            state=state,
            configured_manifest=configured_manifest,
            fallback_command=fallback,
            start_command=start,
            config_json=config_json,
        )
    check_hook_validation_deadline()
    return interpreter, packaged


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
        config_payload = json.loads(decode_bridge_config_argument(config_json))
    except ValueError as exc:
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
    if all(_mapping(event, label="event").get("argv") == expected_argv for event in events):
        return
    compatible_hashes = manifest.get("compatible_bridge_argv_sha256")
    if not isinstance(compatible_hashes, list) or bridge_argv_sha256(expected_argv) not in compatible_hashes:
        raise ValueError("managed Codex hook bridge config changed after authentication")
    for value in compatible_hashes:
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError("managed Codex hook bridge compatibility identity is invalid")
    for event in events:
        binding = _mapping(event, label="event")
        if not isinstance(binding.get("argv"), list):
            raise ValueError("managed Codex hook event identity is invalid")


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"managed Codex hook {label} identity is invalid")
    return {str(key): item for key, item in value.items() if isinstance(key, str)}


def _string_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValueError(f"managed Codex hook {label} is invalid")
    return [item for item in value if isinstance(item, str)]


__all__ = ["TrustedCodexHookLaunch", "validate_codex_hook_launch"]
