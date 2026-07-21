"""Build and verify authenticated identities for Guard-managed Codex hooks.

This module owns the manifest trust model without importing the Codex adapter.
The adapter supplies one complete expected specification, which keeps command
construction at the harness boundary and prevents a circular dependency.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

from .codex_hook_file_integrity import (
    CodexHookIntegrityError,
    canonical_path,
    describe_executable_file,
    describe_regular_file,
    split_hook_command,
    validate_regular_file,
    verify_executable_file_identity,
    verify_regular_file_identity,
)
from .codex_hook_integrity import (
    HOOK_MANIFEST_SCHEMA_VERSION,
    hook_manifest_path,
    hook_secret_path,
    load_authenticated_hook_manifest,
    load_or_create_hook_secret,
    sign_hook_manifest,
)
from .codex_hook_package_identity import assert_package_reauthentication_is_safe

MANAGED_CODEX_HOOK_EVENTS = ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")


@dataclass(frozen=True, slots=True)
class CodexHookManifestSpec:
    """Complete live identity expected for one Codex hook installation."""

    guard_home: Path
    home_dir: Path
    runtime_guard_home: Path
    workspace_dir: Path | None
    config_path: Path
    interpreter_path: Path
    package_version: str
    packaged_file_paths: tuple[tuple[str, Path], ...]
    fallback_argv: tuple[str, ...]
    daemon_start_argv: tuple[str, ...]
    event_bindings: tuple[Mapping[str, object], ...]
    workspace_rebinding_allowed: bool = False


def build_authenticated_hook_manifest(spec: CodexHookManifestSpec) -> dict[str, object]:
    secret = load_or_create_hook_secret(spec.guard_home)
    interpreter = describe_executable_file(spec.interpreter_path, role="interpreter")
    packaged_files = [
        describe_regular_file(path, role=role, executable_required=False) for role, path in spec.packaged_file_paths
    ]
    packaged_by_role = {
        identity.get("role"): identity for identity in packaged_files if isinstance(identity.get("role"), str)
    }
    bridge = packaged_by_role.get("bridge")
    bridge_runtime = packaged_by_role.get("bridge_runtime")
    launch_runtime = packaged_by_role.get("launch_runtime")
    runtime_trust = packaged_by_role.get("runtime_trust")
    windows_job = packaged_by_role.get("windows_job")
    if (
        not isinstance(bridge, dict)
        or not isinstance(bridge_runtime, dict)
        or not isinstance(launch_runtime, dict)
        or not isinstance(runtime_trust, dict)
        or not isinstance(windows_job, dict)
        or len(packaged_by_role) != len(spec.packaged_file_paths)
    ):
        raise CodexHookIntegrityError(
            "codex_hook_manifest_packaged_files_invalid",
            "Guard cannot authenticate an incomplete Codex hook package identity.",
        )
    generated_at = datetime.now(timezone.utc).isoformat()
    unsigned_manifest: dict[str, object] = {
        "config": {"scope": "global", "target": canonical_path(spec.config_path)},
        "context": _expected_context(spec),
        "daemon_start": {
            "argv": list(spec.daemon_start_argv),
            "interpreter": interpreter,
            "package_roles": ["daemon_entrypoint", "daemon_manager"],
        },
        "events": [dict(binding) for binding in spec.event_bindings],
        "fallback": {
            "argv": list(spec.fallback_argv),
            "interpreter": interpreter,
            "package_roles": ["fallback_entrypoint"],
        },
        "generated_at": generated_at,
        "harness": "codex",
        "installation_id": secret.installation_id,
        "interpreter": interpreter,
        "package_version": spec.package_version,
        "packaged_files": packaged_files,
        "schema_version": HOOK_MANIFEST_SCHEMA_VERSION,
        "transport": {
            "bridge": bridge,
            "bridge_runtime": bridge_runtime,
            "launch_runtime": launch_runtime,
            "runtime_trust": runtime_trust,
            "windows_job": windows_job,
            "wrapper": None,
        },
    }
    return sign_hook_manifest(unsigned_manifest, secret)


def load_hook_manifest_baseline(spec: CodexHookManifestSpec) -> dict[str, object] | None:
    """Load a prior authenticated baseline or prove this is a clean install.

    No manifest and no secret is the only unauthenticated state that may create
    a baseline. It covers both a first install and explicit migration of a
    pre-manifest exact legacy hook. If either modern artifact exists, every
    authenticity and ownership check must pass before current package bytes can
    be signed again.
    """

    manifest_path = hook_manifest_path(spec.guard_home, spec.config_path)
    secret_path = hook_secret_path(spec.guard_home)
    manifest_exists = manifest_path.exists() or manifest_path.is_symlink()
    secret_exists = secret_path.exists() or secret_path.is_symlink()
    if not manifest_exists and not secret_exists:
        return None
    try:
        manifest = load_authenticated_hook_manifest(spec.guard_home, spec.config_path)
    except (CodexHookIntegrityError, OSError) as exc:
        raise _untrusted_baseline_error() from exc
    if not _manifest_has_owned_installation_context(manifest, spec):
        raise _untrusted_baseline_error()
    return manifest


def authenticated_manifest_for_ownership(spec: CodexHookManifestSpec) -> dict[str, object] | None:
    """Return exact authenticated ownership evidence for conservative cleanup."""

    try:
        manifest = load_authenticated_hook_manifest(spec.guard_home, spec.config_path)
    except (CodexHookIntegrityError, OSError):
        return None
    return manifest if _manifest_has_owned_installation_context(manifest, spec) else None


def manifest_bindings(manifest: object) -> list[dict[str, object]]:
    if not isinstance(manifest, dict):
        return []
    events = manifest.get("events")
    if not isinstance(events, list):
        return []
    return [dict(binding) for binding in events if isinstance(binding, dict)]


def verify_live_hook_manifest(
    spec: CodexHookManifestSpec,
    *,
    hooks: object,
) -> dict[str, object]:
    event_matches = {event_name: False for event_name in MANAGED_CODEX_HOOK_EVENTS}
    manifest_path = hook_manifest_path(spec.guard_home, spec.config_path)
    try:
        manifest = load_authenticated_hook_manifest(spec.guard_home, spec.config_path)
        _verify_manifest_header(manifest, spec)
        validate_regular_file(spec.config_path, role="config_target", executable_required=False)
        interpreter = manifest.get("interpreter")
        verify_executable_file_identity(interpreter)
        if not isinstance(interpreter, dict) or interpreter.get("invocation_path") != str(spec.interpreter_path):
            _raise_manifest_failure(
                "codex_hook_interpreter_path_mismatch",
                "The Codex hook interpreter does not match this Guard installation; repair it.",
            )
        packaged_by_role = _verify_packaged_files(manifest, spec)
        _verify_launch_identities(manifest, spec, interpreter, packaged_by_role)
        bindings = manifest_bindings(manifest)
        expected_bindings = [dict(binding) for binding in spec.event_bindings]
        if bindings != expected_bindings:
            _raise_manifest_failure(
                "codex_hook_manifest_registration_stale",
                "The authenticated Codex hook registration no longer matches this Guard version; run repair.",
            )
        if not isinstance(hooks, dict):
            _raise_manifest_failure(
                "codex_hook_registration_missing",
                "The authenticated Codex hooks are missing from Codex configuration; run repair.",
            )
        matched_group_indexes = _verify_event_bindings(bindings, spec, hooks, event_matches)
        if not all(event_matches.values()):
            _raise_manifest_failure(
                "codex_hook_registration_mismatch",
                "One or more authenticated Codex hook handlers changed or disappeared; run repair.",
            )
        foreign_count = sum(
            max(0, len(groups) - (1 if event_name in matched_group_indexes else 0))
            for event_name in MANAGED_CODEX_HOOK_EVENTS
            if isinstance((groups := hooks.get(event_name)), list)
        )
        return {
            "event_matches": event_matches,
            "foreign_hook_entries_present": foreign_count > 0,
            "foreign_hook_group_count": foreign_count,
            "integrity_message": "Authenticated manifest and live Codex hook identities are valid.",
            "integrity_reason": "codex_hook_manifest_valid",
            "integrity_status": "valid",
            "manifest_path": str(manifest_path),
            "manifest_schema_version": HOOK_MANIFEST_SCHEMA_VERSION,
            "manifest_package_version": manifest.get("package_version"),
        }
    except (CodexHookIntegrityError, OSError) as exc:
        if isinstance(exc, CodexHookIntegrityError):
            reason, message = exc.reason, exc.message
        else:
            reason = "codex_hook_integrity_io_error"
            message = "Guard could not verify the Codex hook installation; run repair and inspect file permissions."
        return {
            "event_matches": event_matches,
            "foreign_hook_entries_present": _hooks_have_registered_entries(hooks),
            "foreign_hook_group_count": sum(
                len(groups)
                for event_name in MANAGED_CODEX_HOOK_EVENTS
                if isinstance(hooks, dict) and isinstance((groups := hooks.get(event_name)), list)
            ),
            "integrity_message": message,
            "integrity_reason": reason,
            "integrity_status": _manifest_failure_status(reason),
            "manifest_path": str(manifest_path),
            "manifest_schema_version": None,
            "manifest_package_version": None,
        }


def _expected_context(spec: CodexHookManifestSpec) -> dict[str, object]:
    return {
        "guard_home": canonical_path(spec.guard_home),
        "home_dir": canonical_path(spec.home_dir),
        "runtime_guard_home": canonical_path(spec.runtime_guard_home),
        "workspace_dir": canonical_path(spec.workspace_dir) if spec.workspace_dir is not None else None,
    }


def _manifest_has_owned_installation_context(
    manifest: Mapping[str, object],
    spec: CodexHookManifestSpec,
) -> bool:
    config = manifest.get("config")
    context = manifest.get("context")
    expected_context = _expected_context(spec)
    return (
        manifest.get("harness") == "codex"
        and isinstance(config, dict)
        and config.get("scope") == "global"
        and config.get("target") == canonical_path(spec.config_path)
        and isinstance(context, dict)
        and (
            context == expected_context
            or (
                spec.workspace_rebinding_allowed
                and context.keys() == expected_context.keys()
                and context["guard_home"] == expected_context["guard_home"]
                and context["home_dir"] == expected_context["home_dir"]
                and context["runtime_guard_home"] == expected_context["runtime_guard_home"]
            )
        )
    )


def _untrusted_baseline_error() -> CodexHookIntegrityError:
    return CodexHookIntegrityError(
        "codex_hook_manifest_baseline_untrusted",
        "Guard refused to authenticate hook package bytes because the existing managed-hook baseline is "
        "missing, invalid, or belongs to another installation. Reinstall hol-guard from a trusted package, "
        "then run `hol-guard install codex` again.",
    )


def _verify_manifest_header(manifest: Mapping[str, object], spec: CodexHookManifestSpec) -> None:
    if manifest.get("schema_version") != HOOK_MANIFEST_SCHEMA_VERSION:
        _raise_manifest_failure(
            "codex_hook_manifest_schema_unsupported",
            "The Codex hook manifest schema is stale; run `hol-guard install codex` to refresh it.",
        )
    if manifest.get("harness") != "codex":
        _raise_manifest_failure(
            "codex_hook_manifest_context_mismatch",
            "The authenticated hook manifest is not bound to the Codex harness; repair the installation.",
        )
    config = manifest.get("config")
    if (
        not isinstance(config, dict)
        or config.get("scope") != "global"
        or config.get("target") != canonical_path(spec.config_path)
    ):
        _raise_manifest_failure(
            "codex_hook_manifest_config_target_mismatch",
            "The Codex hook manifest is bound to another configuration target; repair the installation.",
        )
    if manifest.get("context") != _expected_context(spec):
        _raise_manifest_failure(
            "codex_hook_manifest_context_mismatch",
            "The Codex hook manifest is bound to another Guard home or workspace; repair the installation.",
        )
    if manifest.get("package_version") != spec.package_version:
        _raise_manifest_failure(
            "codex_hook_manifest_package_version_stale",
            "The Codex hook manifest was generated by another Guard package version; run repair.",
        )
    generated_at = manifest.get("generated_at")
    try:
        generated_time = datetime.fromisoformat(generated_at) if isinstance(generated_at, str) else None
    except ValueError:
        generated_time = None
    if generated_time is None or generated_time.tzinfo is None:
        _raise_manifest_failure(
            "codex_hook_manifest_generated_at_invalid",
            "The Codex hook manifest generation time is invalid; repair the installation.",
        )


def _verify_packaged_files(
    manifest: Mapping[str, object],
    spec: CodexHookManifestSpec,
) -> dict[str, dict[str, object]]:
    packaged_files = manifest.get("packaged_files")
    if not isinstance(packaged_files, list):
        _raise_manifest_failure(
            "codex_hook_manifest_packaged_files_invalid",
            "The Codex hook manifest has no valid packaged-file identities; repair the installation.",
        )
    packaged_by_role: dict[str, dict[str, object]] = {}
    for item in packaged_files:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        if not isinstance(role, str):
            continue
        identity: dict[str, object] = {key: value for key, value in item.items() if isinstance(key, str)}
        packaged_by_role[role] = identity
    for identity in packaged_by_role.values():
        verify_regular_file_identity(identity)
    expected_paths = {role: canonical_path(path) for role, path in spec.packaged_file_paths}
    if set(packaged_by_role) != set(expected_paths) or any(
        packaged_by_role[role].get("path") != expected_path for role, expected_path in expected_paths.items()
    ):
        _raise_manifest_failure(
            "codex_hook_manifest_packaged_files_stale",
            "The Codex hook packaged-file paths changed; run repair to authenticate the new installation.",
        )
    return packaged_by_role


def _verify_launch_identities(
    manifest: Mapping[str, object],
    spec: CodexHookManifestSpec,
    interpreter: dict[str, object],
    packaged_by_role: Mapping[str, dict[str, object]],
) -> None:
    transport = manifest.get("transport")
    if (
        not isinstance(transport, dict)
        or transport.get("wrapper") is not None
        or transport.get("bridge") != packaged_by_role.get("bridge")
        or transport.get("bridge_runtime") != packaged_by_role.get("bridge_runtime")
        or transport.get("launch_runtime") != packaged_by_role.get("launch_runtime")
        or transport.get("runtime_trust") != packaged_by_role.get("runtime_trust")
        or transport.get("windows_job") != packaged_by_role.get("windows_job")
    ):
        _raise_manifest_failure(
            "codex_hook_manifest_transport_invalid",
            "The Codex hook bridge identity is invalid; repair the installation.",
        )
    fallback = manifest.get("fallback")
    if (
        not isinstance(fallback, dict)
        or fallback.get("argv") != list(spec.fallback_argv)
        or fallback.get("interpreter") != interpreter
        or fallback.get("package_roles") != ["fallback_entrypoint"]
    ):
        _raise_manifest_failure(
            "codex_hook_manifest_fallback_mismatch",
            "The Codex hook fallback identity changed; repair the installation.",
        )
    daemon_start = manifest.get("daemon_start")
    if (
        not isinstance(daemon_start, dict)
        or daemon_start.get("argv") != list(spec.daemon_start_argv)
        or daemon_start.get("interpreter") != interpreter
        or daemon_start.get("package_roles") != ["daemon_entrypoint", "daemon_manager"]
    ):
        _raise_manifest_failure(
            "codex_hook_manifest_daemon_start_mismatch",
            "The Codex daemon-start identity changed; repair the installation.",
        )


def _verify_event_bindings(
    bindings: list[dict[str, object]],
    spec: CodexHookManifestSpec,
    hooks: dict[str, object],
    event_matches: dict[str, bool],
) -> dict[str, int]:
    matched_group_indexes: dict[str, int] = {}
    expected_argv_value = spec.event_bindings[0].get("argv", ()) if spec.event_bindings else ()
    if not isinstance(expected_argv_value, (list, tuple)) or not all(
        isinstance(token, str) for token in expected_argv_value
    ):
        _raise_manifest_failure(
            "codex_hook_manifest_registration_invalid",
            "The expected Codex hook registration has an invalid argv identity; repair the installation.",
        )
    expected_argv = [token for token in expected_argv_value if isinstance(token, str)]
    for binding in bindings:
        event_name = binding.get("event")
        expected_group = binding.get("group")
        argv = binding.get("argv")
        handler = binding.get("handler")
        if (
            not isinstance(event_name, str)
            or event_name not in event_matches
            or not isinstance(expected_group, dict)
            or not isinstance(handler, dict)
            or not isinstance(argv, list)
            or not all(isinstance(token, str) for token in argv)
            or binding.get("handler_index") != 0
            or binding.get("handler_id") != f"codex:{event_name}:guard-handler-v1"
        ):
            _raise_manifest_failure(
                "codex_hook_manifest_registration_invalid",
                "The Codex hook manifest contains an invalid event identity; repair the installation.",
            )
        if split_hook_command(handler.get("command")) != argv or argv != expected_argv:
            _raise_manifest_failure(
                "codex_hook_manifest_argv_mismatch",
                "The Codex hook manifest argv identity changed; repair the installation.",
            )
        groups = hooks.get(event_name)
        if not isinstance(groups, list):
            continue
        matching_index = next((index for index, group in enumerate(groups) if group == expected_group), None)
        if matching_index is not None:
            event_matches[event_name] = True
            matched_group_indexes[event_name] = matching_index
    return matched_group_indexes


def _hooks_have_registered_entries(hooks: object) -> bool:
    return isinstance(hooks, dict) and any(
        isinstance(hooks.get(event_name), list) and bool(hooks[event_name]) for event_name in MANAGED_CODEX_HOOK_EVENTS
    )


def _manifest_failure_status(reason: str) -> str:
    if reason in {
        "codex_hook_config_target_missing",
        "codex_hook_manifest_missing",
        "codex_hook_manifest_secret_missing",
        "codex_hook_registration_missing",
    }:
        return "missing"
    if reason in {
        "codex_hook_manifest_key_mismatch",
        "codex_hook_manifest_installation_mismatch",
        "codex_hook_manifest_context_mismatch",
        "codex_hook_manifest_config_target_mismatch",
    }:
        return "foreign"
    if reason in {
        "codex_hook_manifest_schema_unsupported",
        "codex_hook_manifest_package_version_stale",
        "codex_hook_manifest_registration_stale",
        "codex_hook_manifest_packaged_files_stale",
    }:
        return "stale"
    return "tampered"


def _raise_manifest_failure(reason: str, message: str) -> NoReturn:
    raise CodexHookIntegrityError(reason, message)


__all__ = [
    "MANAGED_CODEX_HOOK_EVENTS",
    "CodexHookManifestSpec",
    "assert_package_reauthentication_is_safe",
    "authenticated_manifest_for_ownership",
    "build_authenticated_hook_manifest",
    "load_hook_manifest_baseline",
    "manifest_bindings",
    "verify_live_hook_manifest",
]
