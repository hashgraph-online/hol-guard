"""Explicit opt-in installation inside a private qualification fixture only.

Normal adapter install/repair/refresh and signed Desktop proxy selection never
call this module. The caller must provide a private fixture root and a verified
installed wheel; source imports or runtime environment overrides are rejected.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters import claude_native_pilot_fallback, claude_native_pilot_record
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_hook_config import command_handler_argv, is_guard_hook_handler
from codex_plugin_scanner.guard.adapters.claude_native_pilot_record import (
    EVENTS,
    PURPOSE,
    SCHEMA,
    bounded_read,
    file_binding,
)
from codex_plugin_scanner.guard.codex_hook_integrity import atomic_write_bytes, load_or_create_hook_secret
from codex_plugin_scanner.guard.codex_hook_launch_runtime import isolated_daemon_start_command
from codex_plugin_scanner.guard.local_authority_integrity import sign_local_authority_payload
from scripts.native_slo_artifact import assert_installed_import_origin
from scripts.native_slo_contract import proof_environment_violations


def _private_root(path: Path) -> Path:
    current = path.lstat()
    if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.getuid() or current.st_mode & 0o077:
        raise ValueError("claude_pilot_fixture_root_must_be_private")
    return path.resolve(strict=True)


def _installed_runtime() -> Path:
    if sys.platform != "linux" or bool(getattr(sys, "frozen", False)):
        raise ValueError("claude_pilot_platform_or_frozen_unsupported")
    if proof_environment_violations():
        raise ValueError("claude_pilot_requires_no_override_installed_selection")
    status = native_runtime.native_runtime_status()
    runtime = native_runtime._bundled_runtime_candidate()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.identity.path != runtime.resolve()
    ):
        raise ValueError("claude_pilot_installed_runtime_unverified")
    # An actual wheel record is required; merely copying a binary into src is
    # insufficient. Installed distribution membership binds the helper too.
    from importlib import metadata

    distribution = metadata.distribution("hol-guard")
    assert_installed_import_origin(distribution)
    members = {Path(distribution.locate_file(member)).resolve() for member in distribution.files or ()}
    for member in (
        runtime,
        runtime.with_name("runtime-manifest.json"),
        Path(claude_native_pilot_fallback.__file__),
        Path(claude_native_pilot_record.__file__),
    ):
        if member.resolve() not in members:
            raise ValueError("claude_pilot_requires_installed_wheel_membership")
    return runtime


def install_private_pilot(
    context: HarnessContext,
    *,
    qualification_root: Path,
    require_native_transport: bool = False,
) -> Path:
    """Opt in exactly two already-managed registrations; bind every final byte."""
    if type(require_native_transport) is not bool:
        raise ValueError("claude_pilot_transport_requirement_invalid")
    root = _private_root(qualification_root)
    runtime = _installed_runtime()
    for path in (context.home_dir, context.guard_home, context.workspace_dir):
        if path is None or not path.resolve().is_relative_to(root):
            raise ValueError("claude_pilot_context_outside_private_fixture")
    previous_path = context.guard_home / "managed" / "claude-pilot" / "launcher.json"
    if previous_path.exists():
        previous = claude_native_pilot_record.load_record(previous_path, EVENTS[0], require_registration=False)
        current_digest = hashlib.sha256(bounded_read(Path(previous["configuration"]))).hexdigest()
        if previous.get("require_native_transport", False) is not require_native_transport:
            raise ValueError("claude_pilot_transport_requirement_changed")
        if current_digest == previous["registration_sha256"]:
            claude_native_pilot_record.load_record(previous_path, EVENTS[0])
            claude_native_pilot_record.load_record(previous_path, EVENTS[1])
            return previous_path
        if current_digest != previous["original_registration_sha256"]:
            raise ValueError("claude_pilot_existing_registration_changed")
    result = ClaudeCodeHarnessAdapter().install(context)
    configuration = Path(str(result["config_path"]))
    original = bounded_read(configuration)
    settings = json.loads(original)
    records: dict[str, dict[str, object]] = {}
    for event in EVENTS:
        matches = [
            handler
            for group in settings["hooks"][event]
            for handler in group.get("hooks", [])
            if is_guard_hook_handler(handler)
        ]
        if len(matches) != 1:
            raise ValueError("claude_pilot_existing_registration_ambiguous")
        records[event] = matches[0]
    argv = command_handler_argv(records[EVENTS[0]])
    if argv is None or len(argv) != 4 or argv[1] != "-c" or not Path(argv[0]).is_absolute():
        raise ValueError("claude_pilot_existing_registration_unsupported")
    if any(command_handler_argv(handler) != argv for handler in records.values()):
        raise ValueError("claude_pilot_existing_registration_inconsistent")
    bridge = json.loads(argv[3])
    if set(bridge) != {"state_path", "fallback_daemon_url", "fallback_command", "query"}:
        raise ValueError("claude_pilot_existing_bridge_contract_changed")
    package_root = Path(claude_native_pilot_fallback.__file__).resolve().parents[3]
    secret = load_or_create_hook_secret(context.guard_home)
    folder = context.guard_home / "managed" / "claude-pilot"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_root(folder)
    record_path = folder / "launcher.json"
    pilot_argv = {
        event: [str(runtime), "claude-hook-pilot", "--registration", str(record_path), "--event", event]
        for event in EVENTS
    }
    for event, handler in records.items():
        handler["command"] = pilot_argv[event][0]
        handler["args"] = pilot_argv[event][1:]
    encoded = json.dumps(settings, indent=2).encode("utf-8")
    bindings = {
        "runtime": file_binding(runtime),
        "manifest": file_binding(runtime.with_name("runtime-manifest.json")),
        "interpreter": file_binding(Path(argv[0]), invocation=True),
        "helper": file_binding(Path(claude_native_pilot_fallback.__file__)),
        "record_helper": file_binding(Path(claude_native_pilot_record.__file__)),
    }
    for name in (
        "adapters/claude_daemon_hook_bridge.py",
        "adapters/claude_daemon_hook_transport.py",
        "adapters/codex_daemon_hook_auth.py",
        "adapters/claude_daemon_state.py",
        "codex_hook_launch_runtime.py",
        "codex_hook_process_runtime.py",
        "codex_hook_integrity.py",
        "codex_hook_file_integrity.py",
        "local_authority_integrity.py",
    ):
        bindings[name] = file_binding(package_root / "codex_plugin_scanner" / "guard" / name)
    unsigned: dict[str, object] = {
        "schema": SCHEMA,
        "require_native_transport": require_native_transport,
        "installation_id": secret.installation_id,
        "guard_home": str(context.guard_home),
        "home_dir": str(context.home_dir),
        "workspace": str(context.workspace_dir),
        "configuration": str(configuration),
        "registration_sha256": hashlib.sha256(encoded).hexdigest(),
        "argv": pilot_argv,
        "original_registration_sha256": hashlib.sha256(original).hexdigest(),
        "original_configuration": original.decode("utf-8"),
        "bridge": bridge,
        "files": bindings,
        "recovery_command": list(
            isolated_daemon_start_command(
                argv[0],
                package_root,
                context.guard_home,
                context.home_dir,
            )
        ),
    }
    signed = {
        **unsigned,
        "authentication": sign_local_authority_payload(
            unsigned,
            key=secret.key,
            key_id=secret.key_id,
            purpose=PURPOSE,
            signed_at=datetime.now(timezone.utc).isoformat(),
        ),
    }
    # A failure between the two atomic writes leaves an unusable private pilot
    # record, never a valid command bound to an unauthenticated configuration.
    atomic_write_bytes(
        record_path, json.dumps(signed, sort_keys=True, ensure_ascii=True).encode(), mode=0o600, private=True
    )
    atomic_write_bytes(configuration, encoded, mode=0o600, private=False)
    return record_path


def restore_private_pilot(path: Path) -> None:
    record = claude_native_pilot_record.load_record(path, EVENTS[0])
    original = record["original_configuration"].encode("utf-8")
    if hashlib.sha256(original).hexdigest() != record["original_registration_sha256"]:
        raise ValueError("claude_pilot_original_registration_invalid")
    atomic_write_bytes(Path(record["configuration"]), original, mode=0o600, private=False)
    # Restoring the exact original registration invalidates the old pilot's
    # registration digest even while its evidence record is retained.


def activate_private_pilot(path: Path) -> None:
    """Select an authenticated pilot again after an exact private restore."""
    _installed_runtime()
    record = claude_native_pilot_record.load_record(path, EVENTS[0], require_registration=False)
    configuration = Path(record["configuration"])
    if hashlib.sha256(bounded_read(configuration)).hexdigest() != record["original_registration_sha256"]:
        raise ValueError("claude_pilot_reactivation_requires_exact_original")
    settings = json.loads(record["original_configuration"])
    for event in EVENTS:
        matches = [
            handler
            for group in settings["hooks"][event]
            for handler in group.get("hooks", [])
            if is_guard_hook_handler(handler)
        ]
        if len(matches) != 1:
            raise ValueError("claude_pilot_original_registration_ambiguous")
        matches[0]["command"] = record["argv"][event][0]
        matches[0]["args"] = record["argv"][event][1:]
    encoded = json.dumps(settings, indent=2).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != record["registration_sha256"]:
        raise ValueError("claude_pilot_reactivation_bytes_changed")
    atomic_write_bytes(configuration, encoded, mode=0o600, private=False)
