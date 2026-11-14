"""Codex harness adapter.

The native runtime owns the hook groups and bridge argv Guard registers, the
hook-group identities a migration compares, the MCP and hook rewrites of a
config, the hook state launch and doctor read, and the files an install plans
besides the config. Python keeps the TOML reads and renders, the authenticated
hook manifest, the ownership strips over existing hooks and every publication.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...version import __version__
from ..aibom_detection import (
    detection_from_payload,
    extend_codex_runtime_inventory,
    extend_detection_with_workspace_aibom,
    native_adapter_detection_payload,
)
from ..codex_config import _Wire, dump_toml, read_toml_payload
from ..codex_hook_command_line import render_hook_command
from ..codex_hook_compatibility import NATIVE_CODEX_HOOK_FEATURE, python_bridge_argv
from ..codex_hook_file_integrity import validate_regular_file
from ..codex_hook_integrity import (
    atomic_write_text,
    canonical_manifest_bytes,
    hook_authority_receipt_path,
    hook_manifest_path,
    hook_secret_path,
    remove_hook_secret_if_unused,
)
from ..codex_hook_launch_runtime import isolated_daemon_start_command, isolated_guard_cli_command
from ..codex_hook_manifest import (
    CodexHookManifestSpec,
    build_authenticated_hook_manifest,
    load_hook_manifest_baseline,
    prepare_authenticated_hook_publication,
    verify_live_hook_manifest,
)
from ..codex_hook_manifest import (
    manifest_bindings as _manifest_bindings,
)
from ..codex_hook_recovery import (
    commit_hook_publication,
    hook_publication_pending,
    mark_owned_hook_publication_conflict,
    prepare_hook_publication,
    recover_hook_publication,
)
from ..codex_hook_registration import (
    finalize_codex_doctor_setup_status,
    finalize_codex_doctor_warnings,
    install_managed_codex_hook_groups,
    legacy_binding_fields,
    overlay_live_owned_event_matches,
    require_codex_hook_owner,
)
from ..codex_hook_registration import (
    remove_manifest_bound_hook_events as _remove_manifest_bound_hook_events,
)
from ..codex_hook_rollback import require_unchanged_config_for_rollback, rollback_file_identity
from ..codex_hook_self_binding import (
    answer_text,
    ask_hook_owners,
    install_fields,
    settle_short_paths,
    short_path_fields,
)
from ..codex_hook_sources import parse_json_object, parse_toml_object
from ..codex_hook_sources import strict_json_object as _strict_json_object
from ..codex_hook_sources import strict_toml_object as _strict_toml_object
from ..codex_hook_trust import (
    apply_codex_hook_trust_doctor,
    codex_hook_trust_stale,
    record_guard_hook_trust,
    remap_hook_state,
)
from ..codex_install_transaction import codex_install_transaction
from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config, resolve_guard_home
from ..launcher import merge_guard_launcher_env
from ..models import HarnessDetection
from ..native_codex_hook_identity import wire_codex_hook_bindings as _wire_bindings
from ..native_path_anchor import anchor_to_process_directory
from ..shims import prepare_guard_shim, prepare_guard_shim_removal
from ..stable_guard_cli import resolve_frozen_guard_cli
from .base import HarnessContext, PreparedHarnessInstall
from .codex_detect_sources import path_restorations, read_source_bytes
from .codex_remote_control import (
    codex_remote_launch_environment,
    guarded_codex_launch_command,
    guarded_codex_launch_command_candidates,
    guarded_codex_launch_command_from_prefix,
)
from .mcp_relay_native import mcp_proxy_launch, python_proxy_launch
from .mcp_servers import (
    ManagedMcpServer,
    managed_stdio_servers,
    proxy_launcher_entry,
    skipped_stdio_server_names,
)
from .native_harness import NativeHarnessAdapter, ask, planned_files
from .native_hook_bridge import native_hook_bridge_executable

if TYPE_CHECKING:
    from ..codex_hook_manifest import PreparedCodexHookPublication
    from ..runtime_transition import TransitionFile

__all__ = ("_command_available", "atomic_write_text", "build_authenticated_hook_manifest", "sys")

_read_toml = read_toml_payload

_LEGACY_MANAGED_HOOK_STATUS_MESSAGES = {
    "HOL Guard checking Bash command",
    "HOL Guard checking tool action",
    "HOL Guard checking prompt",
    "HOL Guard checking Codex approval request",
    "HOL Guard checking tool result",
}
_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5
_CODEX_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON = "codex_authoritative_hook_unavailable"


def _codex(op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    return ask(op, context, harness="codex", **fields)


def _command_available(context: HarnessContext) -> bool:
    """Whether the Codex CLI is on the caller's PATH or in a user install directory."""

    return _codex("command_available", context).get("available") is True


def _reply_text(answer: Mapping[str, object], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise ValueError("Harness adapter answer is malformed")
    return value


def _hook_workspace_dir(context: HarnessContext) -> Path | None:
    return context.workspace_dir if context.workspace_override_explicit else None


def _json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _argv_fields(context: HarnessContext, *, home_is_current: bool) -> dict[str, object]:
    guard_home = resolve_guard_home() if home_is_current else context.guard_home
    return {
        "home_is_current": home_is_current,
        "runtime_guard_home": str(guard_home.resolve(strict=False)),
        "workspace_explicit": context.workspace_override_explicit,
    }


def _local_hook_command_parts_for_home_mode(
    context: HarnessContext,
    *,
    home_is_current: bool,
    python_executable: str,
) -> tuple[str, ...]:
    answer = _codex("argv", context, **_argv_fields(context, home_is_current=home_is_current))
    guard_args = [str(part) for part in answer["reply"]["launch"]]
    package_root = Path(__file__).resolve().parents[3]
    return isolated_guard_cli_command(python_executable, package_root, guard_args)


def _guard_python_executable() -> str:
    """Use a prune-safe frozen launcher, else the current interpreter identity."""

    if bool(getattr(sys, "frozen", False)):
        return resolve_frozen_guard_cli()
    return str(Path(sys.executable).expanduser().absolute())


def _home_is_current(context: HarnessContext) -> bool:
    return not context.home_override_explicit and context.home_dir.resolve() == Path.home().resolve()


def _runtime_guard_home(context: HarnessContext) -> Path:
    guard_home = resolve_guard_home() if _home_is_current(context) else context.guard_home
    return guard_home.resolve(strict=False)


def _local_hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    return _local_hook_command_parts_for_home_mode(
        context,
        home_is_current=_home_is_current(context),
        python_executable=_guard_python_executable(),
    )


def _daemon_start_command(
    guard_home: Path,
    home_dir: Path,
    *,
    python_executable: str = sys.executable,
) -> tuple[str, ...]:
    package_root = Path(__file__).resolve().parents[3]
    return isolated_daemon_start_command(
        python_executable,
        package_root,
        guard_home.resolve(strict=False),
        home_dir.resolve(strict=False),
    )


def _native_bridge_executable(guard_home: Path) -> Path | None:
    # HOL_GUARD_CODEX_HOOK_BRIDGE=python keeps the Python bridge argv. Contract
    # tests set it so a subprocess install and the parent verifier agree. The
    # Python bridge is the same fallback used when the native runtime is absent.
    if os.environ.get("HOL_GUARD_CODEX_HOOK_BRIDGE") == "python":
        return None
    return native_hook_bridge_executable(NATIVE_CODEX_HOOK_FEATURE, guard_home=guard_home)


def _hook_command_parts_for_home_mode(
    context: HarnessContext,
    *,
    home_is_current: bool,
    python_executable: str,
) -> tuple[str, ...]:
    fields = _argv_fields(context, home_is_current=home_is_current)
    guard_home = Path(str(fields["runtime_guard_home"]))
    fallback = _local_hook_command_parts_for_home_mode(
        context, home_is_current=home_is_current, python_executable=python_executable
    )
    start = _daemon_start_command(guard_home, context.home_dir, python_executable=python_executable)
    # The native runtime answers each hook from the daemon without starting
    # Python and fails closed without one. It only reads the config the
    # Python bridge argv carries.
    native_bridge = _native_bridge_executable(guard_home)
    answer = _codex(
        "argv",
        context,
        **fields,
        python=python_executable,
        bridge=str(Path(__file__).with_name("codex_daemon_hook_bridge.py").resolve()),
        native_bridge=None if native_bridge is None else str(native_bridge),
        manifest_path=str(hook_manifest_path(guard_home, CodexHarnessAdapter._hook_config_path(context))),
        long_timeout=_post_tool_hook_timeout_seconds(context),
        launch={"fallback": list(fallback), "start": list(start)},
    )
    return tuple(str(part) for part in answer["argv"])


def _hook_command_parts(context: HarnessContext) -> tuple[str, ...]:
    return _hook_command_parts_for_home_mode(
        context,
        home_is_current=_home_is_current(context),
        python_executable=_guard_python_executable(),
    )


def _hook_command(context: HarnessContext) -> str:
    return render_hook_command(_hook_command_parts(context))


def _post_tool_hook_timeout_seconds(context: HarnessContext) -> int:
    configured_wait_timeout = load_guard_config(
        context.guard_home,
        _hook_workspace_dir(context),
        create_home=False,
    ).approval_wait_timeout_seconds
    return (
        min(
            max(configured_wait_timeout, 0),
            MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
        )
        + _MANAGED_HOOK_TIMEOUT_GRACE_SECONDS
    )


@dataclass(frozen=True, slots=True)
class _HookRegistration:
    """The argv, groups and manifest bindings of the hooks Guard registers."""

    argv: tuple[str, ...]
    groups: str
    bindings: str


def _hook_registration(context: HarnessContext) -> _HookRegistration:
    argv = _hook_command_parts(context)
    environment = merge_guard_launcher_env(pin_package=True)
    environment.update(codex_remote_launch_environment(context.home_dir))
    answer = _codex(
        "groups",
        context,
        argv=list(argv),
        command=render_hook_command(argv),
        env=json.dumps(environment),
        long_timeout=_post_tool_hook_timeout_seconds(context),
    )
    return _HookRegistration(argv, _reply_text(answer, "groups"), _reply_text(answer, "bindings"))


def _managed_hook_groups(context: HarnessContext) -> dict[str, dict[str, object]]:
    return json.loads(_hook_registration(context).groups)


def _manifest_event_bindings(context: HarnessContext) -> list[dict[str, object]]:
    return json.loads(_hook_registration(context).bindings)


def _hook_packaged_file_paths() -> tuple[tuple[str, Path], ...]:
    scanner_root = Path(__file__).resolve().parents[2]
    guard_root = Path(__file__).resolve().parents[1]
    return (
        ("bridge", Path(__file__).with_name("codex_daemon_hook_bridge.py").resolve()),
        ("bridge_runtime", guard_root / "codex_hook_bridge_runtime.py"),
        ("hook_probe", guard_root / "runtime_transition_hook_probe.py"),
        ("native_receipt", guard_root / "native_decision_receipt.py"),
        ("fallback_entrypoint", scanner_root / "cli.py"),
        ("daemon_entrypoint", guard_root / "cli" / "daemon_serve.py"),
        ("daemon_manager", guard_root / "native_daemon_manage.py"),
        ("launch_runtime", guard_root / "codex_hook_launch_runtime.py"),
        ("runtime_trust", guard_root / "codex_hook_runtime_trust.py"),
        ("windows_job", guard_root / "codex_hook_windows_job.py"),
    )


def _hook_manifest_spec(context: HarnessContext) -> CodexHookManifestSpec:
    return CodexHookManifestSpec(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        runtime_guard_home=_runtime_guard_home(context),
        workspace_dir=_hook_workspace_dir(context),
        config_path=CodexHarnessAdapter._hook_config_path(context),
        interpreter_path=Path(_guard_python_executable()),
        package_version=__version__,
        packaged_file_paths=_hook_packaged_file_paths(),
        fallback_argv=_local_hook_command_parts(context),
        daemon_start_argv=_daemon_start_command(
            _runtime_guard_home(context),
            context.home_dir,
            python_executable=_guard_python_executable(),
        ),
        event_bindings=tuple(_manifest_event_bindings(context)),
        workspace_rebinding_allowed=not context.workspace_override_explicit,
    )


def _legacy_fields(context: HarnessContext, registration: _HookRegistration | None = None) -> dict[str, Any]:
    """What an exact current bridge entry is matched against for legacy re-adoption."""

    registration = registration or _hook_registration(context)
    current_argv = list(registration.argv)
    # python_bridge_argv keeps the object sequence it was given. This argv is
    # a string command, so only those strings identify the legacy registration.
    legacy_tail = [part for part in python_bridge_argv(current_argv)[1:] if isinstance(part, str)]
    return legacy_binding_fields(
        expected_bindings=json.loads(registration.bindings),
        current_argv=current_argv,
        legacy_argv=[sys.executable, *legacy_tail],
        legacy_status_messages=_LEGACY_MANAGED_HOOK_STATUS_MESSAGES,
    )


def _current_install_legacy_bindings(
    context: HarnessContext,
    hooks: dict[str, object],
    registration: _HookRegistration | None = None,
) -> list[dict[str, object]]:
    """Select exact current bridge entries for explicit legacy re-adoption only."""

    wire = _Wire(hooks)
    answer = ask_hook_owners("legacy", hooks=wire.text(hooks), **_legacy_fields(context, registration))
    return wire.decode(answer_text(answer, "bindings"))


def _strip_owned_hooks(
    context: HarnessContext,
    hooks: dict[str, object],
    owned_bindings: Sequence[Mapping[str, object]],
    *,
    unlaunchable: bool = True,
    hold_recorded: bool = False,
) -> dict[str, object]:
    """The hooks left once every Guard-owned handler is gone.

    The owned handlers go first, then this package's legacy registrations,
    then (``unlaunchable``) legacy registrations whose launcher no longer
    exists, which folding into the active config would leave the harness
    invoking a missing program, and last the handlers an earlier generation
    of this install left. The manifest authenticates the config entries, not
    hooks.json, so only a config cleanup (``hold_recorded``) holds back a
    handler still running a command the owned bindings record.
    """

    owned = list(owned_bindings)
    wire = _Wire(hooks, owned)
    answer = ask_hook_owners(
        "strip",
        hooks=wire.text(hooks),
        owned=wire.text(owned),
        unlaunchable=unlaunchable,
        hold_recorded=hold_recorded,
        **_legacy_fields(context),
        **install_fields(_runtime_guard_home(context), None),
    )
    return wire.decode(answer_text(answer, "hooks"))


def _migrate_hooks_json_into_config(
    config_payload: dict[str, object],
    hooks_payload: dict[str, object],
    *,
    context: HarnessContext,
    source_scope: str,
    owned_bindings: Sequence[Mapping[str, object]] = (),
) -> bool:
    json_hooks = hooks_payload.get("hooks")
    if not isinstance(json_hooks, dict):
        return False
    cleaned = _strip_owned_hooks(context, json_hooks, owned_bindings)
    wire = _Wire(config_payload, cleaned)
    config_text = wire.text(config_payload)
    hooks_text = wire.text(cleaned)
    answer = _codex("migrate", context, config=config_text, hooks=hooks_text, tokens=wire.meanings, scope=source_scope)
    migrated = wire.decode(_reply_text(answer, "config"))
    config_payload.clear()
    config_payload.update(migrated)
    return answer.get("changed") is True


def _hook_tables(payload: Mapping[str, object]) -> dict[str, object]:
    """The part of a config the hook comparisons read: its hooks and their feature flag.

    The rest of a config can be arbitrarily large and would push the request
    past the native size cap without changing the answer.
    """

    tables: dict[str, object] = {}
    if "hooks" in payload:
        tables["hooks"] = payload["hooks"]
    features = payload.get("features")
    if isinstance(features, Mapping) and "hooks" in features:
        tables["features"] = {"hooks": features["hooks"]}
    return tables


def _require_hook_semantics_readback(
    expected: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    source_scope: str,
    source_path: Path,
    context: HarnessContext,
) -> None:
    expected, actual = _hook_tables(expected), _hook_tables(actual)
    wire = _Wire(expected, actual)
    _codex(
        "readback",
        context,
        expected=wire.text(expected),
        actual=wire.text(actual),
        tokens=wire.meanings,
        scope=source_scope,
        source_path=str(source_path),
    )


def _require_migrated_hooks(
    context: HarnessContext,
    expected: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    source_scope: str,
    hooks_path: Path | None = None,
    config_path: Path | None = None,
) -> None:
    """Every hook a migration carried over is still in ``actual``."""

    expected, actual = _hook_tables(expected), _hook_tables(actual)
    wire = _Wire(expected, actual)
    fields: dict[str, object] = {"expected": wire.text(expected), "actual": wire.text(actual)}
    if hooks_path is not None and config_path is not None:
        fields.update(hooks_path=str(hooks_path), config_path=str(config_path))
    _codex("subset", context, **fields, tokens=wire.meanings, scope=source_scope)


def _unmanaged_migration_payload(
    hooks_payload: Mapping[str, object],
    *,
    context: HarnessContext,
    owned_bindings: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    hooks = hooks_payload.get("hooks")
    if not isinstance(hooks, dict):
        return {}
    # The migration prunes unlaunchable legacy launchers instead of adopting
    # them, so the identities verification expects are pruned by the same rule.
    cleaned_hooks = _strip_owned_hooks(context, hooks, owned_bindings)
    return {"hooks": cleaned_hooks} if cleaned_hooks else {}


def _one_planned_file(answer: dict[str, Any]) -> TransitionFile:
    return planned_files({"files": [answer["file"]]})[0]


def _b64(data: bytes | None) -> str | None:
    return None if data is None else base64.b64encode(data).decode("ascii")


def _prepare_hook_migration_backup(
    context: HarnessContext,
    *,
    config_path: Path,
    before_config: bytes | None,
) -> TransitionFile:
    return _one_planned_file(_codex("migration_backup", context, config=str(config_path), before=_b64(before_config)))


@dataclass(frozen=True, slots=True)
class PreparedCodexHookMigration:
    """Captured JSON migration segment; publication requires the complete install."""

    config_payload: dict[str, object]
    files: tuple[TransitionFile, ...]


def _withdraw_publication(context: HarnessContext, publication: PreparedCodexHookPublication) -> None:
    """Publish a committed hook generation's inverse, as long as nobody changed it since."""

    inverse = tuple(
        replace(
            change,
            before=change.after,
            after=change.before,
            before_mode=change.after_mode,
            after_mode=change.before_mode,
        )
        for change in publication.files
    )
    try:
        PreparedHarnessInstall(inverse, {}).publish(context.guard_home, removals=True)
        remove_hook_secret_if_unused(context.guard_home)
    except BaseException as error:
        raise RuntimeError(
            "codex_hook_migration_rollback_failed: Guard could not fully restore Codex hook sources after "
            "legacy JSON removal failed. Run `hol-guard install codex` to repair the installation."
        ) from error


@dataclass(frozen=True, slots=True)
class _CodexInstallPlan:
    """A prepared install, with what publishing it as an ordinary install needs."""

    prepared: PreparedHarnessInstall
    publication: PreparedCodexHookPublication
    backups: frozenset[Path]
    shim_manifest: Mapping[str, object]
    fields: dict[str, object]


def prepare_codex_hook_migration(
    context: HarnessContext,
    *,
    config_path: Path,
    hooks_path: Path,
    owned_bindings: Sequence[Mapping[str, object]] = (),
    expected_config_payload: Mapping[str, object] | None = None,
    expected_hooks_payload: Mapping[str, object] | None = None,
    require_owners: bool = False,
) -> PreparedCodexHookMigration:
    from ..codex_hook_recovery import _snapshot
    from ..runtime_transition import RuntimeTransition, TransitionFile

    scope = CodexHarnessAdapter._scope_for(context, config_path)
    config_path = config_path.parent.resolve(strict=False) / config_path.name
    hooks_path = hooks_path.parent.resolve(strict=False) / hooks_path.name
    before_config = _snapshot(config_path)
    before_hooks = _snapshot(hooks_path)
    config = parse_toml_object(before_config, path=config_path, label="Codex config file")
    hooks = parse_json_object(before_hooks, path=hooks_path, label="Codex hooks file")
    if (expected_config_payload is not None and config != expected_config_payload) or (
        expected_hooks_payload is not None and hooks != expected_hooks_payload
    ):
        raise RuntimeError("codex_hook_inventory_source_changed: Codex migration sources changed after inventory.")
    enabled = _payload_has_hooks_feature_enabled(config)
    for payload, path, source_format, bindings in (
        (config, config_path, "toml", owned_bindings),
        (hooks, hooks_path, "json", ()),
    ):
        owners = _preactivation_owners(
            payload,
            source_path=path,
            source_scope=scope,
            source_format=source_format,
            source_hooks_enabled=enabled,
            context=context,
            authenticated_bindings=bindings,
        )
        if require_owners:
            _require_preactivation_owners(owners, path)
    changed = _migrate_hooks_json_into_config(
        config, hooks, context=context, source_scope=scope, owned_bindings=owned_bindings
    )
    config_mode = config_path.stat().st_mode & 0o777 if before_config is not None else 0o600
    hook_mode = hooks_path.stat().st_mode & 0o777 if before_hooks is not None else 0o600
    files = [
        TransitionFile(
            config_path,
            before_config,
            dump_toml(config, original=before_config).encode("utf-8") if changed else before_config,
            before_mode=config_mode,
            after_mode=0o600 if changed else config_mode,
            no_follow=True,
        ),
        TransitionFile(hooks_path, before_hooks, None, before_mode=hook_mode, after_mode=hook_mode, no_follow=True),
    ]
    if changed:
        files.append(_prepare_hook_migration_backup(context, config_path=config_path, before_config=before_config))
    RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
    return PreparedCodexHookMigration(config, tuple(files))


def prepare_codex_main_backup(
    context: HarnessContext,
    *,
    original: bytes | None,
    migrated_payload: dict[str, object] | None = None,
) -> TransitionFile:
    """Retain an existing backup, or capture the ordinary install's backup content."""
    from ..runtime_transition import RuntimeTransition

    content: dict[str, object] = (
        {"migrated": dump_toml(migrated_payload, original=original)}
        if migrated_payload is not None
        else {"original": _b64(original)}
    )
    change = _one_planned_file(_codex("main_backup", context, **content))
    RuntimeTransition._compare({"files": [change.payload()]}, "before")
    return change


def render_codex_managed_mcp(
    context: HarnessContext,
    payload: dict[str, object],
    *,
    managed_servers: tuple[ManagedMcpServer, ...],
    workspace_payload: dict[str, object],
) -> tuple[dict[str, object], tuple[str, ...]]:
    """Render proxy refresh and workspace precedence from captured payloads."""
    adapter = CodexHarnessAdapter()
    entries = [(server, adapter._proxy_server_entry(context, server)) for server in managed_servers]
    wire = _Wire(payload, workspace_payload, *(entry for _server, entry in entries))
    fields: dict[str, object] = {
        "payload": wire.text(payload),
        "workspace_payload": None if context.workspace_dir is None else wire.text(workspace_payload),
        "servers": [
            {"name": server.name, "source_scope": server.source_scope, "entry": wire.text(entry)}
            for server, entry in entries
        ],
    }
    answer = _codex("managed_mcp", context, **fields)
    if set(answer) == {"reply"}:
        # Each Guard proxy is relaunched the way this process would write it.
        python = _guard_python_executable()
        relaunch: dict[str, object] = {}
        for name, args in answer["reply"]["relaunch"].items():
            _, python_args = python_proxy_launch(None, tuple(str(arg) for arg in args))
            launcher, launch_args = mcp_proxy_launch(python, python_args)
            relaunch[str(name)] = [launcher, list(launch_args)]
        answer = _codex("managed_mcp", context, **fields, relaunch=relaunch)
    rendered = wire.decode(_reply_text(answer, "rendered"))
    return rendered, tuple(str(name) for name in answer["migrated"])


def _alternate_cleanup(
    context: HarnessContext,
    payload: dict[str, object],
    *,
    remove_hooks: bool,
    managed_server_names: Sequence[str],
) -> tuple[dict[str, object], bool, bool]:
    """The cleaned payload, and whether it or its hook tables changed."""
    legacy: tuple[dict[str, object], bool] | None = None
    hooks = payload.get("hooks")
    if remove_hooks and isinstance(hooks, dict):
        bindings = _current_install_legacy_bindings(context, hooks)
        cleaned, removed = _remove_manifest_bound_hook_events(hooks, bindings)
        legacy = (cleaned, bool(removed))
    wire = _Wire(payload, *(() if legacy is None else (legacy[0],)))
    answer = _codex(
        "alternate_cleanup",
        context,
        payload=wire.text(payload),
        remove_hooks=remove_hooks,
        legacy=None if legacy is None else {"removed": legacy[1], "cleaned": wire.text(legacy[0])},
        managed_server_names=list(managed_server_names),
        tokens=wire.meanings,
    )
    rendered = wire.decode(_reply_text(answer, "rendered"))
    return rendered, answer.get("changed") is True, answer.get("hooks_changed") is True


def render_codex_alternate_cleanup(
    context: HarnessContext,
    payload: dict[str, object],
    *,
    remove_hooks: bool = True,
    managed_server_names: Sequence[str] = (),
) -> dict[str, object]:
    """Render scoped alternate cleanup without publishing or changing its input."""
    rendered, _changed, _hooks_changed = _alternate_cleanup(
        context, payload, remove_hooks=remove_hooks, managed_server_names=managed_server_names
    )
    return rendered


def prepare_codex_alternate_cleanup(
    context: HarnessContext,
    *,
    config_path: Path,
    remove_hooks: bool = True,
    managed_server_names: Sequence[str] = (),
) -> TransitionFile:
    """Capture one cleanup segment; this is not a complete Codex install plan."""
    from ..codex_hook_recovery import _snapshot
    from ..runtime_transition import RuntimeTransition, TransitionFile

    config_path = config_path.parent.resolve(strict=False) / config_path.name
    before = _snapshot(config_path)
    payload = parse_toml_object(before, path=config_path, label="Codex config file")
    mode = config_path.stat().st_mode & 0o777 if before is not None else 0o600
    rendered, changed, hooks_changed = _alternate_cleanup(
        context, payload, remove_hooks=remove_hooks, managed_server_names=managed_server_names
    )
    change = TransitionFile(
        config_path,
        before,
        dump_toml(rendered, original=before).encode("utf-8") if changed else before,
        before_mode=mode,
        after_mode=0o600 if hooks_changed else mode,
        no_follow=True,
    )
    RuntimeTransition._compare({"files": [change.payload()]}, "before")
    return change


def _preactivation_owners(
    payload: Mapping[str, object],
    *,
    source_path: Path,
    source_scope: str,
    source_format: str,
    source_hooks_enabled: bool,
    context: HarnessContext,
    authenticated_bindings: Sequence[Mapping[str, object]] = (),
) -> list[dict[str, str]]:
    """Every active handler with a command in one source, once nothing refuses it.

    The native ``preactivation`` op walks the source with this install's
    legacy and self bindings and refuses as a complete preactivation inventory
    must: the first issue, then unmanaged executable hooks a disabled source
    would switch on.
    """

    hooks = payload.get("hooks")
    owned = list(authenticated_bindings)
    wire = _Wire(hooks, owned)
    answer = ask_hook_owners(
        "preactivation",
        hooks=wire.text(hooks),
        owned=wire.text(owned),
        tokens=wire.meanings,
        source_path=str(source_path),
        scope=source_scope,
        format="json" if source_format == "json" else "toml",
        hooks_enabled=source_hooks_enabled,
        **_legacy_fields(context),
        **install_fields(_runtime_guard_home(context), None),
    )
    if "runtime_error" in answer:
        raise RuntimeError(str(answer["runtime_error"]))
    owners = answer.get("owners")
    if not isinstance(owners, list):
        raise RuntimeError("codex_hook_owners answered without owners")
    return [{key: str(owner[key]) for key in ("command", "ownership", "coordinate")} for owner in owners]


def _require_preactivation_owners(owners: Sequence[Mapping[str, str]], source_path: Path) -> None:
    """Active commands need a verified owner before install enables the feature."""

    for owner in owners:
        require_codex_hook_owner(
            owner["command"],
            ownership=owner["ownership"],
            coordinate=owner["coordinate"],
            source_path=str(source_path),
        )


def _payload_has_hooks_feature_enabled(config_payload: Mapping[str, object]) -> bool:
    features = config_payload.get("features")
    if not isinstance(features, Mapping):
        return True
    return features.get("hooks") is not False


def prepare_codex_shell_cleanup(context: HarnessContext) -> tuple[TransitionFile, ...]:
    """Capture all legacy shell removals without reading through symlinks or publishing."""
    from ..runtime_transition import RuntimeTransition

    files = tuple(planned_files(_codex("shell_cleanup", context)))
    RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
    return files


def _verify_live_hook_manifest(
    context: HarnessContext,
    *,
    config_path: Path,
    hooks: object,
) -> dict[str, object]:
    spec = _hook_manifest_spec(context)
    if spec.config_path != config_path:
        raise RuntimeError("Codex hook verification received a non-canonical config target.")
    return verify_live_hook_manifest(spec, hooks=hooks)


def codex_native_hook_state(context: HarnessContext) -> dict[str, object]:
    config_path = CodexHarnessAdapter._hook_config_path(context)
    hooks_path = CodexHarnessAdapter._hooks_path(context)
    config_payload = _read_toml(config_path)
    features = config_payload.get("features") if isinstance(config_payload, dict) else None
    toml_hooks = config_payload.get("hooks") if isinstance(config_payload, dict) else None
    hooks_payload = _json_object(hooks_path)
    json_hooks = hooks_payload.get("hooks") if isinstance(hooks_payload, dict) else None
    hooks = toml_hooks if isinstance(toml_hooks, dict) else json_hooks
    integrity = _verify_live_hook_manifest(context, config_path=config_path, hooks=hooks)
    event_matches = overlay_live_owned_event_matches(integrity, hooks)
    read = {"features": features, "toml_hooks": toml_hooks, "json_hooks": json_hooks}
    wire = _Wire(read, integrity)
    read_text = wire.text(read)
    integrity_text = wire.text(integrity)
    answer = _codex(
        "hook_state",
        context,
        read=read_text,
        integrity=integrity_text,
        event_matches={str(event): matched is True for event, matched in event_matches.items()},
        trust_stale=codex_hook_trust_stale(config_payload, config_path),
        config_path=str(config_path),
        hooks_path=str(hooks_path),
    )
    return wire.decode(_reply_text(answer, "state"))


def _require_codex_authoritative_shell_hook(context: HarnessContext) -> None:
    hook_state = codex_native_hook_state(context)
    if bool(hook_state["shell_protection_active"]):
        return
    raise RuntimeError(
        f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Guard refused to launch Codex because the managed "
        "PreToolUse and PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` "
        "or `hol-guard update` to repair the native-hook enforcement boundary."
    )


def _located(path: Path) -> Path:
    return path.parent.resolve(strict=False) / path.name


def _install_manifest(
    context: HarnessContext, kind: str, shim_manifest: Mapping[str, object], **fields: object
) -> dict[str, object]:
    fields.setdefault("hooks_path", str(CodexHarnessAdapter._hooks_path(context)))
    answer = _codex(
        "manifest",
        context,
        kind=kind,
        shim=json.dumps(shim_manifest),
        config_path=str(CodexHarnessAdapter._target_config_path(context)),
        hook_config_path=str(CodexHarnessAdapter._hook_config_path(context)),
        workspace_explicit=context.workspace_override_explicit,
        **fields,
    )
    return json.loads(_reply_text(answer, "manifest"))


def _server_fields(
    detection: HarnessDetection, managed_servers: Sequence[ManagedMcpServer], migrated: Sequence[str]
) -> dict[str, object]:
    return {
        "managed": [server.name for server in managed_servers],
        "migrated": list(migrated),
        "skipped": list(skipped_stdio_server_names(detection)),
        "source_config_paths": list(detection.config_paths),
    }


class CodexHarnessAdapter(NativeHarnessAdapter):
    """Discover Codex MCP servers and wrapper surfaces."""

    def __init__(self) -> None:
        super().__init__("codex", (), "")

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def preview_launch_commands(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
    ) -> tuple[list[str], ...]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command_candidates(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def launch_command_from_authorized_plan(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
        *,
        authorized_executable_prefixes: Sequence[Sequence[str]],
        launch_environment: Mapping[str, str],
    ) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        prefixes = {tuple(prefix) for prefix in authorized_executable_prefixes if prefix}
        if len(prefixes) != 1:
            raise ValueError("Codex launch candidates do not share one authorized executable prefix.")
        return guarded_codex_launch_command_from_prefix(
            executable_prefix=prefixes.pop(),
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
            environ=launch_environment,
        )

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        return codex_remote_launch_environment(context.home_dir)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    @staticmethod
    def _hooks_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "hooks.json"

    @staticmethod
    def _all_hook_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".codex" / "hooks.json")
        return tuple(paths)

    @staticmethod
    def _config_hook_pairs(context: HarnessContext) -> tuple[tuple[Path, Path], ...]:
        pairs = [(context.home_dir / ".codex" / "config.toml", context.home_dir / ".codex" / "hooks.json")]
        if context.workspace_dir is not None:
            pairs.append(
                (context.workspace_dir / ".codex" / "config.toml", context.workspace_dir / ".codex" / "hooks.json")
            )
        return tuple(pairs)

    def detect(
        self,
        context: HarnessContext,
        *,
        config_contents: Mapping[Path, bytes | None] | None = None,
    ) -> HarnessDetection:
        pairs = self._config_hook_pairs(context)
        if config_contents is None:
            # One read per file feeds both the legacy-ownership bindings and the
            # native inventory, so a file changing in between cannot split them.
            captured = {path: read_source_bytes(path) for pair in pairs for path in pair}
        else:
            captured = {path: config_contents[path] for pair in pairs for path in pair}
            # An install refuses a captured generation it cannot parse strictly.
            for config, hooks in pairs:
                parse_toml_object(captured[config], path=config, label="Codex config file")
                parse_json_object(captured[hooks], path=hooks, label="Codex hooks file")
        authenticated_manifest = load_hook_manifest_baseline(_hook_manifest_spec(context))
        hook_config_path = self._hook_config_path(context)
        request: dict[str, object] = {
            "harness": self.harness,
            "authenticated_bindings": _wire_bindings(_manifest_bindings(authenticated_manifest)),
            "sources": [
                {
                    "config_path": anchor_to_process_directory(config_path),
                    "hooks_path": anchor_to_process_directory(hooks_path),
                    "config_scope": self._scope_for(context, config_path),
                    "hooks_scope": self._scope_for(context, hooks_path),
                    "authenticated": config_path == hook_config_path,
                }
                for config_path, hooks_path in pairs
            ],
            "contents": {
                anchor_to_process_directory(path): None if data is None else data.hex()
                for path, data in captured.items()
            },
            "restore": [
                list(item) for item in path_restorations(tuple(path for pair in pairs for path in pair)).items()
            ],
        }
        legacy: dict[str, object] = {**_legacy_fields(context), **short_path_fields()}
        payload = settle_short_paths(
            lambda: native_adapter_detection_payload("codex_detect", {**request, "legacy": legacy}),
            legacy,
            "codex_detect",
        )
        artifacts, found_paths, warnings = detection_from_payload(payload)
        command_available = _command_available(context)
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=found_paths,
            artifacts=artifacts,
            warnings=warnings,
        )
        extended = extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )
        return extend_codex_runtime_inventory(
            extended,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Prepare the enrolled native installation, including retirements, without publication."""
        return self._prepare_plan(context, enroll=False).prepared

    def _prepare_plan(self, context: HarnessContext, *, enroll: bool) -> _CodexInstallPlan:
        """The whole install as one plan. ``enroll`` may create the hook key and
        checks every active handler's owner, as an ordinary install does."""
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import RuntimeTransition, TransitionError, TransitionFile, merge_transition_dependency

        spec = _hook_manifest_spec(context)
        previous_manifest = load_hook_manifest_baseline(spec)
        bindings = _manifest_bindings(previous_manifest)
        pairs = self._config_hook_pairs(context)
        contents = {path: _snapshot(path) for pair in pairs for path in pair}
        detection = self.detect(context, config_contents=contents)
        managed_servers = managed_stdio_servers(detection)
        migrations = {
            config: prepare_codex_hook_migration(
                context,
                config_path=config,
                hooks_path=hooks,
                owned_bindings=bindings if config == spec.config_path else (),
                require_owners=enroll,
            )
            for config, hooks in pairs
        }
        for config, hooks in pairs:
            if (
                migrations[config].files[0].before != contents[config]
                or migrations[config].files[1].before != contents[hooks]
            ):
                raise TransitionError("adapter_preparation_generation_conflict")
        payload = deepcopy(migrations[spec.config_path].config_payload)
        target_migrated = migrations[spec.config_path].files[0].before != migrations[spec.config_path].files[0].after
        backup = prepare_codex_main_backup(
            context, original=contents[spec.config_path], migrated_payload=payload if target_migrated else None
        )
        features = payload.get("features")
        if not isinstance(features, dict):
            features = {}
        features.pop("codex_hooks", None)
        features["hooks"] = True
        payload["features"] = features
        self._install_config_hooks(payload, context, config_path=spec.config_path, owned_bindings=bindings)
        workspace_path = context.workspace_dir / ".codex/config.toml" if context.workspace_dir is not None else None
        workspace_payload = (
            parse_toml_object(contents[workspace_path], path=workspace_path, label="Codex config file")
            if workspace_path is not None
            else {}
        )
        payload, migrated_proxies = render_codex_managed_mcp(
            context,
            payload,
            managed_servers=managed_servers,
            workspace_payload=workspace_payload,
        )
        publication = prepare_authenticated_hook_publication(
            spec,
            rendered_config=dump_toml(payload, original=contents[spec.config_path]),
            previous_manifest=previous_manifest,
            create_key=enroll,
            _manifest_builder=build_authenticated_hook_manifest if enroll else None,
        )
        if publication.config_change.before != contents[spec.config_path]:
            raise TransitionError("adapter_preparation_generation_conflict")
        files = list(publication.files)
        files.append(backup)
        for config, hooks in pairs:
            migration = migrations[config]
            candidate = payload
            if config != spec.config_path:
                before_change = migration.files[0]
                migrated = before_change.before != before_change.after
                # The cleanup is rendered onto the migrated payload, so a change
                # either step made shows up against the file as it was read.
                candidate, cleanup_changed, hooks_changed = _alternate_cleanup(
                    context,
                    migration.config_payload,
                    remove_hooks=True,
                    managed_server_names=tuple(
                        server.name for server in managed_servers if Path(server.config_path) == config
                    ),
                )
                changed = migrated or cleanup_changed
                mode = 0o600 if migrated or hooks_changed else before_change.before_mode
                files.append(
                    TransitionFile(
                        before_change.path,
                        before_change.before,
                        # An ordinary install writes the hook migration first and
                        # then renders the cleanup onto that file, so render onto
                        # the migrated text here too; otherwise the plan and the
                        # install disagree over spacing the migration introduced.
                        dump_toml(candidate, original=before_change.after if migrated else before_change.before).encode(
                            "utf-8"
                        )
                        if changed
                        else before_change.before,
                        before_mode=before_change.before_mode,
                        after_mode=mode,
                        no_follow=True,
                    )
                )
            source_hooks = parse_json_object(contents[hooks], path=hooks, label="Codex hooks file")
            expected_payload = _unmanaged_migration_payload(
                source_hooks,
                context=context,
                owned_bindings=bindings if config == spec.config_path else (),
            )
            _require_migrated_hooks(context, expected_payload, candidate, source_scope=self._scope_for(context, config))
            files.extend(migration.files[1:])
        files.extend(prepare_codex_shell_cleanup(context))
        shim = prepare_guard_shim(self.harness, context)
        files.extend(shim.files)
        identities = publication.manifest.get("packaged_files")
        interpreter = publication.manifest.get("interpreter")
        if not isinstance(identities, list) or not isinstance(interpreter, dict):
            raise TransitionError("adapter_preparation_generation_conflict")
        for identity in identities:
            if not isinstance(identity, dict) or not isinstance(identity.get("path"), str):
                raise TransitionError("adapter_preparation_generation_conflict")
            dependency = TransitionFile.artifact_dependency(identity)
            files.append(dependency)
        target_identity = interpreter.get("target")
        if not isinstance(target_identity, dict):
            raise TransitionError("adapter_preparation_generation_conflict")
        files.append(TransitionFile.artifact_dependency(target_identity, invocation=interpreter))
        unique_files = {}
        for change in files:
            previous = unique_files.get(change.path)
            unique_files[change.path] = change if previous is None else merge_transition_dependency(previous, change)
        files = list(unique_files.values())
        fields = {"backup_path": str(backup.path), **_server_fields(detection, managed_servers, migrated_proxies)}
        prepared = PreparedHarnessInstall(
            tuple(files),
            _install_manifest(
                context,
                "prepare",
                shim.manifest,
                manifest_path=str(publication.manifest_change.path),
                integrity="authenticated",
                **fields,
            ),
        )
        if len({change.path for change in files}) != len(files):
            raise TransitionError("adapter_preparation_generation_conflict")
        RuntimeTransition._compare({"files": [change.payload() for change in files]}, "before")
        # The backups an install writes before its authenticated generation.
        backups = frozenset(
            {backup.path, *(change.path for migration in migrations.values() for change in migration.files[2:])}
        )
        return _CodexInstallPlan(prepared, publication, backups, shim.manifest, fields)

    def install(self, context: HarnessContext) -> dict[str, object]:
        from ..runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, self._target_config_path(context), actor="install"):
            assert_transition_mutation_allowed(context.guard_home)
            recover_hook_publication(context.guard_home)
            return self._install_owned(context)

    def _install_owned(self, context: HarnessContext) -> dict[str, object]:
        """Publish the prepared plan: the authenticated generation and its
        backups under the hook publication journal, then, once committed, the
        retirements and launchers it planned beside them."""
        from ..runtime_transition import assert_transition_mutation_allowed

        assert_transition_mutation_allowed(context.guard_home)
        spec = _hook_manifest_spec(context)
        if self._hook_config_path(context) != self._target_config_path(context):
            raise RuntimeError("Codex hook authentication currently requires one canonical global config target.")
        # A source that is not a readable regular file refuses before the journal opens.
        for config_path, hooks_path in self._config_hook_pairs(context):
            _strict_toml_object(config_path, label="Codex config file")
            _strict_json_object(hooks_path, label="Codex hooks file")
        plans: list[_CodexInstallPlan] = []

        def plan() -> tuple[PreparedCodexHookPublication, tuple[TransitionFile, ...]]:
            planned = self._prepare_plan(context, enroll=True)
            plans.append(planned)
            backups = tuple(change for change in planned.prepared.files if change.path in planned.backups)
            return planned.publication, backups

        hook_state = self._write_authenticated_hook_config_owned(
            context,
            config_path=spec.config_path,
            payload=None,
            previous_manifest=load_hook_manifest_baseline(spec),
            plan=plan,
        )
        planned = plans[0]
        published = {change.path for change in planned.publication.files} | planned.backups
        remaining = tuple(change for change in planned.prepared.files if change.path not in published)
        try:
            PreparedHarnessInstall(remaining, planned.prepared.manifest).publish(context.guard_home, removals=True)
        except BaseException:
            # The retirements restored themselves; withdraw the committed
            # generation too, so legacy hooks never run beside their migration.
            _withdraw_publication(context, planned.publication)
            raise
        _require_codex_authoritative_shell_hook(context)
        return _install_manifest(
            context,
            "install",
            planned.shim_manifest,
            manifest_path=str(hook_state["manifest_path"]),
            integrity=str(hook_state["integrity_status"]),
            **planned.fields,
        )

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        from ..runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, self._target_config_path(context), actor="uninstall"):
            assert_transition_mutation_allowed(context.guard_home)
            recover_hook_publication(context.guard_home)
            return self._uninstall_owned(context)

    def _uninstall_owned(self, context: HarnessContext) -> dict[str, object]:
        from ..codex_install_transaction import record_codex_mutation

        prepared = self._prepare_uninstall(context)
        config_path = self._hook_config_path(context)
        operations = {
            _located(hook_authority_receipt_path(context.guard_home, config_path)): "remove_authority_receipt",
            _located(hook_manifest_path(context.guard_home, config_path)): "remove_manifest",
        }

        def audit(change: TransitionFile) -> None:
            operation = operations.get(change.path)
            if operation is not None:
                record_codex_mutation(operation, change.path, change.before, None)

        prepared.publish(context.guard_home, removals=True, on_write=audit)
        remove_hook_secret_if_unused(context.guard_home)
        return _install_manifest(
            context,
            "uninstall",
            prepared.manifest,
            hooks_path=str(self._hooks_path(context)),
            backup_path=str(self._backup_path(context)),
        )

    def _prepare_uninstall(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Every file uninstall restores or deletes, captured before any of them changes.

        The main config returns to its backup, or loses only the hooks the
        authenticated manifest binds. Alternate configs lose this install's
        bridge, the receipt and manifest go, and so do shell guards and the
        launcher. JSON hook files created after install stay byte-for-byte.
        """
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        def mode_of(path: Path, data: bytes | None) -> int:
            return path.stat().st_mode & 0o777 if data is not None else 0o600

        owned = _manifest_bindings(load_hook_manifest_baseline(_hook_manifest_spec(context)))
        target = _located(self._target_config_path(context))
        current = _snapshot(target)
        backup_path = _located(self._backup_path(context))
        backup = _snapshot(backup_path)
        files: list[TransitionFile] = []
        if backup is not None:
            files.append(
                TransitionFile(target, current, backup or None, before_mode=mode_of(target, current), no_follow=True)
            )
            files.append(
                TransitionFile(
                    backup_path,
                    backup,
                    None,
                    before_mode=mode_of(backup_path, backup),
                    after_mode=0o600,
                    no_follow=True,
                )
            )
        elif current is not None:
            payload = parse_toml_object(current, path=target, label="Codex config file")
            hooks = payload.get("hooks")
            if owned and isinstance(hooks, dict):
                cleaned, removed = _remove_manifest_bound_hook_events(hooks, owned)
                if removed:
                    if cleaned:
                        payload["hooks"] = cleaned
                    else:
                        payload.pop("hooks", None)
                    rendered = dump_toml(payload, original=current).encode("utf-8")
                    files.append(
                        TransitionFile(target, current, rendered, before_mode=mode_of(target, current), no_follow=True)
                    )
        files.extend(
            prepare_codex_alternate_cleanup(context, config_path=config_path)
            for config_path, _hooks_path in self._config_hook_pairs(context)
            if _located(config_path) != target and config_path.is_file()
        )
        hook_config_path = self._hook_config_path(context)
        for path in (
            _located(hook_authority_receipt_path(context.guard_home, hook_config_path)),
            _located(hook_manifest_path(context.guard_home, hook_config_path)),
        ):
            data = _snapshot(path)
            if data is not None:
                mode = mode_of(path, data)
                files.append(TransitionFile(path, data, None, before_mode=mode, after_mode=mode, no_follow=True))
        files.extend(prepare_codex_shell_cleanup(context))
        shim = prepare_guard_shim_removal(self.harness, context)
        return PreparedHarnessInstall((*files, *shim.files), shim.manifest)

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        hook_state = codex_native_hook_state(context)
        warning_items = payload.get("warnings")
        items = warning_items if isinstance(warning_items, list) else []
        warnings = finalize_codex_doctor_warnings([str(item) for item in items if isinstance(item, str)], hook_state)
        payload["warnings"] = warnings
        base_status = payload.get("setup_status")
        answer = _codex(
            "doctor_status",
            context,
            warnings=warnings,
            status=finalize_codex_doctor_setup_status(base_status, hook_state, warnings),
            base_status=base_status,
        )
        setup_status = answer["status"]
        payload["setup_status"] = setup_status
        apply_codex_hook_trust_doctor(payload, hook_state)
        payload["native_hook_state"] = hook_state
        return payload

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hook_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        target_path = str(CodexHarnessAdapter._target_config_path(context).resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "codex" / f"{digest}.backup.toml"

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        return proxy_launcher_entry(
            proxy_command="codex-mcp-proxy",
            context=context,
            server=server,
        )

    @staticmethod
    def _install_config_hooks(
        payload: dict[str, object],
        context: HarnessContext,
        *,
        config_path: Path,
        owned_bindings: Sequence[Mapping[str, object]] = (),
    ) -> None:
        hooks = payload.get("hooks")
        if not isinstance(hooks, dict):
            hooks = {}
        before = deepcopy(hooks)
        cleaned_hooks = _strip_owned_hooks(context, hooks, owned_bindings, unlaunchable=False, hold_recorded=True)
        install_managed_codex_hook_groups(
            cleaned_hooks,
            _managed_hook_groups(context),
            current_guard_home=_runtime_guard_home(context),
        )
        # Hook state is keyed by position, so the groups just rewritten moved
        # the keys of the hooks Guard leaves alone. Each one follows its
        # handler before trust is read, or another hook's disabled choice
        # lands on a Guard hook and switches it off unseen.
        remap_hook_state(before, cleaned_hooks, config_path)
        payload["hooks"] = cleaned_hooks
        # Codex skips a hook it has no trusted hash for, and says nothing while
        # it does, so an install that stops here leaves the machine unprotected
        # and looks installed. Trust is recorded for the handlers just written.
        record_guard_hook_trust(payload, config_path)

    @staticmethod
    def _write_authenticated_hook_config(
        context: HarnessContext,
        *,
        config_path: Path,
        payload: dict[str, object],
        previous_manifest: dict[str, object] | None,
    ) -> dict[str, object]:
        from ..runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(context.guard_home, config_path, actor="publish"):
            assert_transition_mutation_allowed(context.guard_home)
            return CodexHarnessAdapter._write_authenticated_hook_config_owned(
                context, config_path=config_path, payload=payload, previous_manifest=previous_manifest
            )

    @staticmethod
    def _write_authenticated_hook_config_owned(
        context: HarnessContext,
        *,
        config_path: Path,
        payload: dict[str, object] | None,
        previous_manifest: dict[str, object] | None,
        plan: Callable[[], tuple[PreparedCodexHookPublication, tuple[TransitionFile, ...]]] | None = None,
    ) -> dict[str, object]:
        """Commit manifest first, then config, rolling both back on any failure.

        During the short manifest-first window an old config fails closed against
        the new manifest.  Codex never observes a newly registered hook before
        its complete authenticated identity has been durably committed. ``plan``
        prepares the generation in place of rendering ``payload``, with the
        files written ahead of it.
        """
        from ..runtime_transition import TransitionError

        if hook_publication_pending(context.guard_home):
            raise RuntimeError("Codex hook publication must be recovered before preparing another generation.")
        secret_path = hook_secret_path(context.guard_home)
        original_secret_present = secret_path.exists() or secret_path.is_symlink()
        prepared = False
        if config_path.exists() or config_path.is_symlink():
            validate_regular_file(config_path, role="config_target", executable_required=False)
        try:
            original_config_identity = rollback_file_identity(config_path)
        except RuntimeError as error:
            raise RuntimeError(
                "codex_hook_config_invalid: Codex configuration must be a single-link regular file."
            ) from error
        if config_path.exists() or config_path.is_symlink():
            original_config = config_path.read_bytes()
            try:
                _ = original_config.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RuntimeError("codex_hook_config_invalid: Codex configuration is not valid UTF-8.") from error
        else:
            original_config = None
        try:
            second_snapshot_identity = rollback_file_identity(config_path)
        except RuntimeError as error:
            raise RuntimeError(
                "codex_hook_config_invalid: Codex configuration became an invalid target during its snapshot."
            ) from error
        if second_snapshot_identity != original_config_identity:
            raise RuntimeError("codex_hook_config_invalid: Codex configuration changed during its snapshot.")
        rendered_config = b""
        written_config_identity: tuple[int, int, int, int, int] | None = None

        def remember_written_config(identity: tuple[int, int, int, int, int]) -> None:
            from ..codex_hook_recovery import record_owned_hook_config_publication

            nonlocal written_config_identity
            written_config_identity = identity
            record_owned_hook_config_publication(context.guard_home, config_path, identity)

        try:
            spec = _hook_manifest_spec(context)
            if config_path.resolve(strict=False) != spec.config_path.resolve(strict=False):
                raise RuntimeError("Codex authenticated publication requires its canonical config target.")
            if plan is not None:
                publication, ahead = plan()
            else:
                assert payload is not None
                publication, ahead = (
                    prepare_authenticated_hook_publication(
                        spec,
                        rendered_config=dump_toml(payload, original=original_config),
                        previous_manifest=previous_manifest,
                        create_key=True,
                        _manifest_builder=build_authenticated_hook_manifest,
                    ),
                    (),
                )
            config_change = publication.config_change
            if config_change.before != original_config or config_change.after is None:
                raise TransitionError("adapter_preparation_generation_conflict")
            rendered_config = config_change.after
            prepare_hook_publication(
                context.guard_home,
                config_path,
                before_config=config_change.before,
                before_manifest=publication.manifest_change.before,
                after_config=rendered_config,
                after_manifest=canonical_manifest_bytes(publication.manifest) + b"\n",
                key_created=not original_secret_present,
                before_receipt=publication.receipt_change.before,
                after_receipt=publication.receipt_change.after,
            )
            prepared = True

            def remember(change: TransitionFile) -> None:
                if change is config_change:
                    identity = rollback_file_identity(config_path)
                    if identity is None:
                        raise RuntimeError("codex_hook_config_invalid: Codex configuration vanished after publication.")
                    remember_written_config(identity)

            # The journal restores the authenticated files; backups stay, as
            # they always have.
            PreparedHarnessInstall((*ahead, *publication.files), {}).publish(
                context.guard_home, rollback=False, on_write=remember
            )
            written_payload = _strict_toml_object(config_path, label="rendered Codex config file")
            _require_hook_semantics_readback(
                parse_toml_object(rendered_config, path=config_path, label="rendered Codex config file"),
                written_payload,
                source_scope=CodexHarnessAdapter._scope_for(context, config_path),
                source_path=config_path,
                context=context,
            )
            state = codex_native_hook_state(context)
            if not bool(state.get("protection_active")):
                reason = str(state.get("integrity_reason") or "codex_hook_integrity_readback_failed")
                raise RuntimeError(
                    f"{_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON}: Codex hook authentication readback failed: {reason}"
                )
            commit_hook_publication(context.guard_home)
            return state
        except BaseException as transaction_error:
            # An unknown config cannot safely be paired with the old manifest.
            # Preserve participant files and report the unresolved transaction.
            use_durable_inverse = prepared or hook_publication_pending(context.guard_home)
            if use_durable_inverse:
                try:
                    require_unchanged_config_for_rollback(
                        config_path,
                        original_config,
                        rendered_config,
                        original_identity=original_config_identity,
                        written_identity=written_config_identity,
                    )
                except BaseException as conflict:
                    # Persist the ownership refusal even for matching bytes:
                    # a later recovery must not mistake a replaced inode for
                    # this writer's publication and restore its participants.
                    mark_owned_hook_publication_conflict(context.guard_home, config_path)
                    raise conflict from transaction_error
            rollback_error: BaseException | None = None
            try:
                if use_durable_inverse:
                    recover_hook_publication(context.guard_home)
                elif not original_secret_present:
                    # Preparation has not published either file. Restoring their
                    # snapshots here would overwrite an intervening user edit.
                    remove_hook_secret_if_unused(context.guard_home)
            except BaseException as exc:  # pragma: no cover - catastrophic local I/O failure
                rollback_error = exc
            if rollback_error is not None:
                failure = RuntimeError(
                    "Codex hook transaction failed and rollback could not be completed: "
                    f"{type(rollback_error).__name__}: {rollback_error}"
                )
                add_note = getattr(failure, "add_note", None)
                if callable(add_note):
                    add_note(f"rollback error: {rollback_error!r}")
                raise failure from transaction_error
            raise
